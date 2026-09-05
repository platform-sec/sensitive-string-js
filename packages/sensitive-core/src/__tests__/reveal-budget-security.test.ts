import * as util from 'node:util';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  registerPolicy,
  resetPolicies,
  RevealLimitExceededError,
  RevealRateLimitError,
  SensitiveString,
  st,
  withRevealContext,
} from '../index.js';
import type { RevealContext, RevealDetails, SensitivityClass } from '../index.js';

const CANARY = 'BUDGET_SECURITY_CANARY_7c1e';
const MINUTE = 60_000;
const START = new Date('2026-01-01T00:00:00.000Z');

function advance(ms: number): void {
  vi.setSystemTime(new Date(Date.now() + ms));
}

/**
 * Every operation that hands the raw value, or part of it, to a caller. Named
 * so a new one that forgets the gate fails here rather than shipping as a way
 * to spend a budget for free.
 *
 * `equals()` is deliberately absent: a comparison reads the value without
 * disclosing it, so it is not charged and not refused. The case below asserts
 * that on purpose rather than by omission.
 */
const EXPOSING_OPERATIONS: readonly [string, (value: SensitiveString<'sensitive'>) => unknown][] = [
  ['reveal', (v) => v.reveal()],
  ['mask', (v) => v.mask({ showLast: 2 })],
  ['concat', (v) => v.concat('suffix')],
  ['substring', (v) => v.substring(0, 4)],
  ['trim', (v) => v.trim()],
  ['trimStart', (v) => v.trimStart()],
  ['trimEnd', (v) => v.trimEnd()],
  ['toLowerCase', (v) => v.toLowerCase()],
  ['toUpperCase', (v) => v.toUpperCase()],
  ['padStart', (v) => v.padStart(64, 'x')],
  ['padEnd', (v) => v.padEnd(64, 'x')],
  ['slice', (v) => v.slice(1)],
  ['startsWith', (v) => v.startsWith('B')],
  ['endsWith', (v) => v.endsWith('e')],
  ['includes', (v) => v.includes('CANARY')],
  ['indexOf', (v) => v.indexOf('CANARY')],
  ['lastIndexOf', (v) => v.lastIndexOf('CANARY')],
  ['test', (v) => v.test(/CANARY/)],
  ['search', (v) => v.search(/CANARY/)],
  ['match', (v) => v.match(/CANARY/)],
  ['matchGroups', (v) => v.matchGroups(/(?<tag>CANARY)/)],
  ['matchAll', (v) => Array.from(v.matchAll(/CANARY/g))],
  ['split', (v) => v.split('_')],
  ['replace', (v) => v.replace('CANARY', 'x')],
  ['replaceAll', (v) => v.replaceAll(/CANARY/g, 'x')],
  ['charAt', (v) => v.charAt(0)],
  ['at', (v) => v.at(0)],
  ['map', (v) => v.map((raw) => raw)],
  ['reclassify', (v) => v.reclassify('credential')],
  ['serialize', (v) => v.serialize()],
  ['template literal', (v) => st`prefix ${v}`],
];

/**
 * Every operation that produces a new protected value from an existing one. A
 * derivation that started a fresh counter would hand back an unlimited copy of
 * a value that was meant to be spent.
 */
const DERIVING_OPERATIONS: readonly [
  string,
  (value: SensitiveString<'sensitive'>) => SensitiveString<SensitivityClass>[],
][] = [
  ['concat', (v) => [v.concat('suffix')]],
  ['concat(SensitiveString)', (v) => [v.concat(new SensitiveString('suffix', 'sensitive'))]],
  ['substring', (v) => [v.substring(0, 4)]],
  ['trim', (v) => [v.trim()]],
  ['trimStart', (v) => [v.trimStart()]],
  ['trimEnd', (v) => [v.trimEnd()]],
  ['toLowerCase', (v) => [v.toLowerCase()]],
  ['toUpperCase', (v) => [v.toUpperCase()]],
  ['padStart', (v) => [v.padStart(64, 'x')]],
  ['padEnd', (v) => [v.padEnd(64, 'x')]],
  ['slice', (v) => [v.slice(1)]],
  ['match', (v) => v.match(/CANARY/) ?? []],
  ['matchGroups', (v) => Object.values(v.matchGroups(/(?<tag>CANARY)/) ?? {})],
  ['matchAll', (v) => Array.from(v.matchAll(/CANARY/g)).flat()],
  ['split', (v) => v.split('_')],
  ['replace', (v) => [v.replace('CANARY', 'x')]],
  ['replaceAll', (v) => [v.replaceAll(/CANARY/g, 'x')]],
  ['charAt', (v) => [v.charAt(0)]],
  ['at', (v) => [v.at(0)!]],
  ['map', (v) => [v.map((raw) => raw)]],
  ['reclassify', (v) => [v.reclassify('credential')]],
  ['template literal', (v) => [st`prefix ${v}`]],
];

describe('reveal budget security', () => {
  beforeEach(() => {
    resetPolicies();
    vi.useFakeTimers();
    vi.setSystemTime(START);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('the gate', () => {
    it('refuses every exposing operation on a spent budget, and leaks nothing doing it', () => {
      for (const [name, operation] of EXPOSING_OPERATIONS) {
        const value = new SensitiveString(CANARY, 'sensitive', 'canary', { maxReveals: 0 });

        let thrown: unknown;
        try {
          operation(value);
          expect.unreachable(`${name} must refuse an exhausted value`);
        } catch (error) {
          thrown = error;
        }

        expect(thrown, name).toBeInstanceOf(RevealLimitExceededError);
        expect(String(thrown), name).not.toContain(CANARY);
        expect((thrown as Error).stack ?? '', name).not.toContain(CANARY);
        expect(util.inspect(thrown), name).not.toContain(CANARY);
      }
    });

    it('refuses every exposing operation on a full window, and leaks nothing doing it', () => {
      for (const [name, operation] of EXPOSING_OPERATIONS) {
        const value = new SensitiveString(CANARY, 'sensitive', 'canary', {
          revealWindow: MINUTE,
          maxRevealsPerWindow: 1,
        });

        value.reveal();

        let thrown: unknown;
        try {
          operation(value);
          expect.unreachable(`${name} must refuse a rate-limited value`);
        } catch (error) {
          thrown = error;
        }

        expect(thrown, name).toBeInstanceOf(RevealRateLimitError);
        expect(String(thrown), name).not.toContain(CANARY);
        expect((thrown as Error).stack ?? '', name).not.toContain(CANARY);
      }
    });

    it('refuses even inside an authorized context', () => {
      const key = new SensitiveString(CANARY, 'credential', 'bootstrap', { maxReveals: 1 });
      key.reveal();

      withRevealContext({ name: 'authorized', reason: 'still not allowed' }, () => {
        expect(() => key.reveal()).toThrow(RevealLimitExceededError);
      });

      expect(() => key.reveal({ name: 'explicit', reason: 'still not allowed' })).toThrow(
        RevealLimitExceededError
      );
    });

    it('denies before the audit hook runs, so a refusal is not logged as a reveal', () => {
      const records: RevealDetails[] = [];
      const checked: (RevealContext | null)[] = [];

      registerPolicy(
        {
          name: 'sensitive',
          redact: () => '[REDACTED:sensitive]',
          checkRevealAllowed: (ctx) => {
            checked.push(ctx);
          },
        },
        { overwrite: true }
      );

      const value = new SensitiveString(CANARY, 'sensitive', 'canary', { maxReveals: 0 });

      expect(() =>
        value.reveal({ name: 'audited', auditReveal: (_v, d) => records.push(d) })
      ).toThrow(RevealLimitExceededError);

      expect(records).toEqual([]);
      expect(checked).toEqual([]);
    });

    it('hands out no value when the audit hook throws, and charges nothing for it', () => {
      const key = new SensitiveString(CANARY, 'credential', 'bootstrap', { maxReveals: 1 });
      let leaked: unknown;

      for (let attempt = 0; attempt < 10; attempt++) {
        expect(() => {
          leaked = key.reveal({
            name: 'hostile',
            auditReveal: () => {
              throw new Error('audit sink unavailable');
            },
          });
        }).toThrow('audit sink unavailable');
      }

      expect(leaked).toBeUndefined();
      expect(key.revealCount).toBe(0);

      // The budget survived the ten failures intact, and is still exactly one.
      expect(key.reveal()).toBe(CANARY);
      expect(() => key.reveal()).toThrow(RevealLimitExceededError);
    });

    it('is not lifted by overriding the public accessors', () => {
      class Forged extends SensitiveString<'sensitive'> {
        override isExhausted(): boolean {
          return false;
        }

        override get revealCount(): number {
          return 0;
        }

        override get revealsRemaining(): number | undefined {
          return 99;
        }
      }

      const forged = new Forged(CANARY, 'sensitive', 'canary', { maxReveals: 1 });

      expect(forged.reveal()).toBe(CANARY);
      expect(forged.isExhausted()).toBe(false);
      expect(forged.revealCount).toBe(0);
      expect(() => forged.reveal()).toThrow(RevealLimitExceededError);
      expect(() => forged.serialize()).toThrow(RevealLimitExceededError);
    });

    it('is not lifted by shadowing the accessors on the instance', () => {
      const key = new SensitiveString(CANARY, 'credential', 'bootstrap', { maxReveals: 1 });
      key.reveal();

      Object.defineProperty(key, 'isExhausted', { value: () => false });
      Object.defineProperty(key, 'revealCount', { value: 0 });
      Object.defineProperty(key, 'revealsRemaining', { value: 99 });

      expect(() => key.reveal()).toThrow(RevealLimitExceededError);
    });

    it('has no public path that resets a count', () => {
      const key = new SensitiveString(CANARY, 'credential', 'bootstrap', { maxReveals: 1 });
      key.reveal();

      // Everything a caller can reach: own properties, the prototype's members,
      // and assignment through the accessors. Nothing among them writes a count.
      expect(Object.getOwnPropertyNames(key)).toEqual(['klass', 'label']);
      expect(
        Object.getOwnPropertyNames(SensitiveString.prototype).filter((name) =>
          /reset|clear|reveals|revealCount/i.test(name)
        )
      ).toEqual(['revealCount', 'revealsRemaining']);

      expect(() => {
        (key as unknown as { revealCount: number }).revealCount = 0;
      }).toThrow(TypeError);

      expect(key.revealCount).toBe(1);
      expect(() => key.reveal()).toThrow(RevealLimitExceededError);
    });
  });

  describe('the limits themselves', () => {
    it('cannot be widened by mutating the options object afterwards', () => {
      const options = { maxReveals: 1 };
      const key = new SensitiveString(CANARY, 'credential', 'bootstrap', options);

      options.maxReveals = 1000;

      expect(key.reveal()).toBe(CANARY);
      expect(() => key.reveal()).toThrow(RevealLimitExceededError);
      expect(key.revealsRemaining).toBe(0);
    });

    it('reads each option once, so a getter cannot report two different limits', () => {
      let reads = 0;
      const options = {
        get maxReveals(): number {
          reads++;
          return reads === 1 ? 1 : 1000;
        },
      };

      const key = new SensitiveString(CANARY, 'credential', 'bootstrap', options);

      expect(key.reveal()).toBe(CANARY);
      expect(() => key.reveal()).toThrow(RevealLimitExceededError);
    });

    it('cannot be widened by a window a caller shortens later', () => {
      const options = { revealWindow: MINUTE, maxRevealsPerWindow: 1 };
      const key = new SensitiveString(CANARY, 'credential', 'api_key', options);

      key.reveal();
      options.revealWindow = 1;

      expect(() => key.reveal()).toThrow(RevealRateLimitError);
      advance(MINUTE - 1);
      expect(() => key.reveal()).toThrow(RevealRateLimitError);
      advance(1);
      expect(key.reveal()).toBe(CANARY);
    });
  });

  describe('derived values', () => {
    it('gives every derivation the budget of the value it came from', () => {
      for (const [name, derive] of DERIVING_OPERATIONS) {
        const value = new SensitiveString(CANARY, 'sensitive', 'canary', { maxReveals: 1 });
        const children = derive(value);

        expect(children.length, name).toBeGreaterThan(0);

        // Deriving is itself an exposing read, so the single reveal this value
        // was given has been spent on producing the children.
        expect(value.isExhausted(), name).toBe(true);

        for (const child of children) {
          expect(child.isExhausted(), name).toBe(true);
          expect(child.revealsRemaining, name).toBe(0);

          let thrown: unknown;
          try {
            child.reveal();
            expect.unreachable(`${name} must not hand back an unlimited copy`);
          } catch (error) {
            thrown = error;
          }

          expect(thrown, name).toBeInstanceOf(RevealLimitExceededError);
          expect(String(thrown), name).not.toContain(CANARY);
        }
      }
    });

    it('makes a chain of derivations cost what each step reads', () => {
      const value = new SensitiveString(CANARY, 'sensitive', 'canary', { maxReveals: 4 });

      const chain = value
        .trim()
        .toUpperCase()
        .slice(0)
        .map((raw) => raw);

      expect(value.revealCount).toBe(4);
      expect(chain.isExhausted()).toBe(true);
      expect(() => chain.reveal()).toThrow(RevealLimitExceededError);
      expect(() => value.reveal()).toThrow(RevealLimitExceededError);
      expect(util.inspect(chain)).not.toContain(CANARY);
    });

    it('is exhausted as soon as the tightest of its sources is', () => {
      const single = new SensitiveString(CANARY, 'sensitive', 'single', { maxReveals: 1 });
      const roomy = new SensitiveString('other', 'sensitive', 'roomy', { maxReveals: 100 });
      const combined = single.concat(roomy);

      expect(single.isExhausted()).toBe(true);
      expect(combined.isExhausted()).toBe(true);
      expect(() => combined.reveal()).toThrow(RevealLimitExceededError);
      expect(roomy.reveal()).toBe('other');
    });

    it('does not give a substring a free reveal', () => {
      const key = new SensitiveString(CANARY, 'credential', 'bootstrap', { maxReveals: 1 });

      // The bypass rule R2 exists for: a limit that lived in reveal() alone
      // would be gone the moment the value was derived from.
      expect(() => key.substring(0).reveal()).toThrow(RevealLimitExceededError);
      expect(key.revealCount).toBe(1);
    });

    it('does not multiply a window across siblings', () => {
      const value = new SensitiveString(`${CANARY}-a-b`, 'sensitive', 'parts', {
        revealWindow: MINUTE,
        maxRevealsPerWindow: 2,
      });

      const parts = value.split('-');
      expect(parts.length).toBeGreaterThan(1);

      expect(parts[0]?.reveal()).toContain(CANARY);
      expect(() => parts[1]?.reveal()).toThrow(RevealRateLimitError);
    });
  });

  describe('the clock', () => {
    it('does not open a window when it jumps backwards', () => {
      const key = new SensitiveString(CANARY, 'credential', 'api_key', {
        revealWindow: MINUTE,
        maxRevealsPerWindow: 2,
      });

      key.reveal();
      key.reveal();
      expect(() => key.reveal()).toThrow(RevealRateLimitError);

      // The window reads the wall clock, which an NTP correction can move in
      // either direction. Backwards holds charges inside it for longer, which
      // is the direction to fail in; forwards clears it early, and admits one
      // burst rather than disclosing anything.
      advance(-10 * MINUTE);
      expect(() => key.reveal()).toThrow(RevealRateLimitError);

      advance(11 * MINUTE);
      expect(key.reveal()).toBe(CANARY);
    });
  });

  describe('redaction', () => {
    it('keeps working, and keeps the value out of every observable form', () => {
      const key = new SensitiveString(CANARY, 'credential', 'bootstrap', { maxReveals: 1 });
      key.reveal();

      expect(String(key)).toBe('[REDACTED:credential]');
      expect(JSON.stringify({ key })).not.toContain(CANARY);
      expect(util.inspect(key)).not.toContain(CANARY);
      expect(util.inspect(key, { depth: 10, showHidden: true })).not.toContain(CANARY);
      expect(util.inspect(key)).toContain('EXHAUSTED');
    });

    it('cannot be turned into a reveal by exhausting the value first', () => {
      // A redaction reads the value through the safe path, which is not
      // charged. It must not become a way to observe the value either.
      const key = new SensitiveString(CANARY, 'credential', 'bootstrap', { maxReveals: 1 });

      for (let i = 0; i < 100; i++) {
        expect(String(key)).not.toContain(CANARY);
      }

      expect(key.revealCount).toBe(0);
      expect(key.reveal()).toBe(CANARY);
    });

    it('names the label in a refusal but never the value', () => {
      const key = new SensitiveString(CANARY, 'credential', 'session_token', { maxReveals: 0 });
      const rateLimited = new SensitiveString(CANARY, 'credential', 'session_token', {
        revealWindow: MINUTE,
        maxRevealsPerWindow: 1,
      });

      rateLimited.reveal();

      for (const refuse of [() => key.reveal(), () => rateLimited.reveal()]) {
        try {
          refuse();
          expect.unreachable('the budget must refuse');
        } catch (error) {
          expect((error as Error).message).toContain('session_token');
          expect((error as Error).message).not.toContain(CANARY);
          expect(util.inspect(error)).not.toContain(CANARY);
        }
      }
    });
  });
});
