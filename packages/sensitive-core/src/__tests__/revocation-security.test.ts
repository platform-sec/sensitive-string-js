import * as util from 'node:util';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  pruneRevocations,
  registerPolicy,
  resetPolicies,
  revokeByLabel,
  revokeByPattern,
  RevocationList,
  RevokedSensitiveValueError,
  SensitiveString,
  st,
  withRevealContext,
} from '../index.js';
import type {
  RevealContext,
  RevealDetails,
  RevocationRegistry,
  SensitivityClass,
} from '../index.js';

const CANARY = 'REVOCATION_SECURITY_CANARY_7c3e';

/**
 * Every operation that reaches the raw value, named so a new one that forgets
 * the gate fails here rather than shipping as a bypass.
 */
const RAW_VALUE_OPERATIONS: readonly [string, (value: SensitiveString<'sensitive'>) => unknown][] =
  [
    ['reveal', (v) => v.reveal()],
    ['mask', (v) => v.mask({ showLast: 2 })],
    ['equals', (v) => v.equals(CANARY)],
    ['equals(SensitiveString)', (v) => new SensitiveString('other', 'sensitive').equals(v)],
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
    ['startsWith', (v) => v.startsWith('R')],
    ['endsWith', (v) => v.endsWith('e')],
    ['includes', (v) => v.includes('CANARY')],
    ['indexOf', (v) => v.indexOf('CANARY')],
    ['lastIndexOf', (v) => v.lastIndexOf('CANARY')],
    ['test', (v) => v.test(/CANARY/)],
    ['search', (v) => v.search(/CANARY/)],
    ['match', (v) => v.match(/CANARY/)],
    ['matchGroups', (v) => v.matchGroups(/(?<tag>CANARY)/)],
    ['matchAll', (v) => v.matchAll(/CANARY/g)],
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
 * derivation that dropped the revocation state would hand back a live copy of a
 * value that was meant to stop working, in either direction.
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

function clearGlobalRevocations(): void {
  pruneRevocations(Date.now() + 1);
}

describe('revocation security', () => {
  beforeEach(() => {
    resetPolicies();
    clearGlobalRevocations();
  });

  afterEach(() => {
    clearGlobalRevocations();
  });

  describe('the gate', () => {
    it('refuses every operation that reaches the raw value, and leaks nothing doing it', () => {
      for (const [name, operation] of RAW_VALUE_OPERATIONS) {
        const value = new SensitiveString(CANARY, 'sensitive', 'canary');
        value.revoke('rotated');

        let thrown: unknown;
        try {
          operation(value);
          expect.unreachable(`${name} must refuse a revoked value`);
        } catch (error) {
          thrown = error;
        }

        expect(thrown, name).toBeInstanceOf(RevokedSensitiveValueError);
        expect(String(thrown), name).not.toContain(CANARY);
        expect((thrown as Error).stack ?? '', name).not.toContain(CANARY);
        expect(util.inspect(thrown), name).not.toContain(CANARY);
      }
    });

    it('refuses every operation on a value revoked by label', () => {
      for (const [name, operation] of RAW_VALUE_OPERATIONS) {
        clearGlobalRevocations();
        const value = new SensitiveString(CANARY, 'sensitive', 'canary');
        revokeByLabel('canary', 'label revocation');

        expect(() => operation(value), name).toThrow(RevokedSensitiveValueError);
      }
    });

    it('refuses every operation on a value revoked by pattern', () => {
      for (const [name, operation] of RAW_VALUE_OPERATIONS) {
        clearGlobalRevocations();
        const value = new SensitiveString(CANARY, 'sensitive', 'canary');
        revokeByPattern(/^can/, 'pattern revocation');

        expect(() => operation(value), name).toThrow(RevokedSensitiveValueError);
      }
    });

    it('refuses even inside an authorized context', () => {
      const value = new SensitiveString(CANARY, 'credential', 'token');
      value.revoke('rotated');

      withRevealContext({ name: 'authorized', reason: 'still not allowed' }, () => {
        expect(() => value.reveal()).toThrow(RevokedSensitiveValueError);
      });

      expect(() => value.reveal({ name: 'explicit', reason: 'still not allowed' })).toThrow(
        RevokedSensitiveValueError
      );
    });

    it('denies before the policy and the audit hook run, so a refusal is not logged as a read', () => {
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

      const value = new SensitiveString(CANARY, 'sensitive', 'canary');
      value.revoke('rotated');

      expect(() =>
        value.reveal({ name: 'audited', auditReveal: (_v, d) => records.push(d) })
      ).toThrow(RevokedSensitiveValueError);

      expect(records).toEqual([]);
      expect(checked).toEqual([]);
    });

    it('is not lifted by overriding the public accessors', () => {
      class Forged extends SensitiveString<'sensitive'> {
        override get isRevoked(): boolean {
          return false;
        }

        override get revocationReason(): string | undefined {
          return undefined;
        }
      }

      const forged = new Forged(CANARY, 'sensitive', 'canary');
      forged.revoke('rotated');

      expect(forged.isRevoked).toBe(false);
      expect(forged.revocationReason).toBeUndefined();
      expect(() => forged.reveal()).toThrow(RevokedSensitiveValueError);
      expect(() => forged.serialize()).toThrow(RevokedSensitiveValueError);
    });

    it('is not lifted by shadowing the accessors on the instance', () => {
      const value = new SensitiveString(CANARY, 'sensitive', 'canary');
      value.revoke('rotated');

      Object.defineProperty(value, 'isRevoked', { value: false });
      Object.defineProperty(value, 'revokedAt', { value: undefined });

      expect(() => value.reveal()).toThrow(RevokedSensitiveValueError);
    });

    it('is not lifted by a policy that tries to authorize the read', () => {
      registerPolicy(
        {
          name: 'sensitive',
          redact: () => '[REDACTED:sensitive]',
          checkRevealAllowed: () => undefined,
        },
        { overwrite: true }
      );

      const value = new SensitiveString(CANARY, 'sensitive', 'canary');
      value.revoke('rotated');

      expect(() => value.reveal()).toThrow(RevokedSensitiveValueError);
    });
  });

  describe('irreversibility', () => {
    it('publishes nothing that lifts a revocation', () => {
      const value = new SensitiveString(CANARY, 'sensitive', 'canary');
      value.revoke('rotated');

      const surface = [
        ...Object.getOwnPropertyNames(SensitiveString.prototype),
        ...Object.getOwnPropertyNames(SensitiveString),
      ];

      expect(surface).not.toContain('unrevoke');
      expect(surface).not.toContain('restore');
      expect(surface.filter((name) => /unrevoke|revive|reinstate/i.test(name))).toEqual([]);
    });

    it('is not lifted by a second options object or a round trip through the wire format', () => {
      const value = new SensitiveString(CANARY, 'credential', 'api_key');
      value.revoke('rotated');

      expect(
        () =>
          new SensitiveString(CANARY, 'credential', 'api_key', {
            revocationRegistry: new RevocationList(),
          })
      ).not.toThrow();

      // A fresh value is a fresh value; the revoked one stays revoked, and
      // cannot be read to build a payload that would carry it anywhere.
      expect(value.isRevoked).toBe(true);
      expect(() => value.serialize()).toThrow(RevokedSensitiveValueError);
    });

    it('survives every prune once it has been observed', () => {
      const value = new SensitiveString(CANARY, 'sensitive', 'canary');
      revokeByPattern(/^can/, 'pattern revocation');

      expect(value.isRevoked).toBe(true);

      for (let attempt = 0; attempt < 3; attempt++) {
        pruneRevocations(Date.now() + 1);
        expect(() => value.reveal()).toThrow(RevokedSensitiveValueError);
      }
    });
  });

  describe('derived values', () => {
    it('gives every derivation the revocation of the value it came from', () => {
      for (const [name, derive] of DERIVING_OPERATIONS) {
        const value = new SensitiveString(CANARY, 'sensitive', 'canary');
        const children = derive(value);

        expect(children.length, name).toBeGreaterThan(0);

        value.revoke('rotated');

        for (const child of children) {
          expect(child.isRevoked, name).toBe(true);
          expect(() => child.reveal(), name).toThrow(RevokedSensitiveValueError);
          expect(util.inspect(child), name).not.toContain(CANARY);
        }
      }
    });

    it('lets every derivation revoke the value it came from', () => {
      for (const [name, derive] of DERIVING_OPERATIONS) {
        const value = new SensitiveString(CANARY, 'sensitive', 'canary');
        const children = derive(value);
        const child = children[0];

        expect(child, name).toBeDefined();
        child?.revoke('the derivative leaked');

        // A derivative carries its sources' material, so refusing to revoke
        // through the handle a caller holds would fail open in the incident
        // this exists for.
        expect(value.isRevoked, name).toBe(true);
        expect(() => value.reveal(), name).toThrow(RevokedSensitiveValueError);
      }
    });

    it('cannot outlive its source through a chain of derivations', () => {
      const value = new SensitiveString(CANARY, 'sensitive', 'canary');
      const chain = value
        .trim()
        .toUpperCase()
        .slice(0)
        .map((raw) => raw)
        .concat('tail');

      value.revoke('rotated');

      expect(chain.isRevoked).toBe(true);
      expect(() => chain.reveal()).toThrow(RevokedSensitiveValueError);
      expect(util.inspect(chain)).not.toContain(CANARY);
    });

    it('is revoked as soon as either operand of a two-parent derivation is', () => {
      const left = new SensitiveString(CANARY, 'sensitive', 'left');
      const right = new SensitiveString('other', 'sensitive', 'right');
      const combined = left.concat(right);

      right.revoke('one operand is enough');

      expect(combined.isRevoked).toBe(true);
      expect(() => combined.reveal()).toThrow(RevokedSensitiveValueError);
      expect(left.reveal()).toBe(CANARY);
    });
  });

  describe('what a refusal discloses', () => {
    it('names the label and the reason but never the value', () => {
      const labelled = new SensitiveString(CANARY, 'credential', 'session_token');
      const unlabelled = new SensitiveString(CANARY, 'credential');
      labelled.revoke('Rotated after incident INC-4417');
      unlabelled.revoke('Rotated after incident INC-4417');

      for (const value of [labelled, unlabelled]) {
        try {
          value.reveal();
          expect.unreachable('reveal must throw once revoked');
        } catch (error) {
          const message = (error as Error).message;
          // Both are developer-supplied text and identify which value was
          // refused, so they appear by design. The protected value never does.
          expect(message).toContain('INC-4417');
          expect(message).not.toContain(CANARY);
        }
      }

      expect(labelled.revocationReason).not.toContain(CANARY);
    });

    it('keeps the value out of every observable form after revocation', () => {
      const token = new SensitiveString(CANARY, 'credential', 'token');
      token.revoke('rotated');

      expect(String(token)).not.toContain(CANARY);
      expect(JSON.stringify({ token })).not.toContain(CANARY);
      expect(util.inspect(token)).not.toContain(CANARY);
      expect(util.inspect(token, { depth: 10, showHidden: true })).not.toContain(CANARY);
      expect(String(token.revokedAt)).not.toContain(CANARY);
      expect(String(token.revocationReason)).not.toContain(CANARY);
    });

    it('reports a revocation to an audit sink without the value', () => {
      const records: RevealDetails[] = [];
      const token = new SensitiveString(CANARY, 'credential', 'token');

      token.revoke('rotated', { name: 'incident', auditReveal: (_v, d) => records.push(d) });

      expect(JSON.stringify(records)).not.toContain(CANARY);
    });
  });

  describe('an external registry', () => {
    it('is only ever handed the label, never the value', () => {
      const seen: unknown[] = [];
      const registry: RevocationRegistry = {
        isRevoked(label) {
          seen.push(label);
          return false;
        },
        getReason(label) {
          seen.push(label);
          return undefined;
        },
      };

      const token = new SensitiveString(CANARY, 'credential', 'api_key', {
        revocationRegistry: registry,
      });

      token.reveal();
      token.equals(CANARY);
      expect(token.isRevoked).toBe(false);

      expect(seen.length).toBeGreaterThan(0);
      expect(JSON.stringify(seen)).not.toContain(CANARY);
    });

    it('cannot keep a read alive by refusing to answer', () => {
      for (const answer of [undefined, null, 'no', 0, Promise.resolve(false)]) {
        const registry = {
          isRevoked: () => answer,
        } as unknown as RevocationRegistry;

        const token = new SensitiveString(CANARY, 'credential', 'api_key', {
          revocationRegistry: registry,
        });

        expect(() => token.reveal()).toThrow(RevokedSensitiveValueError);
      }
    });

    it('is handed no instance to re-enter the gate with', () => {
      const arity: number[] = [];
      const registry: RevocationRegistry = {
        isRevoked(...args: unknown[]) {
          arity.push(args.length);
          return false;
        },
      };

      const token = new SensitiveString(CANARY, 'credential', 'api_key', {
        revocationRegistry: registry,
      });

      // Unlike an audit hook or a policy hook, the registry never receives the
      // instance, so there is nothing for it to call reveal() on: the gate it
      // runs inside cannot be re-entered from here.
      expect(token.reveal()).toBe(CANARY);
      expect(arity).toEqual([1]);
    });
  });

  describe('the pattern list', () => {
    it('refuses a pattern that could hang the thread it is checked on', () => {
      const hostile = [/^(a+)+$/, /^(a*)*$/, /^(a|a)+$/, /^(\w+\s?)*$/, /^((b+)+)+$/];

      for (const pattern of hostile) {
        expect(() => revokeByPattern(pattern, 'hostile'), String(pattern)).toThrow(TypeError);
      }

      // Nothing hostile was stored, so the read below cannot be the one that
      // pays for it.
      const value = new SensitiveString('a'.repeat(40), 'sensitive', 'a'.repeat(40));
      const started = Date.now();
      expect(value.isRevoked).toBe(false);
      expect(Date.now() - started).toBeLessThan(1_000);
    });

    it('refuses anything that is not a regular expression', () => {
      const shaped = { source: '^can', flags: '', test: () => true } as unknown as RegExp;

      // The source and flags are read through the intrinsic getters, which
      // verify the RegExp internal slots, so an object shaped like a pattern is
      // rejected at the door rather than stored and consulted.
      expect(() => revokeByPattern(shaped, 'shaped')).toThrow(TypeError);
    });

    it('reads a subclass through the intrinsic getters, not through its overrides', () => {
      const seen: string[] = [];

      class Sneaky extends RegExp {
        override get source(): string {
          // What a caller would see, and what the library must not act on.
          return '^never-matches-anything$';
        }

        override test(input: string): boolean {
          seen.push(input);
          return false;
        }
      }

      revokeByPattern(new Sneaky('^can', ''), 'subclassed');

      // Stored as a plain RegExp built from the real internal slots, so neither
      // the lying `source` nor the instrumented `test` is ever consulted.
      expect(new SensitiveString(CANARY, 'sensitive', 'canary').isRevoked).toBe(true);
      expect(seen).toEqual([]);
    });
  });
});
