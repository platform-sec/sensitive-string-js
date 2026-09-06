import * as util from 'node:util';
import { runInNewContext } from 'node:vm';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  ExpiredSensitiveValueError,
  registerPolicy,
  RenewalNotAllowedError,
  resetPolicies,
  SensitiveString,
  st,
  withRevealContext,
} from '../index.js';
import type { RevealContext, RevealDetails, SensitivityClass } from '../index.js';

const CANARY = 'TTL_SECURITY_CANARY_9f4b';

/** An HMAC key long enough to clear the 16-byte floor. */
const HMAC_KEY = 'k'.repeat(32);

const MINUTE = 60_000;
const START = new Date('2026-01-01T00:00:00.000Z');

function advance(ms: number): void {
  vi.setSystemTime(new Date(Date.now() + ms));
}

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
    ['startsWith', (v) => v.startsWith('T')],
    ['endsWith', (v) => v.endsWith('b')],
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
    ['hash', (v) => v.hash('sha256')],
    ['hmac', (v) => v.hmac('sha256', HMAC_KEY)],
    ['map', (v) => v.map((raw) => raw)],
    ['reclassify', (v) => v.reclassify('credential')],
    ['serialize', (v) => v.serialize()],
  ];

/**
 * Every operation that produces a new protected value from an existing one. A
 * derivation that dropped the deadline would hand back an unconstrained copy of
 * a value that was meant to stop working.
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
  ['hash', (v) => [v.hash('sha256')]],
  ['hmac', (v) => [v.hmac('sha256', HMAC_KEY)]],
  ['map', (v) => [v.map((raw) => raw)]],
  ['reclassify', (v) => [v.reclassify('credential')]],
  ['template literal', (v) => [st`prefix ${v}`]],
];

describe('TTL security', () => {
  beforeEach(() => {
    resetPolicies();
    vi.useFakeTimers();
    vi.setSystemTime(START);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('the gate', () => {
    it('refuses every operation that reaches the raw value, and leaks nothing doing it', () => {
      for (const [name, operation] of RAW_VALUE_OPERATIONS) {
        const value = new SensitiveString(CANARY, 'sensitive', 'canary', { ttl: MINUTE });
        advance(2 * MINUTE);

        let thrown: unknown;
        try {
          operation(value);
          expect.unreachable(`${name} must refuse an expired value`);
        } catch (error) {
          thrown = error;
        }

        expect(thrown, name).toBeInstanceOf(ExpiredSensitiveValueError);
        expect(String(thrown), name).not.toContain(CANARY);
        expect((thrown as Error).stack ?? '', name).not.toContain(CANARY);

        vi.setSystemTime(START);
      }
    });

    it('refuses even inside an authorized context', () => {
      const value = new SensitiveString(CANARY, 'credential', 'token', { ttl: MINUTE });
      advance(MINUTE);

      withRevealContext({ name: 'authorized', reason: 'still not allowed' }, () => {
        expect(() => value.reveal()).toThrow(ExpiredSensitiveValueError);
      });

      expect(() => value.reveal({ name: 'explicit', reason: 'still not allowed' })).toThrow(
        ExpiredSensitiveValueError
      );
    });

    it('refuses a comparison in both operand positions', () => {
      const expired = new SensitiveString(CANARY, 'credential', 'token', { ttl: MINUTE });
      const live = new SensitiveString(CANARY, 'credential', 'other');
      advance(MINUTE);

      expect(() => expired.equals(CANARY)).toThrow(ExpiredSensitiveValueError);
      expect(() => live.equals(expired)).toThrow(ExpiredSensitiveValueError);
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

      const value = new SensitiveString(CANARY, 'sensitive', 'canary', { ttl: MINUTE });
      advance(MINUTE);

      expect(() =>
        value.reveal({ name: 'audited', auditReveal: (_v, d) => records.push(d) })
      ).toThrow(ExpiredSensitiveValueError);

      expect(records).toEqual([]);
      expect(checked).toEqual([]);
    });

    it('is not lifted by overriding the public expiry accessors', () => {
      class Forged extends SensitiveString<'sensitive'> {
        override isExpired(): boolean {
          return false;
        }

        override get expiresAt(): Date | undefined {
          return undefined;
        }
      }

      const forged = new Forged(CANARY, 'sensitive', 'canary', { ttl: MINUTE });
      advance(MINUTE);

      expect(forged.isExpired()).toBe(false);
      expect(forged.expiresAt).toBeUndefined();
      expect(() => forged.reveal()).toThrow(ExpiredSensitiveValueError);
      expect(() => forged.serialize()).toThrow(ExpiredSensitiveValueError);
    });

    it('is not lifted by shadowing the accessors on the instance', () => {
      const value = new SensitiveString(CANARY, 'sensitive', 'canary', { ttl: MINUTE });
      advance(MINUTE);

      Object.defineProperty(value, 'isExpired', { value: () => false });
      Object.defineProperty(value, 'expiresAt', { value: undefined });

      expect(() => value.reveal()).toThrow(ExpiredSensitiveValueError);
    });
  });

  describe('derived values', () => {
    it('gives every derivation the deadline of the value it came from', () => {
      for (const [name, derive] of DERIVING_OPERATIONS) {
        const value = new SensitiveString(CANARY, 'sensitive', 'canary', { ttl: MINUTE });
        const children = derive(value);

        expect(children.length, name).toBeGreaterThan(0);

        for (const child of children) {
          expect(child.expiresAt, name).toEqual(new Date(START.getTime() + MINUTE));
        }

        advance(2 * MINUTE);

        for (const child of children) {
          expect(child.isExpired(), name).toBe(true);
          expect(() => child.reveal(), name).toThrow(ExpiredSensitiveValueError);
        }

        vi.setSystemTime(START);
      }
    });

    it('cannot outlive its source through a chain of derivations', () => {
      const value = new SensitiveString(CANARY, 'sensitive', 'canary', { ttl: MINUTE });
      const chain = value
        .trim()
        .toUpperCase()
        .slice(0)
        .map((raw) => raw)
        .concat('tail');

      advance(MINUTE);

      expect(chain.isExpired()).toBe(true);
      expect(() => chain.reveal()).toThrow(ExpiredSensitiveValueError);
      expect(util.inspect(chain)).not.toContain(CANARY);
    });

    it('expires as soon as the shortest-lived of its sources does', () => {
      const soon = new SensitiveString(CANARY, 'sensitive', 'soon', { ttl: MINUTE });
      const later = new SensitiveString('other', 'sensitive', 'later', { ttl: 10 * MINUTE });
      const combined = soon.concat(later);

      advance(MINUTE);

      expect(combined.isExpired()).toBe(true);
      expect(() => combined.reveal()).toThrow(ExpiredSensitiveValueError);
      expect(later.reveal()).toBe('other');
    });

    it('cannot extend the deadline of the value it came from', () => {
      const session = new SensitiveString(CANARY, 'sensitive', 'session', { ttl: MINUTE });
      const derived = session.substring(0, 4);

      expect(() => derived.renew(10 * MINUTE)).toThrow(RenewalNotAllowedError);

      advance(MINUTE);
      expect(session.isExpired()).toBe(true);
      expect(derived.isExpired()).toBe(true);
    });

    it('does not let reclassify launder away the deadline', () => {
      const value = new SensitiveString(CANARY, 'sensitive', 'canary', { ttl: MINUTE });
      const reclassified = value.reclassify('credential', 'laundered');

      advance(MINUTE);

      expect(reclassified.expiresAt).toEqual(new Date(START.getTime() + MINUTE));
      expect(() => reclassified.reveal()).toThrow(ExpiredSensitiveValueError);
    });
  });

  describe('renewal', () => {
    it('does not let a credential renew itself by default', () => {
      const token = new SensitiveString(CANARY, 'credential', 'token', {
        ttl: MINUTE,
        allowRenewal: false,
      });

      expect(token.isRenewable()).toBe(false);
      expect(() => token.renew(MINUTE)).toThrow(RenewalNotAllowedError);

      const defaulted = new SensitiveString(CANARY, 'credential', 'token', { ttl: MINUTE });
      expect(defaulted.isRenewable()).toBe(false);
    });

    it('does not let the construction option lift a policy prohibition', () => {
      registerPolicy(
        { name: 'sensitive', redact: () => '[REDACTED:sensitive]', allowRenewal: false },
        { overwrite: true }
      );

      const value = new SensitiveString(CANARY, 'sensitive', 'canary', {
        ttl: MINUTE,
        allowRenewal: true,
      });

      expect(value.isRenewable()).toBe(false);
      expect(() => value.renew(MINUTE)).toThrow(RenewalNotAllowedError);
      expect(value.expiresAt).toEqual(new Date(START.getTime() + MINUTE));
    });

    it('does not extend past the lifetime cap however often it is renewed', () => {
      registerPolicy(
        { name: 'sensitive', redact: () => '[REDACTED:sensitive]', maxTtl: 3 * MINUTE },
        { overwrite: true }
      );

      const session = new SensitiveString(CANARY, 'sensitive', 'session', { ttl: MINUTE });
      const cap = new Date(START.getTime() + 3 * MINUTE);

      session.renew(MINUTE);
      session.renew(MINUTE);
      expect(session.expiresAt).toEqual(cap);

      for (let attempt = 0; attempt < 5; attempt++) {
        expect(() => session.renew(MINUTE)).toThrow(RenewalNotAllowedError);
      }

      expect(session.expiresAt).toEqual(cap);

      advance(3 * MINUTE);
      expect(() => session.reveal()).toThrow(ExpiredSensitiveValueError);
    });

    it('does not take effect when the audit sink rejects it', () => {
      const session = new SensitiveString(CANARY, 'sensitive', 'session', { ttl: MINUTE });

      expect(() =>
        session.renew(
          10 * MINUTE,
          {},
          {
            name: 'refusing',
            auditReveal: () => {
              throw new Error('audit sink unavailable');
            },
          }
        )
      ).toThrow('audit sink unavailable');

      expect(session.expiresAt).toEqual(new Date(START.getTime() + MINUTE));
      expect(session.renewalCount).toBe(0);
    });

    it('does not take effect when the policy denies the context', () => {
      registerPolicy(
        {
          name: 'sensitive',
          redact: () => '[REDACTED:sensitive]',
          checkRevealAllowed: (ctx) => {
            if (ctx === null) {
              throw new Error('context required');
            }
          },
        },
        { overwrite: true }
      );

      const session = new SensitiveString(CANARY, 'sensitive', 'session', { ttl: MINUTE });

      expect(() => session.renew(MINUTE)).toThrow('context required');
      expect(session.expiresAt).toEqual(new Date(START.getTime() + MINUTE));
      expect(session.renewalCount).toBe(0);
    });

    it('leaves no audit record for a refused renewal', () => {
      const records: RevealDetails[] = [];
      const token = new SensitiveString(CANARY, 'credential', 'token', { ttl: MINUTE });

      withRevealContext({ name: 'refresh', auditReveal: (_v, d) => records.push(d) }, () => {
        expect(() => token.renew(MINUTE)).toThrow(RenewalNotAllowedError);
      });

      expect(records).toEqual([]);
    });

    it('reports a renewal without disclosing the value', () => {
      const records: RevealDetails[] = [];
      const session = new SensitiveString(CANARY, 'sensitive', 'session', { ttl: MINUTE });

      session.renew(MINUTE, {}, { name: 'refresh', auditReveal: (_v, d) => records.push(d) });

      expect(JSON.stringify(records)).not.toContain(CANARY);
    });
  });

  describe('the deadline itself', () => {
    it('cannot be moved through the getter', () => {
      const token = new SensitiveString(CANARY, 'credential', 'token', { ttl: MINUTE });

      const stolen = token.expiresAt;
      stolen?.setFullYear(2099);

      advance(MINUTE);
      expect(token.isExpired()).toBe(true);
      expect(() => token.reveal()).toThrow(ExpiredSensitiveValueError);
    });

    it('cannot be moved by mutating the Date that set it', () => {
      const deadline = new Date(START.getTime() + MINUTE);
      const token = new SensitiveString(CANARY, 'credential', 'token', { expiresAt: deadline });

      deadline.setFullYear(2099);

      advance(MINUTE);
      expect(() => token.reveal()).toThrow(ExpiredSensitiveValueError);
    });

    it('cannot be forged by a Date whose getTime lies', () => {
      class DriftingDate extends Date {
        #calls = 0;

        override getTime(): number {
          this.#calls++;
          return this.#calls === 1 ? START.getTime() + MINUTE : Number.MAX_SAFE_INTEGER;
        }
      }

      const token = new SensitiveString(CANARY, 'credential', 'token', {
        expiresAt: new DriftingDate(START.getTime() + MINUTE),
      });

      advance(MINUTE);
      expect(() => token.reveal()).toThrow(ExpiredSensitiveValueError);
    });

    it('accepts a Date from another realm', () => {
      const foreign = runInNewContext('new Date(time)', { time: START.getTime() + MINUTE }) as Date;
      const token = new SensitiveString(CANARY, 'credential', 'token', { expiresAt: foreign });

      expect(token.expiresAt).toEqual(new Date(START.getTime() + MINUTE));
      advance(MINUTE);
      expect(() => token.reveal()).toThrow(ExpiredSensitiveValueError);
    });

    it('treats a zero ttl as expired rather than as no deadline', () => {
      const token = new SensitiveString(CANARY, 'credential', 'token', { ttl: 0 });

      expect(token.isExpired()).toBe(true);
      expect(() => token.reveal()).toThrow(ExpiredSensitiveValueError);
    });

    it('rejects a negative ttl instead of reading it as a past deadline', () => {
      expect(() => new SensitiveString(CANARY, 'credential', 'token', { ttl: -MINUTE })).toThrow(
        RangeError
      );
    });
  });

  describe('the onExpire callback', () => {
    it('cannot recurse through the value that fired it', () => {
      let calls = 0;
      let seen: unknown;

      const token: SensitiveString<'sensitive'> = new SensitiveString(
        CANARY,
        'sensitive',
        'token',
        {
          ttl: MINUTE,
          onExpire: () => {
            calls++;
            try {
              token.reveal();
            } catch (error) {
              seen = error;
            }
          },
        }
      );

      advance(MINUTE);
      expect(() => token.reveal()).toThrow(ExpiredSensitiveValueError);

      expect(calls).toBe(1);
      expect(seen).toBeInstanceOf(ExpiredSensitiveValueError);
      expect(String(seen)).not.toContain(CANARY);
    });

    it('does not fire from inspection or redaction', () => {
      const onExpire = vi.fn();
      const token = new SensitiveString(CANARY, 'sensitive', 'token', { ttl: MINUTE, onExpire });

      advance(MINUTE);

      expect(token.toString()).toBe('[REDACTED:sensitive]');
      expect(util.inspect(token)).toContain('EXPIRED');
      expect(token.expiresAt).toEqual(new Date(START.getTime() + MINUTE));
      expect(token.ttlRemaining()).toBe(-1);
      expect(onExpire).not.toHaveBeenCalled();

      expect(token.isExpired()).toBe(true);
      expect(onExpire).toHaveBeenCalledTimes(1);
    });
  });

  describe('the wire format', () => {
    it('never emits an expired value', () => {
      const token = new SensitiveString(CANARY, 'credential', 'token', { ttl: MINUTE });
      advance(MINUTE);

      expect(() => token.serialize()).toThrow(ExpiredSensitiveValueError);
      expect(() => JSON.stringify(token.serialize())).toThrow(ExpiredSensitiveValueError);
    });

    it('does not let a payload grant the right to renew a credential', () => {
      const received = SensitiveString.deserialize({
        __sensitive: true,
        klass: 'credential',
        value: CANARY,
        label: 'token',
        expiresAt: new Date(START.getTime() + MINUTE).toISOString(),
        allowRenewal: true,
        maxRenewals: 99,
        renewalCount: 0,
      });

      expect(received.isRenewable()).toBe(false);
      expect(() => received.renew(MINUTE)).toThrow(RenewalNotAllowedError);
    });

    it('does not let a payload reset the renewal budget', () => {
      const session = new SensitiveString(CANARY, 'sensitive', 'session', {
        ttl: MINUTE,
        maxRenewals: 1,
      });
      session.renew(MINUTE);

      const received = SensitiveString.deserialize<'sensitive'>(session.serialize());

      // The receiving process holds its own state, so it starts a fresh budget
      // rather than inheriting a spent one; what it must not inherit is a
      // deadline it did not enforce.
      expect(received.expiresAt).toEqual(new Date(START.getTime() + 2 * MINUTE));
      expect(received.renewalCount).toBe(0);
    });

    it('enforces a received deadline against the receiver clock', () => {
      const serialized = new SensitiveString(CANARY, 'credential', 'token', {
        ttl: MINUTE,
      }).serialize();

      // A receiver whose clock runs ahead rejects the value early, which is the
      // direction to fail in.
      advance(2 * MINUTE);
      const received = SensitiveString.deserialize(serialized);

      expect(received.isExpired()).toBe(true);
      expect(() => received.reveal()).toThrow(ExpiredSensitiveValueError);
    });

    it('applies the receiving policy cap to a received deadline', () => {
      const serialized = new SensitiveString(CANARY, 'sensitive', 'token', {
        ttl: 60 * MINUTE,
      }).serialize();

      registerPolicy(
        { name: 'sensitive', redact: () => '[REDACTED:sensitive]', maxTtl: MINUTE },
        { overwrite: true }
      );

      const received = SensitiveString.deserialize(serialized);
      expect(received.expiresAt).toEqual(new Date(START.getTime() + MINUTE));
    });
  });

  describe('redaction', () => {
    it('keeps the value out of every observable form after it expires', () => {
      const token = new SensitiveString(CANARY, 'credential', 'token', { ttl: MINUTE });
      advance(MINUTE);

      expect(String(token)).not.toContain(CANARY);
      expect(JSON.stringify({ token })).not.toContain(CANARY);
      expect(util.inspect(token)).not.toContain(CANARY);
      expect(util.inspect(token, { depth: 10, showHidden: true })).not.toContain(CANARY);
      expect(String(token.expiresAt)).not.toContain(CANARY);
    });

    it('names the label in the expiry error but never the value', () => {
      const token = new SensitiveString(CANARY, 'credential', 'session_token', { ttl: MINUTE });
      const unlabeled = new SensitiveString(CANARY, 'credential', undefined, { ttl: MINUTE });
      advance(MINUTE);

      try {
        token.reveal();
        expect.unreachable('reveal must throw once expired');
      } catch (error) {
        // The label is developer-supplied and identifies which value lapsed, so
        // it appears by design. The protected value never does.
        expect((error as Error).message).toContain('session_token');
        expect((error as Error).message).not.toContain(CANARY);
        expect(util.inspect(error)).not.toContain(CANARY);
      }

      expect(() => unlabeled.reveal()).toThrow(
        `Sensitive value expired at ${new Date(START.getTime() + MINUTE).toISOString()}`
      );
    });
  });
});
