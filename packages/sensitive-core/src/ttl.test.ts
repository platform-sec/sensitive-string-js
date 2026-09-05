import * as util from 'node:util';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  ExpiredSensitiveValueError,
  registerPolicy,
  RenewalNotAllowedError,
  resetPolicies,
  SensitiveString,
  st,
  withRevealContext,
} from './index.js';
import type { RevealDetails } from './index.js';

const MINUTE = 60_000;
const START = new Date('2026-01-01T00:00:00.000Z');

/** Advance the clock the expiry checks read. */
function advance(ms: number): void {
  vi.setSystemTime(new Date(Date.now() + ms));
}

describe('TTL and expiration', () => {
  beforeEach(() => {
    resetPolicies();
    vi.useFakeTimers();
    vi.setSystemTime(START);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('construction', () => {
    it('derives a deadline from ttl, measured from construction', () => {
      const otp = new SensitiveString('123456', 'credential', 'otp', { ttl: 5 * MINUTE });

      expect(otp.expiresAt).toEqual(new Date(START.getTime() + 5 * MINUTE));
    });

    it('accepts an absolute deadline', () => {
      const deadline = new Date('2026-06-01T12:00:00.000Z');
      const session = new SensitiveString('token', 'credential', 'session', {
        expiresAt: deadline,
      });

      expect(session.expiresAt).toEqual(deadline);
    });

    it('has no deadline when neither option is given', () => {
      const value = new SensitiveString('value', 'sensitive');

      expect(value.expiresAt).toBeUndefined();
      expect(value.isExpired()).toBe(false);
      expect(value.ttlRemaining()).toBeUndefined();
    });

    it('reads the deadline once, so mutating the Date afterwards moves nothing', () => {
      const deadline = new Date(START.getTime() + MINUTE);
      const value = new SensitiveString('value', 'sensitive', undefined, { expiresAt: deadline });

      deadline.setFullYear(2099);

      expect(value.expiresAt).toEqual(new Date(START.getTime() + MINUTE));
    });

    it('rejects ttl and expiresAt together', () => {
      expect(
        () =>
          new SensitiveString('value', 'sensitive', undefined, {
            ttl: MINUTE,
            expiresAt: new Date(),
          })
      ).toThrow(/mutually exclusive/);
    });

    it('treats ttl 0 as already expired rather than as no TTL', () => {
      const value = new SensitiveString('value', 'sensitive', undefined, { ttl: 0 });

      expect(value.expiresAt).toEqual(START);
      expect(value.isExpired()).toBe(true);
      expect(() => value.reveal()).toThrow(ExpiredSensitiveValueError);
    });

    it('accepts a deadline in the past and refuses to read it', () => {
      const value = new SensitiveString('value', 'sensitive', undefined, {
        expiresAt: new Date('2020-01-01T00:00:00.000Z'),
      });

      expect(value.isExpired()).toBe(true);
      expect(() => value.reveal()).toThrow(ExpiredSensitiveValueError);
    });

    it('accepts a ttl of one millisecond', () => {
      const value = new SensitiveString('value', 'sensitive', undefined, { ttl: 1 });

      expect(value.isExpired()).toBe(false);
      advance(1);
      expect(value.isExpired()).toBe(true);
    });

    it('accepts a ttl of years', () => {
      const tenYears = 10 * 365 * 24 * 60 * 60_000;
      const value = new SensitiveString('value', 'sensitive', undefined, { ttl: tenYears });

      advance(9 * 365 * 24 * 60 * 60_000);
      expect(value.isExpired()).toBe(false);
      expect(value.reveal()).toBe('value');
    });

    it('rejects a negative ttl', () => {
      expect(() => new SensitiveString('value', 'sensitive', undefined, { ttl: -1 })).toThrow(
        RangeError
      );
    });

    it('rejects a non-finite ttl', () => {
      expect(
        () =>
          new SensitiveString('value', 'sensitive', undefined, { ttl: Number.POSITIVE_INFINITY })
      ).toThrow(RangeError);
      expect(
        () => new SensitiveString('value', 'sensitive', undefined, { ttl: Number.NaN })
      ).toThrow(RangeError);
    });

    it('rejects a ttl whose deadline no Date can represent', () => {
      // Finite, so it passes the duration check, but the deadline it computes
      // is an Invalid Date: it would never expire and would throw on serialize.
      expect(
        () => new SensitiveString('value', 'sensitive', undefined, { ttl: Number.MAX_VALUE })
      ).toThrow(RangeError);
      expect(() => new SensitiveString('value', 'sensitive', undefined, { ttl: 8.64e15 })).toThrow(
        /representable date/
      );

      const largest = new SensitiveString('value', 'sensitive', undefined, {
        ttl: 8_640_000_000_000_000 - START.getTime(),
      });
      expect(largest.expiresAt?.toISOString()).toBe('+275760-09-13T00:00:00.000Z');
    });

    it('lets a policy cap bring an over-large ttl back into range', () => {
      registerPolicy(
        { name: 'sensitive', redact: () => '[REDACTED:sensitive]', maxTtl: MINUTE },
        { overwrite: true }
      );

      const value = new SensitiveString('value', 'sensitive', undefined, {
        ttl: Number.MAX_VALUE,
      });

      expect(value.expiresAt).toEqual(new Date(START.getTime() + MINUTE));
    });

    it('rejects a ttl that is not a number', () => {
      expect(
        () =>
          new SensitiveString('value', 'sensitive', undefined, {
            ttl: '60000' as unknown as number,
          })
      ).toThrow(TypeError);
    });

    it('rejects an invalid or non-Date expiresAt', () => {
      expect(
        () => new SensitiveString('value', 'sensitive', undefined, { expiresAt: new Date('nope') })
      ).toThrow(RangeError);
      expect(
        () =>
          new SensitiveString('value', 'sensitive', undefined, {
            expiresAt: START.getTime() as unknown as Date,
          })
      ).toThrow(TypeError);
    });

    it('rejects options of the wrong type', () => {
      expect(
        () =>
          new SensitiveString('value', 'sensitive', undefined, {
            ttl: MINUTE,
            maxRenewals: 1.5,
          })
      ).toThrow(RangeError);
      expect(
        () =>
          new SensitiveString('value', 'sensitive', undefined, {
            maxRenewals: '2' as unknown as number,
          })
      ).toThrow(TypeError);
      expect(
        () =>
          new SensitiveString('value', 'sensitive', undefined, {
            onExpire: 'not-a-function' as unknown as () => void,
          })
      ).toThrow(TypeError);
      expect(
        () =>
          new SensitiveString('value', 'sensitive', undefined, {
            allowRenewal: 'yes' as unknown as boolean,
          })
      ).toThrow(TypeError);
    });
  });

  describe('inspection', () => {
    it('reports remaining time and switches to -1 at the deadline', () => {
      const otp = new SensitiveString('123456', 'credential', 'otp', { ttl: 5 * MINUTE });

      expect(otp.ttlRemaining()).toBe(5 * MINUTE);
      advance(2 * MINUTE);
      expect(otp.ttlRemaining()).toBe(3 * MINUTE);
      advance(3 * MINUTE);
      expect(otp.ttlRemaining()).toBe(-1);
      advance(MINUTE);
      expect(otp.ttlRemaining()).toBe(-1);
    });

    it('is not usable at its own deadline', () => {
      const otp = new SensitiveString('123456', 'credential', 'otp', { ttl: MINUTE });

      advance(MINUTE - 1);
      expect(otp.isExpired()).toBe(false);
      advance(1);
      expect(otp.isExpired()).toBe(true);
    });

    it('returns a copy of the deadline that cannot move it', () => {
      const otp = new SensitiveString('123456', 'credential', 'otp', { ttl: MINUTE });
      const first = otp.expiresAt;

      expect(first).toBeInstanceOf(Date);
      first?.setFullYear(2099);

      expect(otp.expiresAt).toEqual(new Date(START.getTime() + MINUTE));
      expect(otp.expiresAt).not.toBe(first);
    });

    it('marks an expired value in the inspect output without changing the redaction', () => {
      const otp = new SensitiveString('123456', 'credential', 'otp', { ttl: MINUTE });

      expect(util.inspect(otp)).toBe('SensitiveString<credential:otp> { [REDACTED:credential] }');
      advance(MINUTE);
      expect(util.inspect(otp)).toBe(
        'SensitiveString<credential:otp> { [REDACTED:credential] EXPIRED }'
      );
      expect(otp.toString()).toBe('[REDACTED:credential]');
      expect(JSON.stringify({ otp })).toBe('{"otp":"[REDACTED:credential]"}');
    });
  });

  describe('access after the deadline', () => {
    it('throws an error carrying both timestamps and the label', () => {
      const otp = new SensitiveString('123456', 'credential', 'otp', { ttl: MINUTE });
      advance(3 * MINUTE);

      try {
        otp.reveal();
        expect.unreachable('reveal must throw once expired');
      } catch (error) {
        expect(error).toBeInstanceOf(ExpiredSensitiveValueError);
        const expired = error as ExpiredSensitiveValueError;
        expect(expired.name).toBe('ExpiredSensitiveValueError');
        expect(expired.expiredAt).toEqual(new Date(START.getTime() + MINUTE));
        expect(expired.attemptedAt).toEqual(new Date(START.getTime() + 3 * MINUTE));
        expect(expired.expiredFor).toBe(2 * MINUTE);
        expect(expired.label).toBe('otp');
        expect(expired.message).toContain('otp');
      }
    });

    it('leaves redaction and documented metadata working', () => {
      const otp = new SensitiveString('123456', 'sensitive', 'otp', { ttl: MINUTE });
      advance(MINUTE);

      expect(otp.toString()).toBe('[REDACTED:sensitive]');
      expect(otp.toJSON()).toBe('[REDACTED:sensitive]');
      expect(otp.length).toBe(6);
      expect(otp.isEmpty()).toBe(false);
      expect(otp.klass).toBe('sensitive');
      expect(otp.label).toBe('otp');
    });

    it('fires onExpire once, on first detection', () => {
      const onExpire = vi.fn();
      const otp = new SensitiveString('123456', 'sensitive', 'otp', { ttl: MINUTE, onExpire });

      expect(otp.isExpired()).toBe(false);
      expect(onExpire).not.toHaveBeenCalled();

      advance(MINUTE);
      expect(otp.isExpired()).toBe(true);
      expect(otp.isExpired()).toBe(true);
      expect(() => otp.reveal()).toThrow(ExpiredSensitiveValueError);

      expect(onExpire).toHaveBeenCalledTimes(1);
    });

    it('swallows an onExpire callback that throws', () => {
      const otp = new SensitiveString('123456', 'sensitive', 'otp', {
        ttl: MINUTE,
        onExpire: () => {
          throw new Error('callback failure');
        },
      });

      advance(MINUTE);
      expect(otp.isExpired()).toBe(true);
      expect(() => otp.reveal()).toThrow(ExpiredSensitiveValueError);
    });
  });

  describe('renewal', () => {
    it('extends the deadline from the current one', () => {
      const session = new SensitiveString('token', 'sensitive', 'session', { ttl: 5 * MINUTE });

      advance(MINUTE);
      session.renew(5 * MINUTE);

      expect(session.expiresAt).toEqual(new Date(START.getTime() + 10 * MINUTE));
      expect(session.renewalCount).toBe(1);
    });

    it('extends an expired value from now, so it grants the full duration', () => {
      const session = new SensitiveString('token', 'sensitive', 'session', { ttl: MINUTE });

      advance(10 * MINUTE);
      expect(session.isExpired()).toBe(true);

      session.renew(5 * MINUTE);

      expect(session.isExpired()).toBe(false);
      expect(session.expiresAt).toEqual(new Date(START.getTime() + 15 * MINUTE));
      expect(session.reveal()).toBe('token');
    });

    it('re-arms onExpire for the new deadline', () => {
      const onExpire = vi.fn();
      const session = new SensitiveString('token', 'sensitive', 'session', {
        ttl: MINUTE,
        onExpire,
      });

      advance(MINUTE);
      expect(session.isExpired()).toBe(true);
      expect(onExpire).toHaveBeenCalledTimes(1);

      session.renew(MINUTE);
      advance(2 * MINUTE);

      expect(session.isExpired()).toBe(true);
      expect(onExpire).toHaveBeenCalledTimes(2);
    });

    it('clamps the result to maxExtension', () => {
      const session = new SensitiveString('token', 'sensitive', 'session', { ttl: MINUTE });
      const cap = new Date(START.getTime() + 2 * MINUTE);

      session.renew(10 * MINUTE, { maxExtension: cap });

      expect(session.expiresAt).toEqual(cap);
    });

    it('accumulates across renewals up to maxRenewals', () => {
      const session = new SensitiveString('token', 'sensitive', 'session', {
        ttl: MINUTE,
        maxRenewals: 2,
      });

      expect(session.isRenewable()).toBe(true);
      session.renew(MINUTE);
      session.renew(MINUTE);

      expect(session.renewalCount).toBe(2);
      expect(session.expiresAt).toEqual(new Date(START.getTime() + 3 * MINUTE));
      expect(session.isRenewable()).toBe(false);
      expect(() => session.renew(MINUTE)).toThrow(RenewalNotAllowedError);
    });

    it('refuses when the class does not allow renewal', () => {
      const otp = new SensitiveString('123456', 'credential', 'otp', { ttl: MINUTE });

      expect(otp.isRenewable()).toBe(false);
      expect(() => otp.renew(MINUTE)).toThrow(RenewalNotAllowedError);
      expect(() => otp.renew(MINUTE)).toThrow(/not allowed/);
    });

    it('refuses when there is no deadline to extend', () => {
      const value = new SensitiveString('value', 'sensitive', 'note');

      expect(value.isRenewable()).toBe(false);
      expect(() => value.renew(MINUTE)).toThrow(/no expiration/);
    });

    it('refuses a non-positive or non-finite extension', () => {
      const session = new SensitiveString('token', 'sensitive', 'session', { ttl: MINUTE });

      expect(() => session.renew(0)).toThrow(RangeError);
      expect(() => session.renew(-MINUTE)).toThrow(RangeError);
      expect(() => session.renew(Number.POSITIVE_INFINITY)).toThrow(RangeError);
      expect(() => session.renew('60000' as unknown as number)).toThrow(TypeError);
      expect(() => session.renew(Number.MAX_VALUE)).toThrow(/representable date/);
      expect(() => session.renew(MINUTE, { maxExtension: 0 as unknown as Date })).toThrow(
        TypeError
      );
      expect(session.renewalCount).toBe(0);
    });

    it('refuses when a cap leaves no room, instead of reporting a renewal it did not make', () => {
      const session = new SensitiveString('token', 'sensitive', 'session', { ttl: 5 * MINUTE });

      expect(() =>
        session.renew(MINUTE, { maxExtension: new Date(START.getTime() + MINUTE) })
      ).toThrow(RenewalNotAllowedError);
      expect(session.expiresAt).toEqual(new Date(START.getTime() + 5 * MINUTE));
      expect(session.renewalCount).toBe(0);
    });

    it('audits the extension with both deadlines', () => {
      const records: RevealDetails[] = [];
      const session = new SensitiveString('token', 'sensitive', 'session', { ttl: MINUTE });

      session.renew(MINUTE, {}, { name: 'refresh', auditReveal: (_v, d) => records.push(d) });

      expect(records).toEqual([
        {
          operation: 'renew',
          previousExpiresAt: new Date(START.getTime() + MINUTE).toISOString(),
          expiresAt: new Date(START.getTime() + 2 * MINUTE).toISOString(),
          renewalCount: 1,
        },
      ]);
    });

    it('audits through the ambient context', () => {
      const records: RevealDetails[] = [];
      const session = new SensitiveString('token', 'sensitive', 'session', { ttl: MINUTE });

      withRevealContext({ name: 'refresh', auditReveal: (_v, d) => records.push(d) }, () => {
        session.renew(MINUTE);
      });

      expect(records).toHaveLength(1);
      expect(records[0]?.operation).toBe('renew');
    });
  });

  describe('derived values', () => {
    it('carries the deadline into every derived value', () => {
      const secret = new SensitiveString('secret-value', 'sensitive', 'secret', { ttl: MINUTE });
      const derived = [
        secret.substring(0, 6),
        secret.trim(),
        secret.slice(2),
        secret.toUpperCase(),
        secret.map((value) => value),
        secret.replace('secret', 'x'),
        secret.charAt(0),
        secret.reclassify('credential'),
        secret.concat('-suffix'),
        ...secret.split('-'),
        ...(secret.match(/secret/) ?? []),
      ];

      advance(MINUTE);

      for (const value of derived) {
        expect(value.expiresAt).toEqual(new Date(START.getTime() + MINUTE));
        expect(value.isExpired()).toBe(true);
        expect(() => value.reveal()).toThrow(ExpiredSensitiveValueError);
      }
    });

    it('takes the earliest deadline when two values are combined', () => {
      const soon = new SensitiveString('a', 'sensitive', undefined, { ttl: MINUTE });
      const later = new SensitiveString('b', 'sensitive', undefined, { ttl: 10 * MINUTE });

      const combined = soon.concat(later);

      expect(combined.expiresAt).toEqual(new Date(START.getTime() + MINUTE));

      advance(MINUTE);
      expect(combined.isExpired()).toBe(true);
      expect(later.isExpired()).toBe(false);
    });

    it('gives an unexpiring operand the deadline of the one it is combined with', () => {
      const expiring = new SensitiveString('a', 'sensitive', undefined, { ttl: MINUTE });
      const permanent = new SensitiveString('b', 'sensitive');

      expect(permanent.concat(expiring).expiresAt).toEqual(new Date(START.getTime() + MINUTE));
      expect(expiring.concat(permanent).expiresAt).toEqual(new Date(START.getTime() + MINUTE));
      expect(permanent.concat('plain').expiresAt).toBeUndefined();
    });

    it('sees a renewal of the value it came from', () => {
      const session = new SensitiveString('token', 'sensitive', 'session', { ttl: MINUTE });
      const derived = session.substring(0, 3);

      session.renew(5 * MINUTE);

      expect(derived.expiresAt).toEqual(new Date(START.getTime() + 6 * MINUTE));
      advance(3 * MINUTE);
      expect(derived.reveal()).toBe('tok');
    });

    it('refuses to renew through a derived value', () => {
      const session = new SensitiveString('token', 'sensitive', 'session', { ttl: MINUTE });
      const derived = session.substring(0, 3);

      expect(derived.isRenewable()).toBe(false);
      expect(derived.renewalCount).toBe(0);
      expect(() => derived.renew(MINUTE)).toThrow(RenewalNotAllowedError);
      expect(() => derived.renew(MINUTE)).toThrow(/derived/);
      expect(session.expiresAt).toEqual(new Date(START.getTime() + MINUTE));
    });

    it('fires the onExpire of every value a derivative came from', () => {
      const first = vi.fn();
      const second = vi.fn();
      const a = new SensitiveString('a', 'sensitive', undefined, { ttl: MINUTE, onExpire: first });
      const b = new SensitiveString('b', 'sensitive', undefined, { ttl: MINUTE, onExpire: second });

      const combined = a.concat(b);
      advance(MINUTE);

      expect(combined.isExpired()).toBe(true);
      expect(first).toHaveBeenCalledTimes(1);
      expect(second).toHaveBeenCalledTimes(1);
    });
  });

  describe('template literals', () => {
    it('carries an interpolated deadline into the result', () => {
      const token = new SensitiveString('tok', 'credential', 'token', { ttl: MINUTE });
      const url = st`Bearer ${token}`;

      expect(url.expiresAt).toEqual(new Date(START.getTime() + MINUTE));

      advance(MINUTE);
      expect(url.isExpired()).toBe(true);
      expect(() => url.reveal()).toThrow(ExpiredSensitiveValueError);
    });

    it('takes the earliest deadline of its interpolations', () => {
      const soon = new SensitiveString('a', 'sensitive', undefined, { ttl: MINUTE });
      const later = new SensitiveString('b', 'sensitive', undefined, { ttl: 10 * MINUTE });

      expect(st`${later} and ${soon}`.expiresAt).toEqual(new Date(START.getTime() + MINUTE));
    });

    it('refuses to build from an expired interpolation', () => {
      const token = new SensitiveString('tok', 'credential', 'token', { ttl: MINUTE });
      advance(MINUTE);

      expect(() => st`Bearer ${token}`).toThrow(ExpiredSensitiveValueError);
    });

    it('leaves a template with no protected interpolations unexpiring', () => {
      expect(st`plain ${'text'}`.expiresAt).toBeUndefined();
    });
  });

  describe('the wire format', () => {
    it('carries the deadline across serialize and deserialize', () => {
      const token = new SensitiveString('tok', 'credential', 'token', { ttl: 5 * MINUTE });
      const serialized = token.serialize();

      expect(serialized.expiresAt).toBe(new Date(START.getTime() + 5 * MINUTE).toISOString());

      advance(MINUTE);
      const received = SensitiveString.deserialize(serialized);

      expect(received.expiresAt).toEqual(new Date(START.getTime() + 5 * MINUTE));
      expect(received.ttlRemaining()).toBe(4 * MINUTE);
      expect(received.reveal()).toBe('tok');

      advance(4 * MINUTE);
      expect(() => received.reveal()).toThrow(ExpiredSensitiveValueError);
    });

    it('reports the renewed deadline rather than the one it rendered first', () => {
      const session = new SensitiveString('tok', 'sensitive', 'session', { ttl: 5 * MINUTE });

      expect(session.serialize().expiresAt).toBe(
        new Date(START.getTime() + 5 * MINUTE).toISOString()
      );

      session.renew(5 * MINUTE);

      expect(session.serialize().expiresAt).toBe(
        new Date(START.getTime() + 10 * MINUTE).toISOString()
      );
    });

    it('renders every deadline across more of them than it holds at once', () => {
      // More distinct deadlines than the ISO rendering is memoized for, so the
      // memo is discarded partway through and has to rebuild. Each value is
      // then asked twice, once while the memo is cold for it and once after.
      const tokens = Array.from(
        { length: 300 },
        (_unused, index) =>
          new SensitiveString('tok', 'credential', 'token', { ttl: MINUTE + index })
      );

      for (const pass of [1, 2]) {
        for (const [index, token] of tokens.entries()) {
          expect({ pass, at: token.serialize().expiresAt }).toEqual({
            pass,
            at: new Date(START.getTime() + MINUTE + index).toISOString(),
          });
        }
      }
    });

    it('omits the deadline for a value that does not expire', () => {
      const serialized = new SensitiveString('tok', 'credential', 'token').serialize();

      expect(serialized).not.toHaveProperty('expiresAt');
      expect(SensitiveString.deserialize(serialized).expiresAt).toBeUndefined();
    });

    it('refuses to serialize an expired value', () => {
      const token = new SensitiveString('tok', 'credential', 'token', { ttl: MINUTE });
      advance(MINUTE);

      expect(() => token.serialize()).toThrow(ExpiredSensitiveValueError);
    });

    it('rejects a malformed deadline on the wire', () => {
      const base = { __sensitive: true as const, klass: 'credential' as const, value: 'tok' };

      expect(() => SensitiveString.deserialize({ ...base, expiresAt: 'not-a-date' })).toThrow(
        /not a valid date/
      );
      expect(() => SensitiveString.deserialize({ ...base, expiresAt: 12345 })).toThrow(
        /ISO 8601 string/
      );
    });

    it('deserializes an already-expired payload into a value that refuses to be read', () => {
      const received = SensitiveString.deserialize({
        __sensitive: true,
        klass: 'credential',
        value: 'tok',
        expiresAt: new Date(START.getTime() - MINUTE).toISOString(),
      });

      expect(received.isExpired()).toBe(true);
      expect(() => received.reveal()).toThrow(ExpiredSensitiveValueError);
    });
  });

  describe('policy integration', () => {
    it('applies defaultTtl to values constructed without one', () => {
      registerPolicy(
        { name: 'sensitive', redact: () => '[REDACTED:sensitive]', defaultTtl: 2 * MINUTE },
        { overwrite: true }
      );

      const value = new SensitiveString('value', 'sensitive');
      expect(value.expiresAt).toEqual(new Date(START.getTime() + 2 * MINUTE));

      const explicit = new SensitiveString('value', 'sensitive', undefined, { ttl: 30_000 });
      expect(explicit.expiresAt).toEqual(new Date(START.getTime() + 30_000));
    });

    it('caps every lifetime at maxTtl, including one the caller chose', () => {
      registerPolicy(
        { name: 'sensitive', redact: () => '[REDACTED:sensitive]', maxTtl: 2 * MINUTE },
        { overwrite: true }
      );

      expect(new SensitiveString('a', 'sensitive').expiresAt).toEqual(
        new Date(START.getTime() + 2 * MINUTE)
      );
      expect(
        new SensitiveString('a', 'sensitive', undefined, { ttl: 10 * MINUTE }).expiresAt
      ).toEqual(new Date(START.getTime() + 2 * MINUTE));
      expect(new SensitiveString('a', 'sensitive', undefined, { ttl: MINUTE }).expiresAt).toEqual(
        new Date(START.getTime() + MINUTE)
      );
    });

    it('caps renewals at maxTtl, measured from construction', () => {
      registerPolicy(
        { name: 'sensitive', redact: () => '[REDACTED:sensitive]', maxTtl: 3 * MINUTE },
        { overwrite: true }
      );

      const session = new SensitiveString('token', 'sensitive', 'session', { ttl: MINUTE });

      session.renew(10 * MINUTE);
      expect(session.expiresAt).toEqual(new Date(START.getTime() + 3 * MINUTE));

      expect(() => session.renew(MINUTE)).toThrow(RenewalNotAllowedError);
      expect(() => session.renew(MINUTE)).toThrow(/lifetime cap/);
    });

    it('requires an expiration when the policy says so', () => {
      registerPolicy(
        { name: 'sensitive', redact: () => '[REDACTED:sensitive]', requireExpiration: true },
        { overwrite: true }
      );

      expect(() => new SensitiveString('value', 'sensitive')).toThrow(/requires an expiration/);
      expect(new SensitiveString('value', 'sensitive', undefined, { ttl: MINUTE })).toBeInstanceOf(
        SensitiveString
      );
    });

    it('still derives from a value whose class requires an expiration', () => {
      registerPolicy(
        { name: 'sensitive', redact: () => '[REDACTED:sensitive]', requireExpiration: true },
        { overwrite: true }
      );

      const value = new SensitiveString('value', 'sensitive', undefined, { ttl: MINUTE });

      expect(value.substring(0, 3).reveal()).toBe('val');
      expect(value.substring(0, 3).expiresAt).toEqual(new Date(START.getTime() + MINUTE));
    });

    it('lets a policy make a credential renewable', () => {
      registerPolicy(
        { name: 'credential', redact: () => '[REDACTED:credential]', allowRenewal: true },
        { overwrite: true }
      );

      const token = new SensitiveString('tok', 'credential', 'token', { ttl: MINUTE });

      expect(token.isRenewable()).toBe(true);
      token.renew(MINUTE);
      expect(token.expiresAt).toEqual(new Date(START.getTime() + 2 * MINUTE));
    });
  });
});
