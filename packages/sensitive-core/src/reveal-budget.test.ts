import * as util from 'node:util';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  ExpiredSensitiveValueError,
  registerPolicy,
  resetPolicies,
  RevealLimitExceededError,
  RevealRateLimitError,
  SensitiveString,
  st,
  withDevMode,
  withRevealContext,
} from './index.js';
import { chargeReveal, checkRevealBudget, planRevealBudget } from './reveal-budget.js';
import type { RevealDetails } from './index.js';

const MINUTE = 60_000;
const START = new Date('2026-01-01T00:00:00.000Z');

/** Advance the clock the window reads. */
function advance(ms: number): void {
  vi.setSystemTime(new Date(Date.now() + ms));
}

describe('reveal counting and rate limiting', () => {
  beforeEach(() => {
    resetPolicies();
    vi.useFakeTimers();
    vi.setSystemTime(START);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('construction', () => {
    it('leaves a value unlimited when no option is given', () => {
      const value = new SensitiveString('value', 'sensitive');

      expect(value.revealCount).toBe(0);
      expect(value.revealsRemaining).toBeUndefined();
      expect(value.isExhausted()).toBe(false);

      for (let i = 0; i < 100; i++) {
        expect(value.reveal()).toBe('value');
      }

      expect(value.revealCount).toBe(100);
      expect(value.revealsRemaining).toBeUndefined();
    });

    it('accepts a lifetime limit of zero, which denies every reveal', () => {
      const value = new SensitiveString('value', 'credential', 'never', { maxReveals: 0 });

      expect(value.isExhausted()).toBe(true);
      expect(value.revealsRemaining).toBe(0);
      expect(() => value.reveal()).toThrow(RevealLimitExceededError);
    });

    it('rejects a maxReveals that is not a whole, non-negative number', () => {
      for (const maxReveals of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
        expect(
          () => new SensitiveString('value', 'sensitive', undefined, { maxReveals }),
          String(maxReveals)
        ).toThrow(RangeError);
      }

      expect(
        () =>
          new SensitiveString('value', 'sensitive', undefined, {
            maxReveals: '1' as unknown as number,
          })
      ).toThrow(TypeError);
    });

    it('rejects a window that is not a positive, finite number', () => {
      for (const revealWindow of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) {
        expect(
          () =>
            new SensitiveString('value', 'sensitive', undefined, {
              revealWindow,
              maxRevealsPerWindow: 1,
            }),
          String(revealWindow)
        ).toThrow(RangeError);
      }
    });

    it('rejects a per-window limit below one', () => {
      expect(
        () =>
          new SensitiveString('value', 'sensitive', undefined, {
            revealWindow: MINUTE,
            maxRevealsPerWindow: 0,
          })
      ).toThrow(/maxReveals: 0/);
    });

    it('refuses half a rate limit, which would silently be no rate limit', () => {
      expect(
        () => new SensitiveString('value', 'sensitive', undefined, { revealWindow: MINUTE })
      ).toThrow(/must be given together/);

      expect(
        () => new SensitiveString('value', 'sensitive', undefined, { maxRevealsPerWindow: 5 })
      ).toThrow(/must be given together/);
    });
  });

  describe('the lifetime limit', () => {
    it('allows a single-use secret to be revealed exactly once', () => {
      const bootstrap = new SensitiveString('bootstrap-key', 'credential', 'bootstrap', {
        maxReveals: 1,
      });

      expect(bootstrap.reveal()).toBe('bootstrap-key');
      expect(bootstrap.isExhausted()).toBe(true);
      expect(() => bootstrap.reveal()).toThrow(RevealLimitExceededError);
      expect(() => bootstrap.reveal()).toThrow(RevealLimitExceededError);
    });

    it('allows exactly N reveals', () => {
      const key = new SensitiveString('api-key', 'credential', 'api_key', { maxReveals: 3 });

      for (let i = 0; i < 3; i++) {
        expect(key.reveal()).toBe('api-key');
      }

      expect(() => key.reveal()).toThrow(RevealLimitExceededError);
      expect(key.revealCount).toBe(3);
    });

    it('counts up and reports what is left', () => {
      const key = new SensitiveString('api-key', 'credential', 'api_key', { maxReveals: 3 });

      expect([key.revealCount, key.revealsRemaining]).toEqual([0, 3]);

      key.reveal();
      expect([key.revealCount, key.revealsRemaining]).toEqual([1, 2]);

      key.reveal();
      expect([key.revealCount, key.revealsRemaining]).toEqual([2, 1]);

      key.reveal();
      expect([key.revealCount, key.revealsRemaining]).toEqual([3, 0]);
      expect(key.isExhausted()).toBe(true);
    });

    it('does not count a refused reveal against the budget', () => {
      const key = new SensitiveString('api-key', 'credential', 'api_key', { maxReveals: 1 });

      key.reveal();

      for (let attempt = 0; attempt < 5; attempt++) {
        expect(() => key.reveal()).toThrow(RevealLimitExceededError);
      }

      expect(key.revealCount).toBe(1);
    });

    it('names the limit, the attempt, and the label in the error', () => {
      const key = new SensitiveString('api-key', 'credential', 'api_key', { maxReveals: 2 });

      key.reveal();
      key.reveal();

      try {
        key.reveal();
        expect.unreachable('an exhausted value must refuse');
      } catch (error) {
        expect(error).toBeInstanceOf(RevealLimitExceededError);
        const refusal = error as RevealLimitExceededError;

        expect(refusal.name).toBe('RevealLimitExceededError');
        expect(refusal.limit).toBe(2);
        expect(refusal.attempts).toBe(3);
        expect(refusal.label).toBe('api_key');
        expect(refusal.message).toContain('api_key');
      }
    });

    it('leaves the label out of the message when there is none', () => {
      const key = new SensitiveString('api-key', 'credential', undefined, { maxReveals: 0 });

      expect(() => key.reveal()).toThrow('Sensitive value has been revealed 0 times, ');
    });
  });

  describe('what counts as a reveal', () => {
    it('charges one per exposing operation', () => {
      const operations: readonly [string, (value: SensitiveString<'sensitive'>) => unknown][] = [
        ['reveal', (v) => v.reveal()],
        ['mask', (v) => v.mask({ showLast: 2 })],
        ['serialize', (v) => v.serialize()],
        ['map', (v) => v.map((raw) => raw)],
        ['substring', (v) => v.substring(0, 2)],
        ['concat', (v) => v.concat('tail')],
        ['startsWith', (v) => v.startsWith('s')],
        ['test', (v) => v.test(/secret/)],
        ['split', (v) => v.split('-')],
        ['template literal', (v) => st`bearer ${v}`],
      ];

      for (const [name, operation] of operations) {
        const value = new SensitiveString('secret-value', 'sensitive', 'canary');

        operation(value);
        expect(value.revealCount, name).toBe(1);
      }
    });

    it('does not charge a comparison, and does not refuse one when the budget is spent', () => {
      const stored = new SensitiveString('secret-value', 'credential', 'password', {
        maxReveals: 1,
      });

      stored.reveal();
      expect(stored.isExhausted()).toBe(true);

      // Comparison is the operation the library wants used in place of a
      // reveal, so a spent budget must not push a caller back to reveal().
      expect(stored.equals('secret-value')).toBe(true);
      expect(stored.equals('wrong')).toBe(false);
      expect(new SensitiveString('secret-value', 'credential').equals(stored)).toBe(true);
      expect(stored.revealCount).toBe(1);
    });

    it('does not charge redaction or metadata', () => {
      const value = new SensitiveString('secret-value', 'sensitive', 'canary', { maxReveals: 1 });

      String(value);
      JSON.stringify({ value });
      util.inspect(value);
      expect(value.length).toBe(12);
      expect(value.isEmpty()).toBe(false);
      expect(value.klass).toBe('sensitive');

      expect(value.revealCount).toBe(0);
      expect(value.reveal()).toBe('secret-value');
    });

    it('does not charge a reveal an audit hook stopped', () => {
      const key = new SensitiveString('api-key', 'credential', 'api_key', { maxReveals: 1 });

      expect(() =>
        key.reveal({
          name: 'audited',
          auditReveal: () => {
            throw new Error('audit sink unavailable');
          },
        })
      ).toThrow('audit sink unavailable');

      expect(key.revealCount).toBe(0);
      expect(key.isExhausted()).toBe(false);
      expect(key.reveal()).toBe('api-key');
    });

    it('does not charge a reveal the policy denied', () => {
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

      const value = new SensitiveString('secret-value', 'sensitive', 'canary', { maxReveals: 1 });

      expect(() => value.reveal()).toThrow('context required');
      expect(value.revealCount).toBe(0);

      withRevealContext({ name: 'authorized' }, () => {
        expect(value.reveal()).toBe('secret-value');
      });

      expect(value.revealCount).toBe(1);
    });

    it('reports exhaustion in inspect output, next to the redaction', () => {
      const key = new SensitiveString('api-key', 'credential', 'bootstrap', { maxReveals: 1 });

      expect(util.inspect(key)).toBe(
        'SensitiveString<credential:bootstrap> { [REDACTED:credential] }'
      );

      key.reveal();

      expect(util.inspect(key)).toBe(
        'SensitiveString<credential:bootstrap> { [REDACTED:credential] EXHAUSTED }'
      );
      expect(String(key)).toBe('[REDACTED:credential]');
    });
  });

  describe('the sliding window', () => {
    it('refuses once the window is full', () => {
      const key = new SensitiveString('api-key', 'credential', 'api_key', {
        revealWindow: MINUTE,
        maxRevealsPerWindow: 3,
      });

      for (let i = 0; i < 3; i++) {
        expect(key.reveal()).toBe('api-key');
      }

      expect(() => key.reveal()).toThrow(RevealRateLimitError);
      expect(key.revealCount).toBe(3);
      expect(key.isExhausted()).toBe(false);
    });

    it('allows more reveals once the oldest leaves the window', () => {
      const key = new SensitiveString('api-key', 'credential', 'api_key', {
        revealWindow: MINUTE,
        maxRevealsPerWindow: 2,
      });

      key.reveal();
      advance(30_000);
      key.reveal();
      expect(() => key.reveal()).toThrow(RevealRateLimitError);

      // The first charge leaves the window here, the second does not.
      advance(30_000);
      expect(key.reveal()).toBe('api-key');
      expect(() => key.reveal()).toThrow(RevealRateLimitError);

      advance(30_000);
      expect(key.reveal()).toBe('api-key');
    });

    it('slides rather than resetting on a fixed boundary', () => {
      const key = new SensitiveString('api-key', 'credential', 'api_key', {
        revealWindow: MINUTE,
        maxRevealsPerWindow: 2,
      });

      key.reveal();
      key.reveal();

      // A fixed-interval limiter would open the gate for two more here; a
      // sliding one only forgets the charges that are actually a minute old.
      advance(MINUTE - 1);
      expect(() => key.reveal()).toThrow(RevealRateLimitError);

      advance(1);
      key.reveal();
      key.reveal();
      expect(() => key.reveal()).toThrow(RevealRateLimitError);
    });

    it('says how long to wait', () => {
      const key = new SensitiveString('api-key', 'credential', 'api_key', {
        revealWindow: MINUTE,
        maxRevealsPerWindow: 2,
      });

      key.reveal();
      advance(10_000);
      key.reveal();
      advance(5_000);

      try {
        key.reveal();
        expect.unreachable('a full window must refuse');
      } catch (error) {
        expect(error).toBeInstanceOf(RevealRateLimitError);
        const refusal = error as RevealRateLimitError;

        expect(refusal.name).toBe('RevealRateLimitError');
        expect(refusal.retryAfter).toBe(MINUTE - 15_000);
        expect(refusal.windowLimit).toBe(2);
        expect(refusal.label).toBe('api_key');
      }

      advance(MINUTE - 15_000);
      expect(key.reveal()).toBe('api-key');
    });

    it('handles reveals that all land in the same millisecond', () => {
      const key = new SensitiveString('api-key', 'credential', 'api_key', {
        revealWindow: MINUTE,
        maxRevealsPerWindow: 4,
      });

      for (let i = 0; i < 4; i++) {
        key.reveal();
      }

      expect(() => key.reveal()).toThrow(new RegExp(`retry in ${MINUTE}ms`));

      advance(MINUTE);
      for (let i = 0; i < 4; i++) {
        expect(key.reveal()).toBe('api-key');
      }
    });

    it('works with a one-millisecond window', () => {
      const key = new SensitiveString('api-key', 'credential', 'api_key', {
        revealWindow: 1,
        maxRevealsPerWindow: 1,
      });

      key.reveal();
      expect(() => key.reveal()).toThrow(RevealRateLimitError);

      advance(1);
      expect(key.reveal()).toBe('api-key');
    });

    it('enforces a lifetime limit and a window together', () => {
      const key = new SensitiveString('api-key', 'credential', 'strict', {
        maxReveals: 3,
        revealWindow: MINUTE,
        maxRevealsPerWindow: 2,
      });

      key.reveal();
      key.reveal();
      expect(() => key.reveal()).toThrow(RevealRateLimitError);

      advance(MINUTE);
      key.reveal();

      // The lifetime limit is the one that cannot be waited out, and it is the
      // one reported once both would refuse.
      expect(() => key.reveal()).toThrow(RevealLimitExceededError);
      advance(MINUTE);
      expect(() => key.reveal()).toThrow(RevealLimitExceededError);
    });

    it('keeps no more timestamps than the limit needs, whatever the traffic', () => {
      // Driven through the module rather than the class, because the bound is
      // on state a caller cannot reach and asserting it is the point.
      const budget = planRevealBudget({ revealWindow: MINUTE, maxRevealsPerWindow: 5 });
      const state = { reveals: 0, budget: budget! };
      const rate = budget!.rate!;

      for (let i = 0; i < 10_000; i++) {
        advance(MINUTE / 4);
        checkRevealBudget([state], 'api_key');
        chargeReveal([state]);
        expect(rate.times.length).toBeLessThanOrEqual(2 * rate.limit);
      }

      expect(state.reveals).toBe(10_000);
    });

    it('drops every timestamp once the window passes with no traffic', () => {
      const budget = planRevealBudget({ revealWindow: MINUTE, maxRevealsPerWindow: 5 });
      const state = { reveals: 0, budget: budget! };
      const rate = budget!.rate!;

      for (let i = 0; i < 5; i++) {
        checkRevealBudget([state], undefined);
        chargeReveal([state]);
      }

      expect(rate.times.length).toBe(5);

      advance(MINUTE);
      checkRevealBudget([state], undefined);
      chargeReveal([state]);

      expect(rate.times.length).toBe(1);
    });
  });

  describe('derived values', () => {
    it('spends the same budget as the value it came from', () => {
      const key = new SensitiveString('api-key', 'credential', 'bootstrap', { maxReveals: 1 });
      const derived = key.substring(0);

      expect(key.isExhausted()).toBe(true);
      expect(derived.isExhausted()).toBe(true);
      expect(derived.revealsRemaining).toBe(0);
      expect(() => derived.reveal()).toThrow(RevealLimitExceededError);
      expect(() => key.reveal()).toThrow(RevealLimitExceededError);
    });

    it('shares a counter in both directions', () => {
      const key = new SensitiveString('api-key', 'credential', 'api_key', { maxReveals: 4 });
      const derived = key.map((raw) => raw.toUpperCase());

      expect([key.revealCount, derived.revealCount]).toEqual([1, 1]);

      derived.reveal();
      expect([key.revealCount, derived.revealCount]).toEqual([2, 2]);

      key.reveal();
      expect([key.revealCount, derived.revealCount]).toEqual([3, 3]);
      expect([key.revealsRemaining, derived.revealsRemaining]).toEqual([1, 1]);
    });

    it('does not multiply a budget across the parts of a split', () => {
      const value = new SensitiveString('a-b-c', 'sensitive', 'parts', { maxReveals: 3 });
      const parts = value.split('-');

      expect(parts).toHaveLength(3);
      expect(value.revealCount).toBe(1);

      parts[0]?.reveal();
      parts[1]?.reveal();

      expect(value.isExhausted()).toBe(true);
      expect(() => parts[2]?.reveal()).toThrow(RevealLimitExceededError);
    });

    it('charges every source of a two-parent derivation', () => {
      const left = new SensitiveString('left', 'sensitive', 'left', { maxReveals: 2 });
      const right = new SensitiveString('right', 'sensitive', 'right', { maxReveals: 5 });
      const combined = left.concat(right);

      expect([left.revealCount, right.revealCount]).toEqual([1, 1]);

      combined.reveal();
      expect([left.revealCount, right.revealCount]).toEqual([2, 2]);

      // The tightest of the two binds, and reports itself.
      expect(combined.revealsRemaining).toBe(0);
      expect(combined.isExhausted()).toBe(true);
      expect(() => combined.reveal()).toThrow(RevealLimitExceededError);
      expect(right.reveal()).toBe('right');
    });

    it('reports the highest count and the smallest remainder among its sources', () => {
      const left = new SensitiveString('left', 'sensitive', 'left', { maxReveals: 10 });
      const right = new SensitiveString('right', 'sensitive', 'right', { maxReveals: 3 });
      const combined = left.concat(right);

      left.reveal();
      left.reveal();

      expect([left.revealCount, right.revealCount]).toEqual([3, 1]);
      expect(combined.revealCount).toBe(3);
      expect(combined.revealsRemaining).toBe(2);
    });

    it('charges a shared source once per read of the value that shares it', () => {
      const value = new SensitiveString('value', 'sensitive', 'shared', { maxReveals: 10 });
      // Both operands trace back to the same state object: two substrings and
      // the two reads concat makes of them are four charges.
      const combined = value.substring(0, 2).concat(value.substring(3));

      expect(value.revealCount).toBe(4);

      // One read of the result is one charge, not one per operand it was built
      // from, because the derivation records the shared state once.
      combined.reveal();
      expect(value.revealCount).toBe(5);
    });

    it('charges matchAll once, however lazily its results are consumed', () => {
      const value = new SensitiveString('a1b2c3', 'sensitive', 'digits', { maxReveals: 1 });

      // The generator closes over one read. A version that read the value per
      // iteration would charge per match, and the budget would depend on how
      // much of the result a caller happened to consume.
      const matches = value.matchAll(/\d/g);
      expect(value.revealCount).toBe(1);

      expect(Array.from(matches)).toHaveLength(3);
      expect(value.revealCount).toBe(1);
    });

    it('does not let reclassify launder away the budget', () => {
      const value = new SensitiveString('value', 'sensitive', 'canary', { maxReveals: 1 });
      const laundered = value.reclassify('credential', 'laundered');

      expect(laundered.isExhausted()).toBe(true);
      expect(() => laundered.reveal()).toThrow(RevealLimitExceededError);
    });

    it('shares a window with everything derived from it', () => {
      const key = new SensitiveString('api-key', 'credential', 'api_key', {
        revealWindow: MINUTE,
        maxRevealsPerWindow: 2,
      });

      const derived = key.substring(0);
      expect(() => derived.reveal()).not.toThrow();
      expect(() => derived.reveal()).toThrow(RevealRateLimitError);
      expect(() => key.reveal()).toThrow(RevealRateLimitError);
    });

    it('reports the longest wait among the windows that refused', () => {
      const fast = new SensitiveString('fast', 'sensitive', 'fast', {
        revealWindow: MINUTE,
        maxRevealsPerWindow: 1,
      });
      const slow = new SensitiveString('slow', 'sensitive', 'slow', {
        revealWindow: 10 * MINUTE,
        maxRevealsPerWindow: 1,
      });

      const combined = fast.concat(slow);

      try {
        combined.reveal();
        expect.unreachable('both windows are full');
      } catch (error) {
        expect((error as RevealRateLimitError).retryAfter).toBe(10 * MINUTE);
      }
    });
  });

  describe('the wire format', () => {
    it('charges the sender for serializing', () => {
      const key = new SensitiveString('api-key', 'credential', 'api_key', { maxReveals: 1 });

      expect(key.serialize().value).toBe('api-key');
      expect(key.isExhausted()).toBe(true);
      expect(() => key.serialize()).toThrow(RevealLimitExceededError);
    });

    it('starts the receiver on a fresh count, and gives it no limits', () => {
      const key = new SensitiveString('api-key', 'credential', 'api_key', { maxReveals: 1 });
      const wire = key.serialize();

      expect(wire).not.toHaveProperty('maxReveals');
      expect(wire).not.toHaveProperty('revealCount');

      const received = SensitiveString.deserialize<'credential'>(wire);

      expect(received.revealCount).toBe(0);
      expect(received.revealsRemaining).toBeUndefined();
      expect(received.isExhausted()).toBe(false);
      expect(received.reveal()).toBe('api-key');
      expect(received.reveal()).toBe('api-key');
    });

    it('ignores limits a payload claims for itself', () => {
      const received = SensitiveString.deserialize<'credential'>({
        __sensitive: true,
        klass: 'credential',
        value: 'api-key',
        label: 'api_key',
        maxReveals: 0,
        revealWindow: 1,
        maxRevealsPerWindow: 1,
      });

      expect(received.isExhausted()).toBe(false);
      expect(received.reveal()).toBe('api-key');
      expect(received.reveal()).toBe('api-key');
    });
  });

  describe('alongside expiration', () => {
    it('reports the deadline first, since expiry is checked before the budget', () => {
      const otp = new SensitiveString('123456', 'credential', 'otp', {
        ttl: MINUTE,
        maxReveals: 1,
      });

      advance(MINUTE);

      expect(() => otp.reveal()).toThrow(ExpiredSensitiveValueError);
      expect(otp.revealCount).toBe(0);
    });

    it('keeps refusing an exhausted value that has not expired', () => {
      const otp = new SensitiveString('123456', 'credential', 'otp', {
        ttl: 10 * MINUTE,
        maxReveals: 1,
      });

      otp.reveal();

      expect(otp.isExpired()).toBe(false);
      expect(() => otp.reveal()).toThrow(RevealLimitExceededError);
      expect(util.inspect(otp)).toContain('EXHAUSTED');
    });

    it('does not let a renewal restore a spent budget', () => {
      const session = new SensitiveString('token', 'sensitive', 'session', {
        ttl: MINUTE,
        maxReveals: 1,
      });

      session.reveal();
      session.renew(MINUTE);

      expect(session.renewalCount).toBe(1);
      expect(session.isExhausted()).toBe(true);
      expect(() => session.reveal()).toThrow(RevealLimitExceededError);
    });
  });

  describe('audit', () => {
    it('records the reveals that were charged, and only those', () => {
      const records: RevealDetails[] = [];
      const key = new SensitiveString('api-key', 'credential', 'api_key', { maxReveals: 2 });

      withRevealContext({ name: 'job', auditReveal: (_v, d) => records.push(d) }, () => {
        key.reveal();
        key.reveal();
        expect(() => key.reveal()).toThrow(RevealLimitExceededError);
      });

      expect(records).toHaveLength(2);
      expect(key.revealCount).toBe(2);
    });

    it('counts exactly what development mode records', () => {
      withDevMode({ enabled: true }, () => {
        const value = new SensitiveString('api-key', 'sensitive', 'api_key', { maxReveals: 3 });

        value.reveal();
        value.mask({ showLast: 2 });
        value.equals('api-key');
        String(value);

        expect(() =>
          value.reveal({
            name: 'refused',
            auditReveal: () => {
              throw new Error('audit sink unavailable');
            },
          })
        ).toThrow('audit sink unavailable');

        // Two features counting the same events from the same place in the
        // gate: the exposures that reached the caller, and nothing else.
        expect(value.revealCount).toBe(2);
        expect(value.__devInfo?.revealCount).toBe(2);
      });
    });

    it('leaves no record for a reveal a full window refused', () => {
      const records: RevealDetails[] = [];
      const key = new SensitiveString('api-key', 'credential', 'api_key', {
        revealWindow: MINUTE,
        maxRevealsPerWindow: 1,
      });

      withRevealContext({ name: 'job', auditReveal: (_v, d) => records.push(d) }, () => {
        key.reveal();
        expect(() => key.reveal()).toThrow(RevealRateLimitError);
      });

      expect(records).toHaveLength(1);
    });
  });
});
