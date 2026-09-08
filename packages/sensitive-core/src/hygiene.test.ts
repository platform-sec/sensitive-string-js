/**
 * Memory hygiene: `clear()`, the bulk clear, and the two process-global
 * switches.
 *
 * Behaviour only. Whether the plaintext actually leaves the heap is measured
 * in `__tests__/hygiene-retention.timing.test.ts`, which searches a heap
 * snapshot and runs under `pnpm test:timing` for the same reason the timing
 * analysis does: GC scheduling is not a release gate.
 */
import * as util from 'node:util';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  ClearedSensitiveValueError,
  clearAllSensitiveValues,
  ExpiredSensitiveValueError,
  getMemoryHygiene,
  registerPolicy,
  RenewalNotAllowedError,
  resetMemoryHygiene,
  resetPolicies,
  SensitiveString,
  setMemoryHygiene,
  st,
  withRevealContext,
} from './index.js';
import type { RevealDetails } from './index.js';
import { trackedRefCount } from './hygiene.js';

const VALUE = 'a-value-worth-destroying';
const MINUTE = 60_000;
const START = new Date('2026-01-01T00:00:00.000Z');

function advance(ms: number): void {
  vi.setSystemTime(new Date(Date.now() + ms));
}

describe('memory hygiene', () => {
  beforeEach(() => {
    resetPolicies();
    resetMemoryHygiene();
  });

  afterEach(() => {
    resetMemoryHygiene();
    resetPolicies();
    vi.useRealTimers();
  });

  describe('clear()', () => {
    it('makes every exposing read throw ClearedSensitiveValueError', () => {
      const token = new SensitiveString(VALUE, 'credential', 'db_password');

      token.clear();

      expect(() => token.reveal()).toThrow(ClearedSensitiveValueError);
      expect(() => token.equals(VALUE)).toThrow(ClearedSensitiveValueError);
      expect(() => token.serialize()).toThrow(ClearedSensitiveValueError);
      expect(() => token.hash('sha256')).toThrow(ClearedSensitiveValueError);

      // A credential does not permit masking at all, so that refusal comes
      // from the policy before the gate is reached. The masked class shows the
      // gate answering.
      const pii = new SensitiveString(VALUE, 'sensitive', 'email');
      pii.clear();
      expect(() => pii.mask({ showLast: 2 })).toThrow(ClearedSensitiveValueError);
    });

    it('reports the clear through isCleared and clearedAt', () => {
      vi.useFakeTimers();
      vi.setSystemTime(START);

      const token = new SensitiveString(VALUE, 'credential', 'token');

      expect(token.isCleared).toBe(false);
      expect(token.clearedAt).toBeUndefined();

      token.clear();

      expect(token.isCleared).toBe(true);
      expect(token.clearedAt).toEqual(START);
    });

    it('is idempotent per instance and does not move clearedAt', () => {
      vi.useFakeTimers();
      vi.setSystemTime(START);

      const token = new SensitiveString(VALUE, 'credential', 'token');
      token.clear();
      advance(MINUTE);
      token.clear();

      expect(token.clearedAt).toEqual(START);
    });

    it('keeps toString(), toJSON() and inspect() working', () => {
      const token = new SensitiveString(VALUE, 'credential', 'db_password');
      const before = token.toString();

      token.clear();

      expect(token.toString()).toBe(before);
      expect(token.toJSON()).toBe(before);
      expect(JSON.stringify({ token })).toBe(JSON.stringify({ token: before }));
      expect(() => String(token)).not.toThrow();
    });

    it('renders the CLEARED marker beside the redaction, and beside EXPIRED', () => {
      vi.useFakeTimers();
      vi.setSystemTime(START);

      const token = new SensitiveString(VALUE, 'credential', 'db_password');
      token.clear();

      expect(util.inspect(token)).toBe(
        'SensitiveString<credential:db_password> { [REDACTED:credential] CLEARED }'
      );

      const otp = new SensitiveString(VALUE, 'credential', 'otp', { ttl: MINUTE });
      otp.clear();
      advance(2 * MINUTE);

      expect(util.inspect(otp)).toBe(
        'SensitiveString<credential:otp> { [REDACTED:credential] CLEARED EXPIRED }'
      );
    });

    it('reports how long ago the value was destroyed, and never the value', () => {
      vi.useFakeTimers();
      vi.setSystemTime(START);

      const token = new SensitiveString(VALUE, 'credential', 'db_password');
      token.clear();
      advance(MINUTE);

      try {
        token.reveal();
        expect.unreachable('a cleared value must refuse');
      } catch (error) {
        const thrown = error as ClearedSensitiveValueError;

        expect(thrown.clearedAt).toEqual(START);
        expect(thrown.clearedFor).toBe(MINUTE);
        expect(thrown.label).toBe('db_password');
        expect(thrown.code).toBe('cleared-value');
        expect(thrown.message).not.toContain(VALUE);
      }
    });

    it('makes length and isEmpty() throw rather than reporting 0 and true', () => {
      const token = new SensitiveString(VALUE, 'credential', 'token');

      token.clear();

      expect(() => token.length).toThrow(ClearedSensitiveValueError);
      expect(() => token.isEmpty()).toThrow(ClearedSensitiveValueError);
    });

    it('emits exactly one audit record, with operation "clear"', () => {
      const records: RevealDetails[] = [];
      const token = new SensitiveString(VALUE, 'credential', 'token');

      token.clear({ name: 'shutdown', auditReveal: (_v, details) => records.push(details) });
      token.clear({ name: 'shutdown', auditReveal: (_v, details) => records.push(details) });

      expect(records).toEqual([{ operation: 'clear', propagated: true }]);
    });

    it('audits through the ambient context when none is passed', () => {
      const records: RevealDetails[] = [];
      const token = new SensitiveString(VALUE, 'credential', 'token');

      withRevealContext(
        { name: 'shutdown', auditReveal: (_v, details) => records.push(details) },
        () => {
          token.clear();
        }
      );

      expect(records).toEqual([{ operation: 'clear', propagated: true }]);
    });

    it('reports propagated true from an owner and false from a derivative', () => {
      const records: RevealDetails[] = [];
      const audit = {
        name: 'shutdown',
        auditReveal: (_v: unknown, d: RevealDetails) => void records.push(d),
      };

      const owner = new SensitiveString(VALUE, 'sensitive', 'owner');
      const derivative = owner.substring(0, 8);

      derivative.clear(audit);
      owner.clear(audit);

      expect(records).toEqual([
        { operation: 'clear', propagated: false },
        { operation: 'clear', propagated: true },
      ]);
    });

    it('is not refused by a policy: no hook is consulted', () => {
      // The hook's contract is to throw or return undefined; `refuseHookReturn`
      // refuses anything else. What matters here is that it is never called.
      const checkRevealAllowed = vi.fn((): undefined => undefined);
      registerPolicy(
        {
          name: 'sensitive',
          redact: () => '[REDACTED:sensitive]',
          requireConstantTimeEquals: false,
          checkRevealAllowed,
        },
        { overwrite: true }
      );

      const token = new SensitiveString(VALUE, 'sensitive', 'token');
      token.clear();

      expect(token.isCleared).toBe(true);
      expect(checkRevealAllowed).not.toHaveBeenCalled();
    });

    it('succeeds on an expired value, which reads nothing', () => {
      vi.useFakeTimers();
      vi.setSystemTime(START);

      const otp = new SensitiveString(VALUE, 'sensitive', 'otp', { ttl: MINUTE });
      advance(2 * MINUTE);

      expect(() => otp.reveal()).toThrow(ExpiredSensitiveValueError);
      expect(() => otp.clear()).not.toThrow();
      expect(() => otp.reveal()).toThrow(ClearedSensitiveValueError);
    });

    it('succeeds on a revoked value', () => {
      const token = new SensitiveString(VALUE, 'sensitive', 'token');
      token.revoke('rotated');

      expect(() => token.clear()).not.toThrow();
      expect(token.isCleared).toBe(true);
    });
  });

  describe('renew() on a cleared value', () => {
    it('throws rather than moving the deadline', () => {
      vi.useFakeTimers();
      vi.setSystemTime(START);

      const session = new SensitiveString(VALUE, 'sensitive', 'session', { ttl: MINUTE });
      const deadline = session.expiresAt;

      session.clear();

      expect(() => session.renew(MINUTE)).toThrow(ClearedSensitiveValueError);
      expect(session.expiresAt).toEqual(deadline);
    });

    it('reports the clear ahead of the derived refusal', () => {
      const owner = new SensitiveString(VALUE, 'sensitive', 'owner', { ttl: MINUTE });
      const derivative = owner.substring(0, 8);

      expect(() => derivative.renew(MINUTE)).toThrow(RenewalNotAllowedError);

      owner.clear();

      expect(() => derivative.renew(MINUTE)).toThrow(ClearedSensitiveValueError);
    });
  });

  describe('derived values', () => {
    it('refuses every kind of single-parent derivative when the origin is cleared', () => {
      const owner = new SensitiveString('SOME_VALUE_HERE', 'sensitive', 'owner');
      const derivatives = [
        owner.substring(0, 4),
        owner.slice(1),
        owner.trim(),
        owner.toLowerCase(),
        owner.map((raw) => raw),
        owner.replace('SOME', 'x'),
        owner.charAt(0),
        owner.reclassify('credential'),
      ];

      owner.clear();

      for (const derivative of derivatives) {
        expect(derivative.isCleared).toBe(true);
        expect(() => derivative.reveal()).toThrow(ClearedSensitiveValueError);
      }
    });

    it('refuses every split and match sibling at once', () => {
      const owner = new SensitiveString('one_two_three', 'sensitive', 'owner');
      const parts = owner.split('_');
      const matches = owner.match(/t\w+/g) ?? [];

      expect(parts).toHaveLength(3);
      expect(matches.length).toBeGreaterThan(0);

      owner.clear();

      for (const part of [...parts, ...matches]) {
        expect(() => part.reveal()).toThrow(ClearedSensitiveValueError);
      }
    });

    it('refuses a concat result when either operand is cleared', () => {
      const left = new SensitiveString('left-value', 'sensitive', 'left');
      const right = new SensitiveString('right-value', 'sensitive', 'right');

      const fromLeft = left.concat(right);
      const fromRight = left.concat(right);

      left.clear();
      expect(() => fromLeft.reveal()).toThrow(ClearedSensitiveValueError);

      right.clear();
      expect(() => fromRight.reveal()).toThrow(ClearedSensitiveValueError);
    });

    it('refuses a template result when any interpolated value is cleared', () => {
      const a = new SensitiveString('alpha-value', 'sensitive', 'a');
      const b = new SensitiveString('beta-value', 'sensitive', 'b');
      const combined = st`${a} and ${b}`;

      b.clear();

      expect(() => combined.reveal()).toThrow(ClearedSensitiveValueError);
    });

    it('does not refuse the parent, or a sibling, when a derivative is cleared', () => {
      const owner = new SensitiveString('one_two_three', 'sensitive', 'owner');
      const [first, second] = owner.split('_');

      first!.clear();

      expect(owner.isCleared).toBe(false);
      expect(owner.reveal()).toBe('one_two_three');
      expect(second!.isCleared).toBe(false);
      expect(second!.reveal()).toBe('two');
    });

    it('cannot derive from a cleared value at all: the derivation reads through the gate', () => {
      const owner = new SensitiveString(VALUE, 'sensitive', 'owner');
      owner.clear();

      expect(() => owner.substring(0, 4)).toThrow(ClearedSensitiveValueError);
      expect(() => owner.split('-')).toThrow(ClearedSensitiveValueError);
      expect(() => st`${owner}`).toThrow(ClearedSensitiveValueError);
    });

    it('renders a derivative whose origin was cleared rather than throwing', () => {
      const owner = new SensitiveString(VALUE, 'credential', 'owner');
      const derivative = owner.substring(0, 8);

      owner.clear();

      expect(() => derivative.toString()).not.toThrow();
      expect(derivative.toString()).toBe('[REDACTED:credential]');
      expect(util.inspect(derivative)).toContain('CLEARED');
    });

    it('is not a no-op to clear a derivative whose origin was already cleared', () => {
      vi.useFakeTimers();
      vi.setSystemTime(START);

      const records: RevealDetails[] = [];
      const owner = new SensitiveString(VALUE, 'sensitive', 'owner');
      const derivative = owner.substring(0, 8);

      owner.clear();
      advance(MINUTE);
      derivative.clear({ name: 'sweep', auditReveal: (_v, d) => records.push(d) });

      // The second call did work: it emitted its own record, and it dropped the
      // derivative's own copy of the plaintext, which is the pin on the origin.
      expect(records).toEqual([{ operation: 'clear', propagated: false }]);
      // And it reports the origin's earlier time, not its own.
      expect(derivative.clearedAt).toEqual(START);
    });
  });

  describe('setMemoryHygiene', () => {
    it('merges rather than replacing', () => {
      setMemoryHygiene({ freezeInstances: true });
      setMemoryHygiene({ trackInstances: true });

      expect(getMemoryHygiene()).toEqual({ freezeInstances: true, trackInstances: true });
    });

    it('returns a frozen copy that cannot reconfigure the process', () => {
      setMemoryHygiene({ trackInstances: true });
      const config = getMemoryHygiene();

      expect(Object.isFrozen(config)).toBe(true);
      expect(() => {
        (config as { trackInstances: boolean }).trackInstances = false;
      }).toThrow(TypeError);
      expect(getMemoryHygiene().trackInstances).toBe(true);
    });

    it('defaults both switches off', () => {
      expect(getMemoryHygiene()).toEqual({ freezeInstances: false, trackInstances: false });
    });

    it('rejects a non-object and a non-boolean field', () => {
      expect(() => setMemoryHygiene(null as unknown as Record<string, never>)).toThrow(TypeError);
      expect(() => setMemoryHygiene({ trackInstances: 'yes' as unknown as boolean })).toThrow(
        TypeError
      );
    });

    it('does not reach an instance built before it ran', () => {
      const before = new SensitiveString(VALUE, 'sensitive', 'before');

      setMemoryHygiene({ freezeInstances: true, trackInstances: true });

      expect(Object.isFrozen(before)).toBe(false);
      expect(clearAllSensitiveValues()).toBe(0);
      expect(before.isCleared).toBe(false);
    });
  });

  describe('freezeInstances', () => {
    it('freezes an owner and a derivative alike', () => {
      setMemoryHygiene({ freezeInstances: true });

      const owner = new SensitiveString(VALUE, 'sensitive', 'owner');

      expect(Object.isFrozen(owner)).toBe(true);
      expect(Object.isFrozen(owner.substring(0, 4))).toBe(true);
    });

    it("leaves the lifecycle alone: renew() still moves a frozen value's deadline", () => {
      vi.useFakeTimers();
      vi.setSystemTime(START);
      setMemoryHygiene({ freezeInstances: true });

      const session = new SensitiveString(VALUE, 'sensitive', 'session', { ttl: MINUTE });
      session.renew(MINUTE);

      // The deadline lives in a state object the instance points at, and
      // freezing an object does not freeze what it references.
      expect(session.expiresAt).toEqual(new Date(START.getTime() + 2 * MINUTE));
    });

    it('breaks nothing the class already does', () => {
      setMemoryHygiene({ freezeInstances: true });

      const token = new SensitiveString(VALUE, 'credential', 'token');

      expect(token.toString()).toBe('[REDACTED:credential]');
      expect(util.inspect(token)).toContain('[REDACTED:credential]');
      expect(token.reveal()).toBe(VALUE);
      expect(token.equals(VALUE)).toBe(true);
      expect(token.length).toBe(VALUE.length);
      expect(token.substring(0, 4).reveal()).toBe(VALUE.slice(0, 4));
      expect(token.serialize().value).toBe(VALUE);
      expect(token.hash('sha256').reveal()).toMatch(/^[0-9a-f]{64}$/);

      // Masking is refused by the credential policy rather than by the freeze,
      // so the masked class is the one that shows mask() unaffected.
      const pii = new SensitiveString(VALUE, 'sensitive', 'email');
      expect(pii.mask({ showLast: 2 })).toContain(VALUE.slice(-2));
    });
  });

  describe('clearAllSensitiveValues', () => {
    it('clears nothing when tracking is off', () => {
      const token = new SensitiveString(VALUE, 'sensitive', 'token');

      expect(clearAllSensitiveValues()).toBe(0);
      expect(token.isCleared).toBe(false);
    });

    it('clears every tracked instance and reports the count', () => {
      setMemoryHygiene({ trackInstances: true });

      const first = new SensitiveString(VALUE, 'sensitive', 'first');
      const second = new SensitiveString(VALUE, 'credential', 'second');

      expect(clearAllSensitiveValues()).toBe(2);
      expect(first.isCleared).toBe(true);
      expect(second.isCleared).toBe(true);
    });

    it('reaches derivatives, which is what it exists for', () => {
      setMemoryHygiene({ trackInstances: true });

      const owner = new SensitiveString('a-long-enough-value-to-slice', 'sensitive', 'owner');
      const derivative = owner.substring(0, 16);

      // Two instances, the derivative included: it is registered before the
      // derived early return in the constructor.
      expect(clearAllSensitiveValues()).toBe(2);

      // The derivative dropped its own copy, so its pin on the origin is gone.
      expect(derivative.isCleared).toBe(true);
      expect(owner.isCleared).toBe(true);
    });

    it('unregisters what it cleared, so a second sweep double-counts nothing', () => {
      setMemoryHygiene({ trackInstances: true });

      const token = new SensitiveString(VALUE, 'sensitive', 'token');

      expect(clearAllSensitiveValues()).toBe(1);
      expect(clearAllSensitiveValues()).toBe(0);
      expect(token.isCleared).toBe(true);
    });

    it('empties the tracked set of what it reached', () => {
      setMemoryHygiene({ trackInstances: true });

      const held = [
        new SensitiveString(VALUE, 'sensitive', 'a'),
        new SensitiveString(VALUE, 'sensitive', 'b'),
      ];

      expect(trackedRefCount()).toBe(2);
      expect(clearAllSensitiveValues()).toBe(2);
      expect(trackedRefCount()).toBe(0);
      expect(held.every((value) => value.isCleared)).toBe(true);
    });
  });

  describe('the process-global registry', () => {
    it('is reachable under the Symbol.for key a second copy of core would use', () => {
      setMemoryHygiene({ trackInstances: true });
      const token = new SensitiveString(VALUE, 'sensitive', 'token');

      const key = Symbol.for('@platform-sec/sensitive-string-core/memory-hygiene');
      const shared = (
        globalThis as unknown as Record<
          symbol,
          { config: { trackInstances: boolean }; tracked: Set<unknown> }
        >
      )[key];

      // A second physical installation calls getGlobalSingleton with this same
      // key and receives this same object, so one shutdown handler reaches the
      // values both copies built.
      expect(shared?.config.trackInstances).toBe(true);
      expect(shared?.tracked.size).toBe(1);
      expect(token.isCleared).toBe(false);
    });

    it('resetMemoryHygiene restores the defaults and empties the set', () => {
      setMemoryHygiene({ freezeInstances: true, trackInstances: true });
      const token = new SensitiveString(VALUE, 'sensitive', 'token');

      expect(trackedRefCount()).toBe(1);

      resetMemoryHygiene();

      expect(getMemoryHygiene()).toEqual({ freezeInstances: false, trackInstances: false });
      expect(trackedRefCount()).toBe(0);
      // Forgetting is not destroying.
      expect(token.isCleared).toBe(false);
    });
  });
});
