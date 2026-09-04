/**
 * The raw-value gate refuses a policy hook that answers with anything.
 *
 * `checkRevealAllowed` denies by throwing. TypeScript accepts an `async`
 * function where a `void`-returning one is expected, and an `async` hook that
 * throws after its first `await` throws into a Promise nobody reads, after the
 * gate has already handed the raw value back. That is an authorization hook
 * failing open, silently, on exactly the reads it was written to refuse. The
 * declared return type is `undefined`, which rejects the `async` form at
 * compile time, and the gate applies the same rule at runtime.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  SensitiveString,
  registerPolicy,
  resetPolicies,
  withRevealContext,
  type SensitivityClass,
  type SensitivityPolicy,
} from '../index.js';

const CANARY = 'HOOK_RETURN_CANARY_4f2a9c';

/** A policy whose hook answers with `returned` instead of throwing or returning nothing. */
function registerHookReturning(klass: SensitivityClass, returned: unknown): void {
  registerPolicy(
    {
      name: klass,
      redact: () => `[REDACTED:${klass}]`,
      requireConstantTimeEquals: klass === 'credential',
      allowMask: true,
      // The type refuses this shape. The cast is the test reaching past it, as
      // JavaScript or a looser declaration would.
      checkRevealAllowed: (() => returned) as unknown as NonNullable<
        SensitivityPolicy['checkRevealAllowed']
      >,
    },
    { overwrite: true }
  );
}

/** A rejection that is already handled, so the runner does not report it as unhandled. */
function handledRejection(message: string): Promise<never> {
  const rejection = Promise.reject(new Error(message));
  rejection.catch(() => undefined);
  return rejection;
}

/** Every operation the hook gates. */
const GATED: Array<[string, (value: SensitiveString<'credential'>) => unknown]> = [
  ['reveal()', (value) => value.reveal()],
  ['equals()', (value) => value.equals(CANARY)],
  ['mask()', (value) => value.mask({ showLast: 2 })],
  ['serialize()', (value) => value.serialize()],
  ['substring()', (value) => value.substring(0, 2)],
  ['concat()', (value) => value.concat('x')],
];

describe('a checkRevealAllowed hook that answers instead of throwing', () => {
  beforeEach(() => {
    resetPolicies();
  });

  describe('an async hook', () => {
    it.each(GATED)('%s refuses a hook that returns a Promise', (_name, operation) => {
      registerHookReturning('credential', Promise.resolve(undefined));
      const value = new SensitiveString(CANARY, 'credential');

      expect(() => operation(value)).toThrow(TypeError);
      expect(() => operation(value)).toThrow(/must be synchronous/);
    });

    it('cannot fail open by denying after an await', () => {
      registerHookReturning('credential', handledRejection('[test] denied after await'));
      const value = new SensitiveString(CANARY, 'credential');

      let revealed: unknown;
      let refusal: unknown;

      try {
        revealed = value.reveal();
      } catch (error) {
        refusal = error;
      }

      expect(revealed).toBeUndefined();
      expect(refusal).toBeInstanceOf(TypeError);
      expect(String(refusal)).not.toContain(CANARY);
    });

    it('is refused before the audit hook, so a refused read is not recorded as a reveal', () => {
      registerHookReturning('credential', Promise.resolve(undefined));
      const auditReveal = vi.fn();
      const value = new SensitiveString(CANARY, 'credential');

      withRevealContext({ name: 'test', auditReveal }, () => {
        expect(() => value.reveal()).toThrow(TypeError);
      });

      expect(auditReveal).not.toHaveBeenCalled();
    });

    it('refuses renew() the same way, and the deadline does not move', () => {
      registerHookReturning('sensitive', Promise.resolve(undefined));
      const value = new SensitiveString(CANARY, 'sensitive', 'session', { ttl: 60_000 });
      const before = value.expiresAt;

      expect(() => value.renew(60_000)).toThrow(/must be synchronous/);
      expect(value.expiresAt).toEqual(before);
      expect(value.renewalCount).toBe(0);
    });

    it('is refused at compile time, which is what the return type is for', () => {
      const policy: SensitivityPolicy = {
        name: 'credential',
        redact: () => '[REDACTED:credential]',
        // @ts-expect-error an async hook returns a Promise, and the hook must return undefined
        checkRevealAllowed: async () => {
          await Promise.resolve();
          throw new Error('[test] denied');
        },
      };

      expect(policy.name).toBe('credential');
    });
  });

  describe('a hook that returns a value', () => {
    it.each([
      ['false', false],
      ['true', true],
      ['null', null],
      ['a string', 'allowed'],
      ['an object', { allowed: true }],
    ])('is refused when it returns %s', (_name, returned) => {
      registerHookReturning('credential', returned);
      const value = new SensitiveString(CANARY, 'credential');

      expect(() => value.reveal()).toThrow(TypeError);
      expect(() => value.reveal()).toThrow(/must return undefined/);
    });

    it('names the class in the refusal and never the value', () => {
      registerHookReturning('credential', false);
      const value = new SensitiveString(CANARY, 'credential');

      expect(() => value.reveal()).toThrow(/sensitivity class 'credential'/);
      expect(() => value.reveal()).not.toThrow(CANARY);
    });
  });

  describe('a hook that answers the one way the gate understands', () => {
    it('allows the read when it returns nothing', () => {
      registerHookReturning('credential', undefined);

      expect(new SensitiveString(CANARY, 'credential').reveal()).toBe(CANARY);
    });

    it('denies the read with its own error when it throws', () => {
      registerPolicy(
        {
          name: 'credential',
          redact: () => '[REDACTED:credential]',
          checkRevealAllowed: () => {
            throw new Error('[test] context required');
          },
        },
        { overwrite: true }
      );

      expect(() => new SensitiveString(CANARY, 'credential').reveal()).toThrow(
        '[test] context required'
      );
    });
  });
});
