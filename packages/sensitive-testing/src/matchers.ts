import { SensitiveString } from '@platform-sec/sensitive-string-core';
import type { SensitivityClass } from '@platform-sec/sensitive-string-core';
import { CONTAINS_CHECK_CONTEXT, MATCHER_CONTEXT, rawValueOf } from './canary.js';
import { describeType } from './describe-type.js';
import { findRawValue } from './leak-scan.js';

/**
 * What a matcher returns. Structurally the result type Vitest and Jest both
 * expect, declared here so this package depends on neither.
 */
export interface MatcherResult {
  pass: boolean;
  message: () => string;
}

/**
 * The matchers this package adds, as an interface a consumer can use to
 * augment their test framework's assertion types.
 *
 * @example
 * ```ts
 * // vitest.d.ts, when not importing the ready-made augmentation
 * import type { SensitiveMatchers } from '@platform-sec/sensitive-string-testing';
 *
 * declare module 'vitest' {
 *   interface Assertion<T = unknown> extends SensitiveMatchers<T> {}
 *   interface AsymmetricMatchersContaining extends SensitiveMatchers<unknown> {}
 * }
 * ```
 */
export interface SensitiveMatchers<R = unknown> {
  /** The value is a `SensitiveString`. */
  toBeSensitiveString(): R;
  /** The value is a `SensitiveString` of this sensitivity class. */
  toHaveSensitivityClass(expected: SensitivityClass): R;
  /** The value is a `SensitiveString` with this label. */
  toHaveLabel(expected: string | undefined): R;
  /** Revealing the value yields exactly this string. */
  toRevealAs(expected: string): R;
  /** The value has a deadline and that deadline has passed. */
  toBeExpired(): R;
  /** The received output contains the raw value of the given secret. */
  toContainSensitive(expected: SensitiveString<SensitivityClass>): R;
}

/**
 * Custom matchers for Vitest and Jest.
 *
 * Register them once, in a setup file:
 *
 * ```ts
 * import { expect } from 'vitest';
 * import { sensitiveMatchers } from '@platform-sec/sensitive-string-testing';
 *
 * expect.extend(sensitiveMatchers);
 * ```
 *
 * Both frameworks also expose a registered matcher asymmetrically, so
 * `expect.toBeSensitiveString()` works inside `toEqual` and
 * `expect.objectContaining` without any further registration.
 *
 * Every matcher is read only: none of them changes the value under assertion,
 * and none of them puts a raw value into a failure message. `toRevealAs` is the
 * one that could, and it reports the redacted rendering and the length instead,
 * because an assertion message ends up in a CI log.
 *
 * `toRevealAs` reveals through the instance, so an expired value or a policy
 * denial fails the assertion rather than passing on a remembered copy. The leak
 * matcher `toContainSensitive` reads the canary registry instead, since what it
 * needs is a string to search output for, not permission to use the value.
 */
export const sensitiveMatchers = {
  toBeSensitiveString(received: unknown): MatcherResult {
    const pass = received instanceof SensitiveString;

    return {
      pass,
      message: () =>
        pass
          ? 'Expected value not to be a SensitiveString, but it was.'
          : `Expected value to be a SensitiveString, but got ${describeType(received)}.`,
    };
  },

  toHaveSensitivityClass(received: unknown, expected: SensitivityClass): MatcherResult {
    if (!(received instanceof SensitiveString)) {
      return notASensitiveString(received);
    }

    const actual: SensitivityClass = received.klass;

    return {
      pass: actual === expected,
      message: () =>
        actual === expected
          ? `Expected sensitivity class not to be '${expected}'.`
          : `Expected sensitivity class '${expected}', but got '${actual}'.`,
    };
  },

  toHaveLabel(received: unknown, expected: string | undefined): MatcherResult {
    if (!(received instanceof SensitiveString)) {
      return notASensitiveString(received);
    }

    const actual = received.label;

    return {
      pass: actual === expected,
      message: () =>
        actual === expected
          ? `Expected label not to be ${quote(expected)}.`
          : `Expected label ${quote(expected)}, but got ${quote(actual)}.`,
    };
  },

  toRevealAs(received: unknown, expected: string): MatcherResult {
    if (!(received instanceof SensitiveString)) {
      return notASensitiveString(received);
    }

    const secret = received;
    let actual: string;
    try {
      // Deliberately `reveal()`, not the canary registry the leak checks use.
      // This matcher asserts on what revealing the value yields, so it has to
      // go through the same gate the code under test would: a value whose
      // deadline has passed, or whose policy denies the context, does not
      // reveal, and reading a remembered copy would report that it does.
      actual = secret.reveal({ name: MATCHER_CONTEXT });
    } catch (error) {
      // An expired value, or one a policy refuses to reveal, is not equal to
      // anything. Reporting it as a failed assertion keeps `.not` usable, which
      // a thrown error would not.
      return {
        pass: false,
        message: () => `Expected the value to reveal, but the reveal failed: ${reason(error)}.`,
      };
    }

    const pass = actual === expected;

    return {
      pass,
      message: () =>
        pass
          ? `Expected the revealed value not to equal ${quote(expected)}.`
          : [
              `Expected the revealed value to equal ${quote(expected)} `,
              `(${expected.length} characters), but got ${secret.toString()} `,
              `(${actual.length} characters). The actual value is withheld so a `,
              'failing assertion cannot print a secret into a log.',
            ].join(''),
    };
  },

  toBeExpired(received: unknown): MatcherResult {
    if (!(received instanceof SensitiveString)) {
      return notASensitiveString(received);
    }

    const secret = received;
    const pass = secret.isExpired();

    return {
      pass,
      message: () => {
        if (pass) {
          return 'Expected the value not to be expired, but its deadline has passed.';
        }

        const remaining = secret.ttlRemaining();

        return remaining === undefined
          ? 'Expected the value to be expired, but it has no deadline.'
          : `Expected the value to be expired, but it has ${remaining}ms left.`;
      },
    };
  },

  toContainSensitive(
    received: unknown,
    expected: SensitiveString<SensitivityClass>
  ): MatcherResult {
    const raw = rawValueOf(expected, CONTAINS_CHECK_CONTEXT);
    const location = findRawValue(received, raw);

    return {
      pass: location !== undefined,
      message: () =>
        location === undefined
          ? 'Expected the output to contain the raw sensitive value, but it does not.'
          : [
              'Expected the output not to contain the raw sensitive value, but found it at ',
              `${location.path === '' ? '(the target itself)' : location.path}: `,
              location.context,
            ].join(''),
    };
  },
};

/**
 * Register the matchers with a test framework's `expect`.
 *
 * Taking `expect` as an argument rather than importing it keeps this package
 * free of a dependency on either framework, which is what lets the same build
 * serve Vitest and Jest.
 *
 * @example
 * ```ts
 * // vitest.setup.ts
 * import { expect } from 'vitest';
 * import { setupSensitiveMatchers } from '@platform-sec/sensitive-string-testing';
 *
 * setupSensitiveMatchers(expect);
 * ```
 */
export function setupSensitiveMatchers(expect: {
  extend(matchers: typeof sensitiveMatchers): unknown;
}): void {
  expect.extend(sensitiveMatchers);
}

function notASensitiveString(received: unknown): MatcherResult {
  return {
    pass: false,
    message: () => `Expected a SensitiveString, but got ${describeType(received)}.`,
  };
}

function quote(value: string | undefined): string {
  return value === undefined ? '(none)' : `'${value}'`;
}

function reason(error: unknown): string {
  return error instanceof Error ? `${error.name}: ${error.message}` : String(error);
}
