import { randomBytes } from 'node:crypto';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import type { SensitivityClass, SensitiveStringOptions } from '@platform-sec/sensitive-string-core';
import { rememberCanary } from './canary.js';

/**
 * Options for `createTestSecret`.
 *
 * Every option of `SensitiveStringOptions` is accepted and passed through, so a
 * feature that adds one to the core options object is usable here without a
 * change to this package.
 */
export interface TestSecretOptions extends SensitiveStringOptions {
  /** Leading marker of the generated value. Defaults to `__CANARY_`. */
  prefix?: string;
  /** Trailing marker of the generated value. Defaults to `__`. */
  suffix?: string;
  /**
   * Use this value instead of generating one.
   *
   * Useful when a test asserts on an exact value or needs a value of a specific
   * shape, such as an address for the `email` mask strategy. It is remembered
   * in the canary registry like a generated value, so it should be a fixture
   * rather than a real secret.
   */
  value?: string;
}

/**
 * Counter component of the generated value.
 *
 * The timestamp alone is not enough: two secrets created in the same
 * millisecond would collide, and under fake timers the clock does not move at
 * all between them.
 */
let counter = 0;

/**
 * Create a `SensitiveString` whose value is a unique, conspicuous canary.
 *
 * The value is built to be searchable, so it stands out in a diff, a log
 * capture, or a snapshot, and unique, so a leak found in one test cannot be
 * confused with a value another test created. Nothing else about it is
 * meaningful: it is not a realistic API key and is not meant to look like one.
 *
 * The raw value is recorded in this package's canary registry, so the leak and
 * redaction assertions can search for it without revealing the instance.
 *
 * @param klass - Sensitivity classification. Defaults to `sensitive`.
 * @param label - Optional label, carried onto the instance.
 * @param options - Canary shape, plus any `SensitiveStringOptions`.
 *
 * @example
 * ```ts
 * const apiKey = createTestSecret('credential', 'api_key');
 * const otp = createTestSecret('credential', 'otp', { ttl: 30_000 });
 * const email = createTestSecret('sensitive', 'email', { value: 'jane@example.com' });
 * ```
 */
export function createTestSecret<C extends SensitivityClass = 'sensitive'>(
  klass?: C,
  label?: string,
  options: TestSecretOptions = {}
): SensitiveString<C> {
  const { prefix = '__CANARY_', suffix = '__', value, ...sensitiveStringOptions } = options;
  const raw = value ?? generateCanary(prefix, suffix);
  const secret = new SensitiveString(
    raw,
    (klass ?? 'sensitive') as C,
    label,
    sensitiveStringOptions
  );

  rememberCanary(secret, raw);

  return secret;
}

/**
 * Create a test secret whose deadline has already passed.
 *
 * `ttl: 0` is the deadline at construction, so the value is expired before the
 * test does anything with it and no clock has to be advanced or faked.
 *
 * @example
 * ```ts
 * expect(() => createExpiredSecret('credential', 'otp').reveal()).toThrow(
 *   ExpiredSensitiveValueError
 * );
 * ```
 */
export function createExpiredSecret<C extends SensitivityClass = 'sensitive'>(
  klass?: C,
  label?: string,
  options: Omit<TestSecretOptions, 'ttl' | 'expiresAt'> = {}
): SensitiveString<C> {
  return createTestSecret(klass, label, { ...options, ttl: 0 });
}

/**
 * Create a test secret that expires after `ttlMs`.
 *
 * A thin wrapper over `createTestSecret(klass, label, { ttl })` that reads as
 * what the test is setting up. Pair it with fake timers rather than a real
 * wait: the deadline is checked against the clock, not against a timer.
 *
 * @example
 * ```ts
 * vi.useFakeTimers();
 * const session = createExpiringSecret('credential', 'session', 60_000);
 * vi.advanceTimersByTime(60_001);
 * expect(session.isExpired()).toBe(true);
 * ```
 */
export function createExpiringSecret<C extends SensitivityClass = 'sensitive'>(
  klass: C | undefined,
  label: string | undefined,
  ttlMs: number,
  options: Omit<TestSecretOptions, 'ttl' | 'expiresAt'> = {}
): SensitiveString<C> {
  return createTestSecret(klass, label, { ...options, ttl: ttlMs });
}

/**
 * A value no application would produce, unique across a process.
 *
 * Randomness comes from `node:crypto` rather than `Math.random`, which test
 * suites stub often enough that a stub would silently turn every canary in a
 * file into the same string.
 */
function generateCanary(prefix: string, suffix: string): string {
  counter += 1;

  return `${prefix}${Date.now()}_${counter}_${randomBytes(6).toString('hex')}${suffix}`;
}
