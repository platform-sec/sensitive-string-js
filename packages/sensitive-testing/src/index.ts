/**
 * @platform-sec/sensitive-string-testing
 *
 * Test utilities for code that handles `SensitiveString` values.
 *
 * - `createTestSecret` builds unique, conspicuous canary values.
 * - `expectNotLeaked` and `expectRedacted` assert the core security property.
 * - `sensitiveMatchers` adds matchers to Vitest or Jest.
 * - `mockRevealContext` and `createMockAuditLog` record what was accessed.
 *
 * The package depends on no test framework. The matchers are a plain object
 * passed to `expect.extend`, and anything that needs a spy takes a factory such
 * as `vi.fn` or `jest.fn` as an argument.
 *
 * @example
 * ```ts
 * import {
 *   createTestSecret,
 *   expectNotLeaked,
 *   sensitiveMatchers,
 * } from '@platform-sec/sensitive-string-testing';
 *
 * expect.extend(sensitiveMatchers);
 *
 * it('does not leak the key into the response', async () => {
 *   const apiKey = createTestSecret('credential', 'api_key');
 *
 *   const response = await handler(apiKey);
 *
 *   expect(apiKey).toHaveSensitivityClass('credential');
 *   expectNotLeaked(apiKey, response);
 * });
 * ```
 *
 * @packageDocumentation
 */

// Test secret creation
export {
  createTestSecret,
  createExpiredSecret,
  createExpiringSecret,
} from './create-test-secret.js';
export type { TestSecretOptions } from './create-test-secret.js';

// Assertions
export { expectNotLeaked, expectRedacted, LeakageDetectedError } from './assertions.js';
export type { RedactionOptions } from './assertions.js';

// Matchers
export { sensitiveMatchers, setupSensitiveMatchers } from './matchers.js';
export type { SensitiveMatchers, MatcherResult } from './matchers.js';

// Mocks
export { mockRevealContext, createMockAuditLog } from './mocks.js';
export type {
  AuditCall,
  AuditEntry,
  AuditRevealFn,
  MockAuditLog,
  MockFunctionFactory,
  MockRevealContext,
  MockRevealContextOptions,
} from './mocks.js';

// Leak scanning, for a check this package does not already provide
export { collectFragments, findRawValue, findRawValueIn, joinFragments } from './leak-scan.js';
export type { Fragment, LeakLocation } from './leak-scan.js';

// Reveal context names, so a strict policy can allow them
export {
  UnreadableSecretError,
  TESTING_CONTEXT_NAMES,
  LEAK_CHECK_CONTEXT,
  REDACTION_CHECK_CONTEXT,
  MATCHER_CONTEXT,
  CONTAINS_CHECK_CONTEXT,
} from './canary.js';
