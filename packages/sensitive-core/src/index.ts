/**
 * @anthropic-security/sensitive-core
 *
 * Enterprise-grade library for handling sensitive string data in Node.js.
 *
 * Features:
 * - Automatic redaction in logging, serialization, and display
 * - Type-safe sensitivity classification
 * - Explicit reveal with audit hooks
 * - Constant-time comparison for credentials
 * - AsyncLocalStorage context propagation
 *
 * @example
 * ```ts
 * import { SensitiveString, safeLog, withRevealContext } from '@anthropic-security/sensitive-core';
 *
 * // Create a sensitive value
 * const apiKey = new SensitiveString(process.env.API_KEY!, 'credential', 'api_key');
 *
 * // Safe for logging
 * console.log('Authenticating with', apiKey);
 * // Output: Authenticating with SensitiveString<credential:api_key> { [REDACTED:credential] }
 *
 * // Explicit reveal with audit
 * await withRevealContext({ name: 'api-call', reason: 'authenticate' }, async () => {
 *   const raw = apiKey.reveal();
 *   await callApi(raw);
 * });
 * ```
 *
 * @packageDocumentation
 */

// Core types
export type {
  SensitivityClass,
  SensitivityPolicy,
  SensitivityAdvisory,
  SerializedSensitiveString,
  RevealContext,
  ISensitiveString,
} from './types.js';

export { SENSITIVITY_PRECEDENCE } from './types.js';

// Main class
export { SensitiveString } from './sensitive-string.js';

// Policy management
export {
  registerPolicy,
  getPolicy,
  getDefaultPolicy,
  hasPolicy,
  getRegisteredClasses,
  resetPolicies,
  defaultCombineClasses,
} from './policy.js';
export type { RegisterPolicyOptions } from './policy.js';

// Context management
export {
  withRevealContext,
  getCurrentRevealContext,
  createChildContext,
  withAuditedReveals,
} from './context.js';

// Redaction helpers
export {
  redactInStructure,
  safeLog,
  safeStringify,
  createSensitiveSerializer,
  containsSensitive,
} from './redact.js';
export type { SafeStringifyOptions } from './redact.js';

// Path-based wrapping utilities
export {
  wrapSensitiveByPath,
  unwrapSensitiveByPath,
  validateSensitiveFieldConfig,
  checkSensitiveFieldsWrapped,
} from './wrap.js';
export type { SensitiveFieldConfig, WrappedResult } from './wrap.js';
