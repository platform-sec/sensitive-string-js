/**
 * @platform-sec/sensitive-string-core
 *
 * Enterprise-grade library for handling sensitive string data in Node.js.
 *
 * Features:
 * - Automatic redaction in logging, serialization, and display
 * - Type-safe sensitivity classification
 * - Explicit reveal with audit hooks
 * - Partial masking for support, debugging, and user confirmation
 * - Constant-time comparison for credentials
 * - AsyncLocalStorage context propagation
 *
 * @example
 * ```ts
 * import { SensitiveString, safeLog, withRevealContext } from '@platform-sec/sensitive-string-core';
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
  SensitiveStringOptions,
  SerializedSensitiveString,
  MaskOptions,
  MaskStrategy,
  MaskAuditDetails,
  RevealAuditDetails,
  RevealContext,
  RevealDetails,
  ISensitiveString,
} from './types.js';

export { SENSITIVITY_PRECEDENCE } from './types.js';

// Main class
export { SensitiveString } from './sensitive-string.js';

// Anchored patterns for common sensitive-value formats
export { patterns } from './patterns.js';

// Template literals
export { sensitiveTemplate, st } from './template.js';
export type { TemplateValue, SensitiveTemplateOptions, SensitiveTemplateTag } from './template.js';

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
export type { SensitiveFieldConfig, SensitiveFieldOptions, WrappedResult } from './wrap.js';
