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
  RenewalOptions,
  RenewAuditDetails,
  RevealAccess,
  RevealAuditDetails,
  RevealContext,
  RevealDetails,
  RevocationRegistry,
  RevocationScope,
  RevokeAuditDetails,
  ISensitiveString,
} from './types.js';

export { SENSITIVITY_PRECEDENCE } from './types.js';

// Main class
export { SensitiveString } from './sensitive-string.js';

// Expiration
export { ExpiredSensitiveValueError, RenewalNotAllowedError } from './ttl.js';
export { RevealDuringRedactionError } from './redaction-scope.js';
export type { RenewalRefusal } from './ttl.js';

// Reveal limits and rate limiting
export { RevealLimitExceededError, RevealRateLimitError } from './reveal-budget.js';

// Revocation
export {
  RevokedSensitiveValueError,
  RevocationList,
  revokeByLabel,
  revokeByPattern,
  pruneRevocations,
  revocationCount,
} from './revocation.js';
export type { RevocationRecord } from './revocation.js';

// Development mode
export { setDevMode, getDevModeConfig, withDevMode } from './dev-mode.js';
export type {
  DevModeConfig,
  DevInfo,
  RepeatedRevealOptions,
  RevealLogOptions,
} from './dev-mode.js';

// Anchored patterns for common sensitive-value formats
export { patterns } from './patterns.js';

// Keyed derivation, shared by deterministic redaction and by LLM entity
// handles. One implementation, because a truncated keyed HMAC over a
// low-entropy value has exactly one correct shape.
export {
  deriveKeyedToken,
  assertKeyedDerivationOptions,
  DEFAULT_DERIVED_TOKEN_LENGTH,
  MIN_DERIVED_TOKEN_LENGTH,
  MAX_DERIVED_TOKEN_LENGTH,
  MIN_DERIVATION_KEY_BYTES,
} from './derive.js';
export type { KeyedDerivationOptions } from './derive.js';

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

// The marker a redaction substitutes for an object it could not read at all.
// Exported because it appears in output, so a caller asserting on redacted
// values needs a name for it rather than a string literal.
export { UNREADABLE } from './probe.js';

// Redaction helpers
export {
  redactInStructure,
  safeLog,
  safeStringify,
  createSensitiveSerializer,
  containsSensitive,
  sensitiveClassesIn,
} from './redact.js';
export type { SafeStringifyOptions } from './redact.js';
export { redactCopy } from './redact-copy.js';

// Winston format
export { sensitiveFormat } from './winston.js';
export type { SensitiveFormatOptions, WinstonFormat, WinstonInfo } from './winston.js';

// Field classification, shared by the integrations that decide which keys of a
// decoded payload get wrapped
export { compileClassification, classifyField } from './classification.js';
export type {
  FieldClass,
  ClassificationRule,
  ClassificationSpec,
  CompiledClassification,
} from './classification.js';

// Path-based wrapping utilities
export {
  wrapSensitiveByPath,
  unwrapSensitiveByPath,
  validateSensitiveFieldConfig,
  checkSensitiveFieldsWrapped,
} from './wrap.js';
export type { SensitiveFieldConfig, SensitiveFieldOptions, WrappedResult } from './wrap.js';
