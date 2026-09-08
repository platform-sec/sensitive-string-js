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
 * - An explicit handoff across worker threads and child processes
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
  HashAlgorithm,
  HashEncoding,
  HashOptions,
  HashAuditDetails,
  HmacOptions,
  HmacAuditDetails,
  RenewalOptions,
  RenewAuditDetails,
  ClearAuditDetails,
  AuditContext,
  RevealAccess,
  RevealAuditDetails,
  RevealContext,
  RevealDetails,
  RevocationRegistry,
  RevocationScope,
  EnvironmentInfo,
  EnvironmentRestrictions,
  SerializedEnvironmentRestrictions,
  RevokeAuditDetails,
  WorkerHandoffAuditDetails,
  ISensitiveString,
} from './types.js';

export { SENSITIVITY_PRECEDENCE } from './types.js';

// Main class
export { SensitiveString } from './sensitive-string.js';

// The base every refusal extends, so a caller can catch any of them at once
export { SensitiveStringError } from './errors.js';

// Expiration
export { ExpiredSensitiveValueError, RenewalNotAllowedError } from './ttl.js';
export { RevealDuringRedactionError } from './redaction-scope.js';

// BSON refusal.  on the class throws this; BSON honours toBSON() and
// ignores toJSON(), so without it a Mongo write silently persists the husk.
export { SensitiveBsonError } from './bson.js';
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

// Environment and region restrictions. The environment is process-global
// configuration under rule R6: it protects against a value being deployed
// somewhere it was not meant to run, not against a caller who wants it.
export {
  setEnvironmentInfo,
  getEnvironmentInfo,
  lockEnvironmentInfo,
  isEnvironmentLocked,
  resetEnvironmentInfo,
  EnvironmentRestrictedError,
  EnvironmentLockedError,
  UnserializableRestrictionError,
} from './environment.js';
export type { RestrictionKind } from './environment.js';

// Worker thread and child process handoff
export {
  toWorkerPayload,
  fromWorkerPayload,
  withWorkerPayload,
  MalformedWorkerPayloadError,
  ConsumedWorkerPayloadError,
  MissingWorkerValueError,
  UnregisteredClassError,
  UnauditedWorkerError,
  UnportableDataError,
  UnshareableConstraintError,
} from './worker.js';
export type {
  WorkerTransport,
  SensitiveValues,
  AnySensitiveValues,
  PortableRevealContext,
  WorkerPayloadOptions,
  WorkerPayloadValues,
  WorkerPayload,
  FromWorkerPayloadOptions,
  ReceivedWorkerPayload,
} from './worker.js';

// The reference wire format. Minting and resolving live in
// `@platform-sec/sensitive-string-secrets`, which is the layer that knows the
// store, the version and the credentials; the format lives here because the
// walks that meet one on the way to a log line do.
export {
  REFERENCE_VERSION,
  carriesReferenceMarker,
  isSensitiveValueReference,
  referenceFormatVersion,
} from './reference.js';
export type { SensitiveValueReference } from './reference.js';

// Memory hygiene. `clear()` drops the library's reference to the plaintext and
// nothing else: JavaScript cannot zero a string, and whether the library held
// the last reference is a property of the calling code. The two switches are
// process-global under rule R6, both off by default, and both read at
// construction.
export {
  clearAllSensitiveValues,
  setMemoryHygiene,
  getMemoryHygiene,
  resetMemoryHygiene,
  ClearedSensitiveValueError,
} from './hygiene.js';
export type { MemoryHygieneConfig } from './hygiene.js';

// Sealing: holding the value as AES-256-GCM ciphertext in a Buffer rather than
// as a string. Not encryption at rest, and encryption is not even what keeps a
// sealed value out of a heap snapshot, which a plain Buffer does on its own.
// What the key adds is that destroying it makes every sealed value in the
// process unreadable at once, and that a byte-oriented store lets `clear()` and
// `equals()` leave nothing behind. Off by default, per value or per process,
// and `sealed` is documented with the cost it carries.
export {
  setSealing,
  getSealing,
  resetSealing,
  destroySealingKey,
  SealingUnavailableError,
  SealingKeyDestroyedError,
  SealedValueIntegrityError,
} from './sealing.js';
export type { SealingConfig } from './sealing.js';

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

// Deterministic redaction, the first caller of that derivation inside core. It
// changes what redacted output means, so it is opt-in through a registered
// policy and never a default.
export {
  createDeterministicRedactor,
  deterministicRedaction,
  DeterministicRedactionNotAllowedError,
} from './deterministic.js';
export type { DeterministicRedactorOptions } from './deterministic.js';

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
  policyRegistryVersion,
} from './policy.js';
export type { RegisterPolicyOptions } from './policy.js';

// Recognizing this library's own redacted output, for the guards that refuse to
// hand a redaction onward: a write that would persist one, a request body that
// would transmit one, a column read that hands one back as if it were a value.
export {
  containsRedactionMarker,
  redactionMatchers,
  resetRedactionMarkerCache,
  MARKER_PREFIX,
} from './redaction-marker.js';

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
