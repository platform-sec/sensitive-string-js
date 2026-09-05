/**
 * @platform-sec/sensitive-string-zod
 *
 * Zod integration for SensitiveString.
 * Parse and validate input directly into sensitive types at boundary layers.
 *
 * @example
 * ```ts
 * import { z } from 'zod';
 * import { zSensitive, zCredential } from '@platform-sec/sensitive-string-zod';
 *
 * const WebhookSchema = z.object({
 *   token: zCredential('session_token'),
 *   email: zSensitive('email'),
 *   note: z.string().max(1024).optional(),
 * });
 *
 * // Type inference works correctly
 * type Webhook = z.infer<typeof WebhookSchema>;
 * // Webhook['token'] is SensitiveString<'credential'>
 * // Webhook['email'] is SensitiveString<'sensitive'>
 * ```
 *
 * @example Collections, normalization, and refinements
 * ```ts
 * const SignupSchema = z.object({
 *   email: zSensitivePreprocess({ trim: true, lowercase: true }, 'email', z.email()),
 *   password: zCredential('password').refineSensitive((raw) => raw.length >= 12, {
 *     message: 'Password must be at least 12 characters',
 *   }),
 *   backupCodes: zCredentialArray('backup_code').min(1),
 * });
 *
 * // Errors that never echo the input, in the message or in the issue objects.
 * const result = sensitiveSafeParse(SignupSchema, req.body);
 * ```
 *
 * @packageDocumentation
 */

// Base schema factories
export {
  zSensitiveString,
  zSensitive,
  zCredential,
  zSensitiveWithValidation,
  zSensitiveOptional,
  zSensitiveDeserialize,
} from './base.js';

// Collections
export {
  zSensitiveStringArray,
  zSensitiveArray,
  zCredentialArray,
  zSensitiveStringRecord,
  zSensitiveRecord,
  zCredentialRecord,
} from './collections.js';
export type { SensitiveArraySchema, SensitiveRecordSchema } from './collections.js';

// Refinements over the raw value
export { refineSensitive } from './refine.js';

// Normalization before wrapping
export {
  zSensitiveStringPreprocess,
  zSensitivePreprocess,
  zCredentialPreprocess,
} from './preprocessing.js';
export type { PreprocessOptions, PreprocessSpec } from './preprocessing.js';

// Sensitivity decided by a sibling field
export { zConditionalSensitive } from './conditional.js';
export type {
  ConditionalSensitivity,
  ConditionalConditions,
  ConditionalSensitiveConfig,
  ConditionalSensitiveInput,
  ConditionalSensitiveOutput,
} from './conditional.js';

// Default values
export { zSensitiveDefault } from './defaults.js';

// Error handling that does not echo the input
export {
  sensitiveErrorMap,
  installSensitiveErrorMap,
  redactZodIssues,
  redactZodError,
  sensitiveParse,
  sensitiveSafeParse,
  sensitiveSafeParseAsync,
  REDACTED_ISSUE_VALUE,
} from './error-map.js';
export type { SensitiveParseOptions } from './error-map.js';

// Shared types
export type {
  SensitiveSchema,
  SensitiveSchemaMethods,
  SensitiveCheck,
  RefineSensitiveParams,
} from './types.js';

// Re-export core types and utilities for convenience
export { SensitiveString } from '@platform-sec/sensitive-string-core';
export type {
  SensitivityClass,
  SerializedSensitiveString,
  RevealContext,
} from '@platform-sec/sensitive-string-core';
export {
  withRevealContext,
  getCurrentRevealContext,
  safeLog,
  redactInStructure,
} from '@platform-sec/sensitive-string-core';
