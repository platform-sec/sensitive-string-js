/**
 * @anthropic-security/sensitive-zod
 *
 * Zod integration for SensitiveString.
 * Parse and validate input directly into sensitive types at boundary layers.
 *
 * @example
 * ```ts
 * import { z } from 'zod';
 * import { zSensitive, zSensitiveEmail } from '@anthropic-security/sensitive-zod';
 *
 * const WebhookSchema = z.object({
 *   token: zSensitive('token'),
 *   email: zSensitiveEmail(),
 *   note: z.string().max(1024).optional(),
 * });
 *
 * // Type inference works correctly
 * type Webhook = z.infer<typeof WebhookSchema>;
 * // Webhook['token'] is SensitiveString<'token'>
 * // Webhook['email'] is SensitiveString<'pii_email'>
 * ```
 *
 * @packageDocumentation
 */

import { z } from 'zod';
import {
  SensitiveString,
  SensitivityClass,
} from '@anthropic-security/sensitive-core';

/**
 * Create a Zod schema that parses strings into SensitiveString instances.
 *
 * @typeParam C - The sensitivity class for the resulting SensitiveString
 * @param klass - The sensitivity classification to apply
 * @returns A Zod schema that transforms strings to SensitiveString<C>
 *
 * @example
 * ```ts
 * const schema = z.object({
 *   apiKey: zSensitive('secret'),
 *   sessionToken: zSensitive('token'),
 * });
 *
 * const result = schema.parse({
 *   apiKey: 'sk-xxx',
 *   sessionToken: 'sess-yyy',
 * });
 *
 * console.log(result.apiKey);  // SensitiveString<secret> { [REDACTED:secret] }
 * ```
 */
export function zSensitive<C extends SensitivityClass>(
  klass: C
): z.ZodEffects<z.ZodString, SensitiveString<C>, string> {
  return z.string().transform((value): SensitiveString<C> => {
    return new SensitiveString(value, klass);
  });
}

/**
 * Create a Zod schema for email addresses that parses into SensitiveString<'pii_email'>.
 * Validates email format before wrapping.
 *
 * @returns A Zod schema that validates and transforms email strings
 *
 * @example
 * ```ts
 * const schema = z.object({
 *   email: zSensitiveEmail(),
 * });
 *
 * // Invalid email throws validation error
 * schema.parse({ email: 'not-an-email' }); // throws
 *
 * // Valid email returns SensitiveString
 * const result = schema.parse({ email: 'user@example.com' });
 * console.log(result.email); // SensitiveString<pii_email> { [REDACTED:pii_email] }
 * ```
 */
export function zSensitiveEmail(): z.ZodEffects<
  z.ZodString,
  SensitiveString<'pii_email'>,
  string
> {
  return z
    .string()
    .email('Invalid email address')
    .transform((value): SensitiveString<'pii_email'> => {
      return new SensitiveString(value, 'pii_email');
    });
}

/**
 * Create a Zod schema for generic PII strings.
 *
 * @returns A Zod schema that transforms strings to SensitiveString<'pii_generic'>
 *
 * @example
 * ```ts
 * const schema = z.object({
 *   fullName: zSensitivePII(),
 *   phoneNumber: zSensitivePII(),
 * });
 * ```
 */
export function zSensitivePII(): z.ZodEffects<
  z.ZodString,
  SensitiveString<'pii_generic'>,
  string
> {
  return zSensitive('pii_generic');
}

/**
 * Create a Zod schema for secret values (passwords, API keys, etc.).
 *
 * @returns A Zod schema that transforms strings to SensitiveString<'secret'>
 *
 * @example
 * ```ts
 * const schema = z.object({
 *   password: zSensitiveSecret(),
 *   apiKey: zSensitiveSecret(),
 * });
 * ```
 */
export function zSensitiveSecret(): z.ZodEffects<
  z.ZodString,
  SensitiveString<'secret'>,
  string
> {
  return zSensitive('secret');
}

/**
 * Create a Zod schema for token values (session tokens, auth tokens, etc.).
 *
 * @returns A Zod schema that transforms strings to SensitiveString<'token'>
 *
 * @example
 * ```ts
 * const schema = z.object({
 *   sessionToken: zSensitiveToken(),
 *   refreshToken: zSensitiveToken(),
 * });
 * ```
 */
export function zSensitiveToken(): z.ZodEffects<
  z.ZodString,
  SensitiveString<'token'>,
  string
> {
  return zSensitive('token');
}

/**
 * Create a Zod schema with additional string validation before wrapping.
 *
 * @typeParam C - The sensitivity class for the resulting SensitiveString
 * @param klass - The sensitivity classification to apply
 * @param schema - A Zod string schema with validations
 * @returns A Zod schema that validates then transforms to SensitiveString<C>
 *
 * @example
 * ```ts
 * // API key must be at least 32 characters
 * const apiKeySchema = zSensitiveWithValidation(
 *   'secret',
 *   z.string().min(32, 'API key too short')
 * );
 *
 * // Password with complexity requirements
 * const passwordSchema = zSensitiveWithValidation(
 *   'secret',
 *   z.string()
 *     .min(8, 'Password must be at least 8 characters')
 *     .regex(/[A-Z]/, 'Password must contain uppercase')
 *     .regex(/[0-9]/, 'Password must contain a number')
 * );
 * ```
 */
export function zSensitiveWithValidation<C extends SensitivityClass>(
  klass: C,
  schema: z.ZodString
): z.ZodEffects<z.ZodString, SensitiveString<C>, string> {
  return schema.transform((value): SensitiveString<C> => {
    return new SensitiveString(value, klass);
  });
}

/**
 * Create a Zod schema for optional sensitive strings.
 * Returns null for undefined/null input, SensitiveString for valid strings.
 *
 * @typeParam C - The sensitivity class for the resulting SensitiveString
 * @param klass - The sensitivity classification to apply
 * @returns A Zod schema that transforms optional strings
 *
 * @example
 * ```ts
 * const schema = z.object({
 *   apiKey: zSensitiveOptional('secret'),
 * });
 *
 * schema.parse({ apiKey: undefined }); // { apiKey: null }
 * schema.parse({ apiKey: 'sk-xxx' });  // { apiKey: SensitiveString<secret> }
 * ```
 */
export function zSensitiveOptional<C extends SensitivityClass>(
  klass: C
): z.ZodEffects<
  z.ZodOptional<z.ZodNullable<z.ZodString>>,
  SensitiveString<C> | null,
  string | null | undefined
> {
  return z
    .string()
    .nullable()
    .optional()
    .transform((value): SensitiveString<C> | null => {
      if (value == null || value === '') {
        return null;
      }
      return new SensitiveString(value, klass);
    });
}

/**
 * Create a Zod schema that validates against an envelope format
 * and reconstructs the SensitiveString.
 *
 * Useful for validating incoming payloads that were serialized with toEnvelope().
 *
 * @typeParam C - The expected sensitivity class
 * @param expectedKlass - Optional expected class (validates if provided)
 * @returns A Zod schema that parses envelopes to SensitiveString
 *
 * @example
 * ```ts
 * const schema = z.object({
 *   token: zSensitiveFromEnvelope('token'),
 * });
 *
 * // Validates envelope structure and reconstructs
 * const result = schema.parse({
 *   token: { __sensitive: true, klass: 'token', value: 'secret-value' }
 * });
 * ```
 */
export function zSensitiveFromEnvelope<C extends SensitivityClass>(
  expectedKlass?: C
): z.ZodEffects<
  z.ZodObject<{
    __sensitive: z.ZodLiteral<true>;
    klass: z.ZodString;
    value: z.ZodString;
  }>,
  SensitiveString<C>,
  {
    __sensitive: true;
    klass: string;
    value: string;
  }
> {
  return z
    .object({
      __sensitive: z.literal(true),
      klass: z.string(),
      value: z.string(),
    })
    .transform((envelope): SensitiveString<C> => {
      if (expectedKlass && envelope.klass !== expectedKlass) {
        throw new Error(
          `Expected sensitivity class '${expectedKlass}', got '${envelope.klass}'`
        );
      }
      return new SensitiveString(envelope.value, envelope.klass as C);
    });
}

// Re-export core types and utilities for convenience
export { SensitiveString } from '@anthropic-security/sensitive-core';
export type {
  SensitivityClass,
  SensitiveEnvelope,
  RevealContext,
} from '@anthropic-security/sensitive-core';
export {
  withRevealContext,
  getCurrentRevealContext,
  safeLog,
  redactInStructure,
} from '@anthropic-security/sensitive-core';
