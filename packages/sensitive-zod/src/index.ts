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
 * @packageDocumentation
 */

import { z } from 'zod';
import { SensitiveString, SensitivityClass } from '@platform-sec/sensitive-string-core';

/**
 * Create a Zod schema that parses strings into SensitiveString instances.
 *
 * @typeParam C - The sensitivity class for the resulting SensitiveString
 * @param klass - The sensitivity classification to apply
 * @param label - Optional label for audit/compliance categorization
 * @returns A Zod schema that transforms strings to SensitiveString<C>
 *
 * @example
 * ```ts
 * const schema = z.object({
 *   apiKey: zSensitiveString('credential', 'api_key'),
 *   email: zSensitiveString('sensitive', 'email'),
 * });
 *
 * const result = schema.parse({
 *   apiKey: 'sk-xxx',
 *   email: 'user@example.com',
 * });
 *
 * console.log(result.apiKey);  // SensitiveString<credential:api_key> { [REDACTED:credential] }
 * ```
 */
export function zSensitiveString<C extends SensitivityClass>(
  klass: C,
  label?: string
): z.ZodEffects<z.ZodString, SensitiveString<C>, string> {
  return z.string().transform((value): SensitiveString<C> => {
    return new SensitiveString(value, klass, label);
  });
}

/**
 * Create a Zod schema for sensitive data (PII, business data, etc.).
 * Shorthand for zSensitiveString('sensitive', label).
 *
 * @param label - Optional label for audit/compliance (e.g., 'email', 'phone', 'address')
 * @returns A Zod schema that transforms strings to SensitiveString<'sensitive'>
 *
 * @example
 * ```ts
 * const schema = z.object({
 *   email: zSensitive('email'),
 *   phone: zSensitive('phone'),
 *   name: zSensitive('name'),
 * });
 * ```
 */
export function zSensitive(
  label?: string
): z.ZodEffects<z.ZodString, SensitiveString<'sensitive'>, string> {
  return zSensitiveString('sensitive', label);
}

/**
 * Create a Zod schema for credential data (passwords, API keys, tokens).
 * Shorthand for zSensitiveString('credential', label).
 * Values will use constant-time comparison to prevent timing attacks.
 *
 * @param label - Optional label for audit/compliance (e.g., 'api_key', 'password', 'session_token')
 * @returns A Zod schema that transforms strings to SensitiveString<'credential'>
 *
 * @example
 * ```ts
 * const schema = z.object({
 *   password: zCredential('password'),
 *   apiKey: zCredential('api_key'),
 *   sessionToken: zCredential('session_token'),
 * });
 * ```
 */
export function zCredential(
  label?: string
): z.ZodEffects<z.ZodString, SensitiveString<'credential'>, string> {
  return zSensitiveString('credential', label);
}

/**
 * Create a Zod schema with additional string validation before wrapping.
 *
 * @typeParam C - The sensitivity class for the resulting SensitiveString
 * @param klass - The sensitivity classification to apply
 * @param schema - A Zod string schema with validations
 * @param label - Optional label for audit/compliance
 * @returns A Zod schema that validates then transforms to SensitiveString<C>
 *
 * @example
 * ```ts
 * // API key must be at least 32 characters
 * const apiKeySchema = zSensitiveWithValidation(
 *   'credential',
 *   z.string().min(32, 'API key too short'),
 *   'api_key'
 * );
 *
 * // Password with complexity requirements
 * const passwordSchema = zSensitiveWithValidation(
 *   'credential',
 *   z.string()
 *     .min(8, 'Password must be at least 8 characters')
 *     .regex(/[A-Z]/, 'Password must contain uppercase')
 *     .regex(/[0-9]/, 'Password must contain a number'),
 *   'password'
 * );
 * ```
 */
export function zSensitiveWithValidation<C extends SensitivityClass>(
  klass: C,
  schema: z.ZodString,
  label?: string
): z.ZodEffects<z.ZodString, SensitiveString<C>, string> {
  return schema.transform((value): SensitiveString<C> => {
    return new SensitiveString(value, klass, label);
  });
}

/**
 * Create a Zod schema for optional sensitive strings.
 * Returns null for undefined/null input, SensitiveString for valid strings.
 *
 * @typeParam C - The sensitivity class for the resulting SensitiveString
 * @param klass - The sensitivity classification to apply
 * @param label - Optional label for audit/compliance
 * @returns A Zod schema that transforms optional strings
 *
 * @example
 * ```ts
 * const schema = z.object({
 *   apiKey: zSensitiveOptional('credential', 'api_key'),
 * });
 *
 * schema.parse({ apiKey: undefined }); // { apiKey: null }
 * schema.parse({ apiKey: 'sk-xxx' });  // { apiKey: SensitiveString<credential> }
 * ```
 */
export function zSensitiveOptional<C extends SensitivityClass>(
  klass: C,
  label?: string
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
      return new SensitiveString(value, klass, label);
    });
}

/**
 * Create a Zod schema that validates against a serialized format
 * and reconstructs the SensitiveString.
 *
 * Useful for validating incoming payloads that were serialized with serialize().
 *
 * Reconstruction is delegated to `SensitiveString.deserialize()`, so this path
 * enforces exactly what the core wire format does: the sensitivity class must be
 * registered, and a deadline carried by the payload is carried into the value.
 * Rebuilding the value here instead would silently drop the deadline, which
 * fails open: an expiring token would arrive as one that never expires.
 *
 * @typeParam C - The expected sensitivity class
 * @param expectedKlass - Optional expected class (validates if provided)
 * @returns A Zod schema that parses serialized forms to SensitiveString
 *
 * @example
 * ```ts
 * const schema = z.object({
 *   token: zSensitiveDeserialize('credential'),
 * });
 *
 * // Validates serialized structure and reconstructs
 * const result = schema.parse({
 *   token: { __sensitive: true, klass: 'credential', value: 'secret-value', label: 'api_key' }
 * });
 * ```
 */
export function zSensitiveDeserialize<C extends SensitivityClass>(
  expectedKlass?: C
): z.ZodEffects<
  z.ZodObject<{
    __sensitive: z.ZodLiteral<true>;
    klass: z.ZodString;
    value: z.ZodString;
    label: z.ZodOptional<z.ZodString>;
    expiresAt: z.ZodOptional<z.ZodString>;
  }>,
  SensitiveString<C>,
  {
    __sensitive: true;
    klass: string;
    value: string;
    label?: string | undefined;
    expiresAt?: string | undefined;
  }
> {
  return z
    .object({
      __sensitive: z.literal(true),
      klass: z.string(),
      value: z.string(),
      label: z.string().optional(),
      expiresAt: z.string().optional(),
    })
    .transform((serialized): SensitiveString<C> => {
      if (expectedKlass && serialized.klass !== expectedKlass) {
        throw new Error(`Expected sensitivity class '${expectedKlass}', got '${serialized.klass}'`);
      }
      return SensitiveString.deserialize<C>(serialized);
    });
}

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
