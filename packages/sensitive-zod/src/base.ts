/**
 * The base schema factories: plain strings, validated strings, optional
 * fields, and the serialized wire format.
 *
 * @packageDocumentation
 */

import { z } from 'zod';
import { SensitiveString, SensitivityClass } from '@platform-sec/sensitive-string-core';
import { withSensitiveMethods } from './refine.js';
import type { SensitiveSchema } from './types.js';

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
): SensitiveSchema<C, string> {
  return withSensitiveMethods(
    z.string().transform((value): SensitiveString<C> => {
      return new SensitiveString(value, klass, label);
    })
  );
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
export function zSensitive(label?: string): SensitiveSchema<'sensitive', string> {
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
export function zCredential(label?: string): SensitiveSchema<'credential', string> {
  return zSensitiveString('credential', label);
}

/**
 * Create a Zod schema with additional string validation before wrapping.
 *
 * The schema parameter is any string-to-string schema, not specifically a
 * `z.ZodString`. Zod 4 promoted the string formats to top-level constructors
 * with classes of their own, so `z.email()` is a `ZodEmail` and is not a
 * `ZodString`; requiring the narrower type would push callers back onto the
 * deprecated `z.string().email()` spelling to use this package.
 *
 * @typeParam C - The sensitivity class for the resulting SensitiveString
 * @param klass - The sensitivity classification to apply
 * @param schema - A Zod schema that takes and returns a string
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
 * // A v4 format constructor works directly.
 * const emailSchema = zSensitiveWithValidation('sensitive', z.email(), 'email');
 *
 * // Password with complexity requirements
 * const passwordSchema = zSensitiveWithValidation(
 *   'credential',
 *   z.string()
 *     .min(8, 'Password must be at least 8 characters')
 *     .regex(/[A-Z]/, 'Password must contain uppercase'),
 *   'password'
 * );
 * ```
 */
export function zSensitiveWithValidation<C extends SensitivityClass>(
  klass: C,
  schema: z.ZodType<string, string>,
  label?: string
): SensitiveSchema<C, string> {
  return withSensitiveMethods(
    schema.transform((value): SensitiveString<C> => {
      return new SensitiveString(value, klass, label);
    })
  );
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
): z.ZodType<SensitiveString<C> | null, string | null | undefined> {
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
 * registered, a deadline carried by the payload is carried into the value, a
 * payload that marks the value revoked produces a revoked value, and environment
 * restrictions arrive with it. Rebuilding the value here instead would silently
 * drop all three, which fails open: an expiring token would arrive as one that
 * never expires, a revoked one as live, and one restricted to the EU as readable
 * anywhere.
 *
 * A class mismatch, an unregistered class, and a malformed payload are all
 * reported as Zod issues, so `safeParse` reports them rather than throwing.
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
): SensitiveSchema<
  C,
  {
    __sensitive: true;
    klass: string;
    value: string;
    label?: string | undefined;
    expiresAt?: string | undefined;
    revoked?: true | undefined;
    revocationReason?: string | undefined;
    restrictions?: unknown[] | undefined;
  }
> {
  return withSensitiveMethods(
    z
      .object({
        __sensitive: z.literal(true),
        klass: z.string(),
        value: z.string(),
        label: z.string().optional(),
        expiresAt: z.string().optional(),
        // Declared so the object schema does not strip them before
        // `deserialize()` sees them. An unlisted key is dropped, and dropping
        // these would turn a payload that says "do not use this" into one that
        // says nothing, or a value restricted to the EU into one readable
        // anywhere, which is the same fail-open shape as losing the deadline.
        // Validating them is still core's job, so all three are accepted
        // loosely here and rejected there.
        revoked: z.literal(true).optional(),
        revocationReason: z.string().optional(),
        restrictions: z.array(z.unknown()).optional(),
      })
      .transform((serialized, ctx): SensitiveString<C> => {
        // Reported as issues rather than thrown. A throw from inside a
        // transform escapes `safeParse`, so a caller who chose the
        // non-throwing API would get an exception anyway, from the one schema
        // whose whole job is handling a payload from another service.
        if (expectedKlass && serialized.klass !== expectedKlass) {
          ctx.addIssue({
            code: 'custom',
            message: `Expected sensitivity class '${expectedKlass}', got '${serialized.klass}'`,
          });
          return z.NEVER;
        }

        try {
          return SensitiveString.deserialize<C>(serialized);
        } catch (error) {
          ctx.addIssue({
            code: 'custom',
            message: error instanceof Error ? error.message : 'Invalid serialized sensitive value',
          });
          return z.NEVER;
        }
      })
  );
}
