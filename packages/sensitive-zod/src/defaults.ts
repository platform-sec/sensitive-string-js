/**
 * Default values for sensitive fields.
 *
 * The default is produced as a raw string and wrapped by the schema, so a
 * caller never has to build a `SensitiveString` to describe a fallback, and a
 * generated default is classified the same way a parsed one is.
 *
 * @packageDocumentation
 */

import { z } from 'zod';
import { SensitiveString, SensitivityClass } from '@platform-sec/sensitive-string-core';
import { withSensitiveMethods } from './refine.js';
import type { SensitiveSchema } from './types.js';

/**
 * Create a schema that falls back to a default when the field is absent.
 *
 * A function default is called lazily, once per parse that needs it, so a
 * generated token is not shared between parses and a default read from the
 * environment is read at parse time rather than at schema construction.
 *
 * `undefined` triggers the default; `null` and `''` do not. They are values a
 * client sent, and treating them as absent would silently substitute a secret
 * for input that should have been rejected.
 *
 * The fallback is held in the transform's closure rather than in a
 * `.default()`, and that placement is the security-relevant part.
 * `z.toJSONSchema(schema, { io: 'input' })` reads a schema definition's
 * `default` and emits it verbatim, calling a function default to do so; every
 * OpenAPI generator in the ecosystem takes that path. The documented example
 * below reads `process.env.API_KEY`, so under a `.default()` the live key
 * would be embedded in a document whose whole purpose is publication. A
 * closure is not part of the definition and has nothing to read.
 *
 * @typeParam C - The sensitivity class for the resulting SensitiveString
 * @param klass - The sensitivity classification to apply
 * @param label - Optional label for audit/compliance
 * @param defaultValue - The fallback string, or a function producing one
 * @returns A schema producing SensitiveString<C>, with the field optional
 *
 * @example
 * ```ts
 * const Config = z.object({
 *   apiKey: zSensitiveDefault('credential', 'api_key', () => process.env.API_KEY ?? ''),
 * });
 *
 * Config.parse({}).apiKey;  // SensitiveString<'credential'>
 * ```
 */
export function zSensitiveDefault<C extends SensitivityClass>(
  klass: C,
  label: string | undefined,
  defaultValue: string | (() => string)
): SensitiveSchema<C, string | undefined> {
  return withSensitiveMethods(
    z
      .string()
      .optional()
      .transform((value): SensitiveString<C> => {
        const raw = value ?? (typeof defaultValue === 'function' ? defaultValue() : defaultValue);
        return new SensitiveString(raw, klass, label);
      })
  );
}
