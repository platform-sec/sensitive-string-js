/**
 * Arrays and records of sensitive values.
 *
 * Each helper wraps a per-element sensitive schema in a plain `z.array` or
 * `z.record`, rather than transforming a whole collection at once. That keeps
 * the collection combinators available (`.min()`, `.max()`, `.nonempty()`) and
 * puts a failing element's index or key in the issue path, where a whole-array
 * transform would report only against the array itself.
 *
 * @packageDocumentation
 */

import { z } from 'zod';
import type { SensitivityClass } from '@platform-sec/sensitive-string-core';
import { zSensitiveString } from './base.js';
import type { SensitiveSchema } from './types.js';

/**
 * A schema for an array of sensitive values.
 *
 * Exposed as its own name because the element schema is an intersection type
 * and spelling it out at every call site is noise.
 */
export type SensitiveArraySchema<C extends SensitivityClass> = z.ZodArray<SensitiveSchema<C>>;

/**
 * A schema for a record of sensitive values, keyed by plain strings.
 *
 * Keys stay plain. A key is a field name, not the secret, and redacting it
 * would leave the record unusable for lookup.
 */
export type SensitiveRecordSchema<C extends SensitivityClass> = z.ZodRecord<
  z.ZodString,
  SensitiveSchema<C>
>;

/**
 * Create a schema for an array whose elements are wrapped individually.
 *
 * @typeParam C - The sensitivity class applied to every element
 * @param klass - The sensitivity classification to apply
 * @param label - Optional label shared by every element
 * @returns A ZodArray of sensitive values
 *
 * @example
 * ```ts
 * const schema = zSensitiveStringArray('credential', 'api_key').min(1);
 * const keys = schema.parse(['sk-a', 'sk-b']);
 * // keys[0] is SensitiveString<'credential'>
 * ```
 */
export function zSensitiveStringArray<C extends SensitivityClass>(
  klass: C,
  label?: string
): SensitiveArraySchema<C> {
  return z.array(zSensitiveString(klass, label));
}

/**
 * Create a schema for an array of sensitive data (PII, business data).
 * Shorthand for zSensitiveStringArray('sensitive', label).
 *
 * @param label - Optional label shared by every element
 * @returns A ZodArray of SensitiveString<'sensitive'>
 *
 * @example
 * ```ts
 * const schema = z.object({ recipients: zSensitiveArray('email') });
 * schema.parse({ recipients: ['a@example.com', 'b@example.com'] });
 * ```
 */
export function zSensitiveArray(label?: string): SensitiveArraySchema<'sensitive'> {
  return zSensitiveStringArray('sensitive', label);
}

/**
 * Create a schema for an array of credentials.
 * Shorthand for zSensitiveStringArray('credential', label).
 *
 * @param label - Optional label shared by every element
 * @returns A ZodArray of SensitiveString<'credential'>
 *
 * @example
 * ```ts
 * const schema = z.object({ keys: zCredentialArray('api_key') });
 * ```
 */
export function zCredentialArray(label?: string): SensitiveArraySchema<'credential'> {
  return zSensitiveStringArray('credential', label);
}

/**
 * Create a schema for a record whose values are wrapped individually.
 *
 * @typeParam C - The sensitivity class applied to every value
 * @param klass - The sensitivity classification to apply
 * @param label - Optional label shared by every value
 * @returns A ZodRecord of sensitive values
 *
 * @example
 * ```ts
 * const schema = zSensitiveStringRecord('credential', 'secret');
 * const secrets = schema.parse({ stripe: 'sk-a', twilio: 'sk-b' });
 * // secrets.stripe is SensitiveString<'credential'>
 * ```
 */
export function zSensitiveStringRecord<C extends SensitivityClass>(
  klass: C,
  label?: string
): SensitiveRecordSchema<C> {
  return z.record(z.string(), zSensitiveString(klass, label));
}

/**
 * Create a schema for a record of sensitive data.
 * Shorthand for zSensitiveStringRecord('sensitive', label).
 *
 * @param label - Optional label shared by every value
 * @returns A ZodRecord of SensitiveString<'sensitive'>
 */
export function zSensitiveRecord(label?: string): SensitiveRecordSchema<'sensitive'> {
  return zSensitiveStringRecord('sensitive', label);
}

/**
 * Create a schema for a record of credentials.
 * Shorthand for zSensitiveStringRecord('credential', label).
 *
 * @param label - Optional label shared by every value
 * @returns A ZodRecord of SensitiveString<'credential'>
 *
 * @example
 * ```ts
 * const schema = zCredentialRecord('secret');
 * ```
 */
export function zCredentialRecord(label?: string): SensitiveRecordSchema<'credential'> {
  return zSensitiveStringRecord('credential', label);
}
