/**
 * Normalizing input before it is wrapped.
 *
 * Normalization has to happen before wrapping: once a value is a
 * SensitiveString, trimming it means revealing it. Doing it here keeps the
 * whole normalize-validate-wrap sequence on the raw string, inside the parse,
 * with no reveal at all.
 *
 * Order is normalize, then validate, then wrap. That matches Zod's own
 * `preprocess`, and it is the order callers expect: `' A@B.COM '` should pass
 * an email check.
 *
 * @packageDocumentation
 */

import { z } from 'zod';
import { SensitiveString, SensitivityClass } from '@platform-sec/sensitive-string-core';
import { withSensitiveMethods } from './refine.js';
import type { SensitiveSchema } from './types.js';

/**
 * Declarative normalization steps, applied in the order listed here.
 */
export interface PreprocessOptions {
  /**
   * Unicode normalization form, applied first so that later steps and any
   * validation see one canonical encoding of the same text.
   */
  normalize?: 'NFC' | 'NFD' | 'NFKC' | 'NFKD';
  /** Collapse each run of whitespace to a single space. */
  collapseWhitespace?: boolean;
  /** Remove every whitespace character. Useful for keys pasted with line breaks. */
  stripWhitespace?: boolean;
  /** Remove leading and trailing whitespace. */
  trim?: boolean;
  /** Lowercase the value. Mutually exclusive with `uppercase`. */
  lowercase?: boolean;
  /** Uppercase the value. Mutually exclusive with `lowercase`. */
  uppercase?: boolean;
}

/**
 * What a caller may pass as the normalization to apply: the declarative option
 * set, a single function, or a list of functions run left to right.
 */
export type PreprocessSpec =
  PreprocessOptions | ((value: string) => string) | ReadonlyArray<(value: string) => string>;

/**
 * Turn a spec into a single function over the raw string.
 *
 * @throws TypeError If `lowercase` and `uppercase` are both set, or a step is not a function.
 */
function compileSpec(spec: PreprocessSpec): (value: string) => string {
  if (typeof spec === 'function') {
    return spec;
  }

  if (Array.isArray(spec)) {
    const steps = spec as ReadonlyArray<(value: string) => string>;
    for (const step of steps) {
      if (typeof step !== 'function') {
        throw new TypeError('Preprocess steps must be functions');
      }
    }
    return (value) => steps.reduce((acc, step) => step(acc), value);
  }

  const options = spec as PreprocessOptions;
  if (options.lowercase === true && options.uppercase === true) {
    throw new TypeError('Preprocess options cannot set both lowercase and uppercase');
  }

  return (value) => {
    let result = value;
    if (options.normalize !== undefined) {
      result = result.normalize(options.normalize);
    }
    if (options.collapseWhitespace === true) {
      result = result.replace(/\s+/gu, ' ');
    }
    if (options.stripWhitespace === true) {
      result = result.replace(/\s+/gu, '');
    }
    if (options.trim === true) {
      result = result.trim();
    }
    if (options.lowercase === true) {
      result = result.toLowerCase();
    }
    if (options.uppercase === true) {
      result = result.toUpperCase();
    }
    return result;
  };
}

/**
 * Create a schema that normalizes the input, validates it, then wraps it.
 *
 * A non-string input is passed through untouched, so the inner string schema
 * reports the usual `invalid_type` issue rather than the preprocessor throwing
 * on it.
 *
 * @typeParam C - The sensitivity class for the resulting SensitiveString
 * @param klass - The sensitivity classification to apply
 * @param spec - Normalization options, a function, or a list of functions
 * @param label - Optional label for audit/compliance
 * @param schema - Optional string schema, validated after normalization
 * @returns A schema that transforms normalized strings to SensitiveString<C>
 * @throws TypeError If the spec is malformed.
 *
 * @example
 * ```ts
 * const email = zSensitiveStringPreprocess(
 *   'sensitive',
 *   { trim: true, lowercase: true },
 *   'email',
 *   z.string().email()
 * );
 *
 * email.parse('  Alice@Example.COM  ').reveal(); // 'alice@example.com'
 * ```
 */
export function zSensitiveStringPreprocess<C extends SensitivityClass>(
  klass: C,
  spec: PreprocessSpec,
  label?: string,
  schema?: z.ZodString
): SensitiveSchema<C, string> {
  const normalize = compileSpec(spec);

  const built = z
    .preprocess(
      (value) => (typeof value === 'string' ? normalize(value) : value),
      schema ?? z.string()
    )
    .transform((value): SensitiveString<C> => new SensitiveString(value, klass, label));

  // `z.preprocess` declares its input as `unknown`, and `undefined` extends
  // `unknown`, so carrying that through would mark the field optional wherever
  // this schema sits in an object. A missing value is rejected at runtime, so
  // the declared input is the string the schema actually asks for.
  return withSensitiveMethods(
    built as unknown as z.ZodType<SensitiveString<C>, z.ZodTypeDef, string>
  );
}

/**
 * Normalize, then wrap as sensitive data.
 * Shorthand for zSensitiveStringPreprocess('sensitive', spec, label, schema).
 *
 * @param spec - Normalization options, a function, or a list of functions
 * @param label - Optional label for audit/compliance
 * @param schema - Optional string schema, validated after normalization
 * @returns A schema producing SensitiveString<'sensitive'>
 *
 * @example
 * ```ts
 * const schema = zSensitivePreprocess({ trim: true, lowercase: true }, 'email');
 * ```
 */
export function zSensitivePreprocess(
  spec: PreprocessSpec,
  label?: string,
  schema?: z.ZodString
): SensitiveSchema<'sensitive', string> {
  return zSensitiveStringPreprocess('sensitive', spec, label, schema);
}

/**
 * Normalize, then wrap as a credential.
 * Shorthand for zSensitiveStringPreprocess('credential', spec, label, schema).
 *
 * @param spec - Normalization options, a function, or a list of functions
 * @param label - Optional label for audit/compliance
 * @param schema - Optional string schema, validated after normalization
 * @returns A schema producing SensitiveString<'credential'>
 *
 * @example
 * ```ts
 * // An API key pasted from a console arrives with line breaks in it.
 * const apiKey = zCredentialPreprocess({ stripWhitespace: true }, 'api_key');
 * ```
 */
export function zCredentialPreprocess(
  spec: PreprocessSpec,
  label?: string,
  schema?: z.ZodString
): SensitiveSchema<'credential', string> {
  return zSensitiveStringPreprocess('credential', spec, label, schema);
}
