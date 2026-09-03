/**
 * Keeping the input out of validation errors.
 *
 * Most of Zod's built-in issues are already safe: a failed `min`, `email`, or
 * `regex` check reports the rule, not the string that failed it. Four are not,
 * and all four are reachable from a schema that has sensitive fields:
 *
 * - `invalid_enum_value` puts the input in `received` and in the message.
 * - `invalid_literal` puts the input in `received`.
 * - `unrecognized_keys` puts unknown key names in `keys` and in the message.
 * - `custom` carries whatever a `superRefine` caller attached to `params`.
 *
 * `invalid_union` nests entire `ZodError`s, so any of the four can arrive one
 * level down.
 *
 * That splits the fix in two. An error map can only rewrite the message, so it
 * handles what a caller sees in `error.message`. The `received`, `keys`, and
 * `params` fields survive an error map untouched and reach anything that
 * serializes the error, which is where structured logging picks them up. Use
 * {@link sensitiveSafeParse} to get both, or {@link redactZodError} on an error
 * you already hold.
 *
 * @packageDocumentation
 */

import { z } from 'zod';

/**
 * Stand-in written over any value stripped from an issue.
 *
 * Matches the core library's redaction marker so that one grep over a log
 * finds every kind of redaction the library performs.
 */
export const REDACTED_ISSUE_VALUE = '[REDACTED]';

/**
 * A Zod error map that never echoes the input into a message.
 *
 * Install it globally with {@link installSensitiveErrorMap}, or pass it per
 * call as `schema.safeParse(data, { errorMap: sensitiveErrorMap })`.
 *
 * This rewrites messages only. The issue objects still carry `received` and
 * `keys`; see {@link redactZodError}.
 *
 * @example
 * ```ts
 * const result = z.enum(['a', 'b']).safeParse(secret, { errorMap: sensitiveErrorMap });
 * // "Invalid enum value. Expected 'a' | 'b'" - and nothing about the input
 * ```
 */
export const sensitiveErrorMap: z.ZodErrorMap = (issue, ctx) => {
  switch (issue.code) {
    case z.ZodIssueCode.invalid_enum_value:
      return {
        message: `Invalid enum value. Expected ${issue.options
          .map((option) => JSON.stringify(option))
          .join(' | ')}`,
      };

    case z.ZodIssueCode.unrecognized_keys:
      return {
        message: `Unrecognized key(s) in object: ${issue.keys.length} not allowed`,
      };

    default:
      return { message: ctx.defaultError };
  }
};

/**
 * Install {@link sensitiveErrorMap} as Zod's global error map.
 *
 * Global on purpose: the leaking issue codes come from schemas this package
 * knows nothing about, most often a `z.enum` sitting beside a sensitive field
 * in the same object. Scoping the map to sensitive schemas would miss exactly
 * the cases it exists for.
 *
 * It is not installed on import. A library that reaches into a process's
 * global Zod configuration behind the application's back is worse than one
 * that asks for a line of setup.
 *
 * @example
 * ```ts
 * // Once, during startup.
 * installSensitiveErrorMap();
 * ```
 */
export function installSensitiveErrorMap(): void {
  z.setErrorMap(sensitiveErrorMap);
}

/**
 * Merge the caller's parse params with the error map.
 *
 * An explicit `errorMap: undefined` counts as not supplying one. Spreading it
 * over the default would leave Zod resolving the global map instead, which is
 * a fail-open in the one helper whose whole job is not leaking the input.
 */
function withSensitiveErrorMap(params: Partial<z.ParseParams> | undefined): Partial<z.ParseParams> {
  return { ...params, errorMap: params?.errorMap ?? sensitiveErrorMap };
}

/**
 * Replace every occurrence of a value's string form in a message.
 *
 * The message is rewritten rather than discarded so that a caller who has not
 * installed the error map still gets a usable explanation of the failure.
 */
function scrubFromMessage(message: string, value: unknown): string {
  const rendered = typeof value === 'string' ? value : String(value);
  if (rendered === '' || !message.includes(rendered)) {
    return message;
  }
  return message.split(rendered).join(REDACTED_ISSUE_VALUE);
}

/**
 * Strip input values out of one issue.
 *
 * `invalid_type` is left alone: its `received` is a type name such as
 * `'string'`, not the value.
 */
function redactIssue(issue: z.ZodIssue): z.ZodIssue {
  switch (issue.code) {
    case z.ZodIssueCode.invalid_literal:
      return {
        ...issue,
        received: REDACTED_ISSUE_VALUE,
        message: scrubFromMessage(issue.message, issue.received),
      };

    case z.ZodIssueCode.invalid_enum_value:
      return {
        ...issue,
        received: REDACTED_ISSUE_VALUE,
        message: scrubFromMessage(issue.message, issue.received),
      };

    case z.ZodIssueCode.unrecognized_keys: {
      let message = issue.message;
      for (const key of issue.keys) {
        message = scrubFromMessage(message, key);
      }
      return {
        ...issue,
        keys: issue.keys.map(() => REDACTED_ISSUE_VALUE),
        message,
      };
    }

    case z.ZodIssueCode.custom: {
      // `params` is whatever a superRefine caller attached. It is dropped
      // rather than inspected: this helper cannot tell a locale key from the
      // value that failed the check.
      const { params: _params, ...rest } = issue;
      return rest;
    }

    case z.ZodIssueCode.invalid_union:
      return {
        ...issue,
        unionErrors: issue.unionErrors.map((unionError) => redactZodError(unionError)),
      };

    case z.ZodIssueCode.invalid_arguments:
      return {
        ...issue,
        argumentsError: redactZodError(issue.argumentsError),
      };

    case z.ZodIssueCode.invalid_return_type:
      return {
        ...issue,
        returnTypeError: redactZodError(issue.returnTypeError),
      };

    default:
      return issue;
  }
}

/**
 * Copy a list of issues with every input value stripped out.
 *
 * The originals are not modified: a caller may still be holding the unredacted
 * error, and silently mutating it would change what an already-written handler
 * reports.
 *
 * @param issues - The issues to copy
 * @returns Issues safe to log or serialize
 */
export function redactZodIssues(issues: readonly z.ZodIssue[]): z.ZodIssue[] {
  return issues.map(redactIssue);
}

/**
 * Copy a ZodError with every input value stripped out, including from the
 * errors nested inside a union issue.
 *
 * @param error - The error to copy
 * @returns A new ZodError safe to log or serialize
 *
 * @example
 * ```ts
 * try {
 *   schema.parse(payload);
 * } catch (err) {
 *   if (err instanceof z.ZodError) {
 *     logger.warn('validation failed', { issues: redactZodError(err).issues });
 *   }
 * }
 * ```
 */
export function redactZodError<Input>(error: z.ZodError<Input>): z.ZodError<Input> {
  return new z.ZodError<Input>(redactZodIssues(error.issues));
}

/**
 * `safeParse` with both halves of the fix applied: the error map rewrites the
 * messages, and the returned issues are redacted.
 *
 * @typeParam Output - What the schema produces
 * @typeParam Input - What the schema accepts
 * @param schema - The schema to parse with
 * @param data - The input
 * @param params - Additional Zod parse params; a supplied `errorMap` wins
 * @returns Zod's usual safe-parse result, with a redacted error on failure
 *
 * @example
 * ```ts
 * const result = sensitiveSafeParse(LoginSchema, req.body);
 * if (!result.success) {
 *   res.status(400).json({ issues: result.error.issues });  // no input echoed
 * }
 * ```
 */
export function sensitiveSafeParse<Output, Input>(
  schema: z.ZodType<Output, z.ZodTypeDef, Input>,
  data: unknown,
  params?: Partial<z.ParseParams>
): z.SafeParseReturnType<Input, Output> {
  const result = schema.safeParse(data, withSensitiveErrorMap(params));
  return result.success ? result : { success: false, error: redactZodError(result.error) };
}

/**
 * The async counterpart of {@link sensitiveSafeParse}, for schemas carrying an
 * async refinement.
 *
 * @typeParam Output - What the schema produces
 * @typeParam Input - What the schema accepts
 * @param schema - The schema to parse with
 * @param data - The input
 * @param params - Additional Zod parse params; a supplied `errorMap` wins
 * @returns Zod's usual safe-parse result, with a redacted error on failure
 */
export async function sensitiveSafeParseAsync<Output, Input>(
  schema: z.ZodType<Output, z.ZodTypeDef, Input>,
  data: unknown,
  params?: Partial<z.ParseParams>
): Promise<z.SafeParseReturnType<Input, Output>> {
  const result = await schema.safeParseAsync(data, withSensitiveErrorMap(params));
  return result.success ? result : { success: false, error: redactZodError(result.error) };
}

/**
 * `parse` that throws a redacted ZodError.
 *
 * Anything else raised during parsing, such as an error thrown from inside a
 * `transform`, propagates untouched. This helper cannot know what such an
 * error's message contains, and pretending to have sanitized it would be worse
 * than passing it through.
 *
 * @typeParam Output - What the schema produces
 * @typeParam Input - What the schema accepts
 * @param schema - The schema to parse with
 * @param data - The input
 * @param params - Additional Zod parse params; a supplied `errorMap` wins
 * @returns The parsed value
 * @throws z.ZodError Redacted, if validation fails.
 */
export function sensitiveParse<Output, Input>(
  schema: z.ZodType<Output, z.ZodTypeDef, Input>,
  data: unknown,
  params?: Partial<z.ParseParams>
): Output {
  const result = sensitiveSafeParse(schema, data, params);
  if (!result.success) {
    throw result.error;
  }
  return result.data;
}
