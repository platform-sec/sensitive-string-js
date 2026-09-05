/**
 * Keeping the input out of validation errors.
 *
 * Most of Zod's built-in issues report the rule, not the string that failed it,
 * and Zod 4 closed two leaks v3 had: `invalid_enum_value` and `invalid_literal`
 * are both `invalid_value` now, which carries the *allowed* set rather than
 * what arrived. What is left, measured against 4.5.4 with a canary:
 *
 * - `unrecognized_keys` puts unknown key names in `keys` and in the message.
 * - `custom` carries whatever a `superRefine` caller attached to `params`.
 * - `invalid_element` carries the offending map key in `key`.
 * - every issue can carry `input`, the value itself. Zod drops it during
 *   finalization by default, but `{ reportInput: true }` in the parse options
 *   keeps it, and the raw issue an error function sees always has it.
 * - `invalid_union`, `invalid_key`, and `invalid_element` nest issue lists, so
 *   any of the above can arrive one or more levels down.
 *
 * That splits the fix in two. An error map can only rewrite the message, so it
 * handles what a caller sees in `error.message`. The `keys`, `params`, `key`,
 * and `input` fields survive an error map untouched and reach anything that
 * serializes the error, which is where structured logging picks them up. Use
 * {@link sensitiveSafeParse} to get both, or {@link redactZodError} on an error
 * you already hold.
 *
 * What is deliberately *not* covered is `issue.path`. A container keyed by a
 * sensitive value puts that value in the path of every issue below it. Redacting
 * it would collapse every field of a multi-issue error into one bucket and make
 * `z.treeifyError` useless, so the answer is not to key a container by a secret:
 * put it in the value position, which is what `zSensitiveRecord` does.
 *
 * One thing this module does not attempt at all: the guarantee is about the
 * *input*, not about values a schema author embedded in their own schema.
 * `invalid_value.values` echoes what `z.literal()` and `z.enum()` were given,
 * and `invalid_format` echoes the argument to `startsWith`, `endsWith`, and
 * `includes`. Those read as safe in the table above, and they are, with respect
 * to the input. `z.literal(secret)` still puts the secret in every issue it
 * produces, and there is nothing here that could tell it apart from a legitimate
 * allowed value. Do not build a schema out of a secret.
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
 * The parse options accepted by the helpers in this module.
 *
 * Zod 4 renamed the per-call error map from `errorMap` to `error` and does not
 * reject unknown keys, so a v3 spelling would be accepted at runtime and
 * ignored. This alias is the v4 type, which rejects `errorMap` at compile time.
 */
export type SensitiveParseOptions = z.core.ParseContext<z.core.$ZodIssue>;

/**
 * A Zod error map that never echoes the input into a message.
 *
 * Install it globally with {@link installSensitiveErrorMap}, or pass it per
 * call as `schema.safeParse(data, { error: sensitiveErrorMap })`.
 *
 * This rewrites messages only. The issue objects still carry `keys`, `params`,
 * and `key`; see {@link redactZodError}.
 *
 * Returning `undefined` is how a v4 error map declines: there is no second
 * `ctx` argument carrying a default message, and returning nothing hands the
 * issue back to Zod's own message resolution.
 *
 * @example
 * ```ts
 * const schema = z.object({ a: z.string() }).strict();
 * const result = schema.safeParse({ a: 'x', [secret]: 1 }, { error: sensitiveErrorMap });
 * // "Unrecognized key(s) in object: 1 not allowed" - and nothing about the key
 * ```
 */
export const sensitiveErrorMap: z.core.$ZodErrorMap = (issue) => {
  // Invariant S3: `issue.input` is never read here. The raw issue handed to an
  // error function carries the value in full, so interpolating any part of the
  // issue into a message is how this function would become the leak it exists
  // to prevent.
  switch (issue.code) {
    case 'unrecognized_keys':
      return `Unrecognized key(s) in object: ${issue.keys.length} not allowed`;

    default:
      return undefined;
  }
};

/**
 * Install {@link sensitiveErrorMap} as Zod's global error map.
 *
 * Global on purpose: the leaking issue codes come from schemas this package
 * knows nothing about, most often a strict object sitting beside a sensitive
 * field. Scoping the map to sensitive schemas would miss exactly the cases it
 * exists for.
 *
 * It is not installed on import. A library that reaches into a process's
 * global Zod configuration behind the application's back is worse than one
 * that asks for a line of setup.
 *
 * `z.config()` reads the configuration back, so a caller who needs to undo this
 * can capture `z.config().customError` first and restore it afterwards.
 *
 * @example
 * ```ts
 * // Once, during startup.
 * installSensitiveErrorMap();
 * ```
 */
export function installSensitiveErrorMap(): void {
  z.config({ customError: sensitiveErrorMap });
}

/**
 * Merge the caller's parse options with the ones this module requires.
 *
 * Two rules, and both are fail-open if dropped.
 *
 * An explicit `error: undefined` counts as not supplying a map. Spreading it
 * over the default would leave Zod resolving the global map instead, which
 * defeats the one helper whose whole job is not leaking the input.
 *
 * `reportInput` is forced off. It is a v4 parse option that keeps the raw
 * value on every finalized issue; `redactIssue` strips it afterwards either
 * way, but a helper named for not leaking the input should not ask Zod to put
 * it there in the first place.
 */
function withSensitiveParseOptions(
  params: SensitiveParseOptions | undefined
): SensitiveParseOptions {
  return { ...params, error: params?.error ?? sensitiveErrorMap, reportInput: false };
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
 * Drop `input` from an issue.
 *
 * Zod strips it during finalization under the default parse options, but
 * `z.core.$ZodIssueBase` declares `readonly input?: unknown`, so the field
 * type-checks on a finalized issue and `{ reportInput: true }` really does
 * populate it. This does not depend on which of those a caller got.
 */
function withoutInput(issue: z.core.$ZodIssue): z.core.$ZodIssue {
  if (!('input' in issue)) {
    return issue;
  }

  const copy: Record<string, unknown> = { ...issue };
  delete copy['input'];
  return copy as unknown as z.core.$ZodIssue;
}

/**
 * Strip input-derived values out of one issue's own fields.
 *
 * `invalid_type` is left alone: its `expected` is a type name such as
 * `'string'`, not the value. `too_small`, `too_big`, `invalid_format`,
 * `not_multiple_of`, and `invalid_value` describe the rule and were measured
 * clean.
 */
function redactIssueFields(issue: z.core.$ZodIssue): z.core.$ZodIssue {
  switch (issue.code) {
    case 'unrecognized_keys': {
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

    case 'custom': {
      // `params` is whatever a superRefine caller attached. It is dropped
      // rather than inspected: this helper cannot tell a locale key from the
      // value that failed the check.
      const { params: _params, ...rest } = issue;
      return rest;
    }

    case 'invalid_union':
      // The multiple-match member declares `errors: []` and carries nothing to
      // redact, and mapping over it would not type-check against that member.
      return 'matches' in issue
        ? issue
        : { ...issue, errors: issue.errors.map((nested) => redactZodIssues(nested)) };

    case 'invalid_key':
      // A record or map key rejected by its own schema. The nested issues are
      // about the key, so a refinement on it can put the key in `params`.
      return { ...issue, issues: redactZodIssues(issue.issues) };

    case 'invalid_element':
      // Zod reports a map value under a non-primitive key here, and `key` is
      // that key verbatim.
      return {
        ...issue,
        key: REDACTED_ISSUE_VALUE,
        issues: redactZodIssues(issue.issues),
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
export function redactZodIssues(issues: readonly z.core.$ZodIssue[]): z.core.$ZodIssue[] {
  return issues.map((issue) => withoutInput(redactIssueFields(issue)));
}

/**
 * Copy a ZodError with every input value stripped out, including from the
 * issues nested inside a union, key, or element issue.
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
export function redactZodError<T>(error: z.ZodError<T>): z.ZodError<T> {
  // v4 exports `ZodError` as `core.$constructor<ZodError>`, with no type
  // parameter, so `new z.ZodError<T>(...)` is a compile error. The result
  // carries the same issues for the same input, so the parameter is restored
  // here rather than dropped from the signature and pushed onto every caller.
  return new z.ZodError(redactZodIssues(error.issues)) as z.ZodError<T>;
}

/**
 * `safeParse` with both halves of the fix applied: the error map rewrites the
 * messages, and the returned issues are redacted.
 *
 * @typeParam Output - What the schema produces
 * @typeParam Input - What the schema accepts
 * @param schema - The schema to parse with
 * @param data - The input
 * @param params - Additional Zod parse options; a supplied `error` map wins
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
  schema: z.ZodType<Output, Input>,
  data: unknown,
  params?: SensitiveParseOptions
): z.ZodSafeParseResult<Output> {
  const result = schema.safeParse(data, withSensitiveParseOptions(params));
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
 * @param params - Additional Zod parse options; a supplied `error` map wins
 * @returns Zod's usual safe-parse result, with a redacted error on failure
 */
export async function sensitiveSafeParseAsync<Output, Input>(
  schema: z.ZodType<Output, Input>,
  data: unknown,
  params?: SensitiveParseOptions
): Promise<z.ZodSafeParseResult<Output>> {
  const result = await schema.safeParseAsync(data, withSensitiveParseOptions(params));
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
 * @param params - Additional Zod parse options; a supplied `error` map wins
 * @returns The parsed value
 * @throws z.ZodError Redacted, if validation fails.
 */
export function sensitiveParse<Output, Input>(
  schema: z.ZodType<Output, Input>,
  data: unknown,
  params?: SensitiveParseOptions
): Output {
  const result = sensitiveSafeParse(schema, data, params);
  if (!result.success) {
    throw result.error;
  }
  return result.data;
}
