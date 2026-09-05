/**
 * Refinements that need the raw value.
 *
 * A refinement that checks a password's shape, or an API key's prefix, has to
 * see the string. Running it before wrapping would hide that read from the
 * audit trail, so these helpers run after wrapping and read through
 * `reveal()`: the same authorization and the same audit hook as any other
 * reveal in the codebase.
 *
 * @packageDocumentation
 */

import { z } from 'zod';
import type { SensitiveString, SensitivityClass } from '@platform-sec/sensitive-string-core';
import type {
  RefineSensitiveParams,
  SensitiveCheck,
  SensitiveSchema,
  SensitiveSchemaMethods,
} from './types.js';

/**
 * The message used when a check fails and the caller supplied none.
 *
 * Deliberately says nothing about the value, not even its length.
 */
const DEFAULT_REFINE_MESSAGE = 'Invalid value';

/**
 * Build the issue for a failed check.
 *
 * `params.message` is the only caller-controlled text that reaches the issue.
 * Nothing derived from the raw value is added here, and a caller who
 * interpolates the value into their own message is the one leaking it.
 */
function refinementIssue(params: RefineSensitiveParams | undefined): {
  code: 'custom';
  message: string;
  path?: (string | number)[];
  fatal?: boolean;
} {
  const issue: {
    code: 'custom';
    message: string;
    path?: (string | number)[];
    fatal?: boolean;
  } = {
    code: 'custom',
    message: params?.message ?? DEFAULT_REFINE_MESSAGE,
  };

  if (params?.path !== undefined) {
    issue.path = params.path;
  }
  if (params?.fatal !== undefined) {
    issue.fatal = params.fatal;
  }

  return issue;
}

/**
 * Refine a schema that produces a SensitiveString, using the raw value.
 *
 * The predicate receives the revealed string. That read goes through
 * `reveal()`, so an ambient `RevealContext` authorizes it and its
 * `auditReveal` hook sees it with `operation: 'reveal'`. Pass
 * `params.context` to audit the refinement under a context of its own.
 *
 * @typeParam C - The sensitivity class the schema produces
 * @typeParam Input - The schema's input type
 * @param schema - A schema whose output is a SensitiveString
 * @param check - Predicate over the raw value; `false` produces an issue
 * @param params - Message, path, and reveal context for the check
 * @returns A schema producing the same value, refined
 *
 * @example
 * ```ts
 * const password = refineSensitive(
 *   zCredential('password'),
 *   (raw) => /[A-Z]/.test(raw),
 *   { message: 'Password must contain an uppercase letter' }
 * );
 * ```
 *
 * @remarks
 * An async check requires `parseAsync`. Zod throws `$ZodAsyncError` rather
 * than skipping it if it is reached from a synchronous `parse()`.
 *
 * A reveal the policy refuses, or one denied by a lapsed deadline, throws out
 * of the parse rather than becoming an issue, and that is deliberate. An issue
 * says the input was wrong. A refused reveal says this process may not read a
 * value it holds, which is a configuration or lifetime problem; reporting it as
 * a validation failure would tell a client its payload was bad and hide the
 * real cause. This is the opposite call from `zSensitiveDeserialize`, whose
 * failures really are the payload's fault and so are reported as issues.
 */
export function refineSensitive<C extends SensitivityClass, Input>(
  schema: z.ZodType<SensitiveString<C>, Input>,
  check: SensitiveCheck,
  params?: RefineSensitiveParams
): SensitiveSchema<C, Input> {
  const refined = schema.superRefine((value, ctx) => {
    const rawValue = value.reveal(params?.context);
    const outcome = check(rawValue);

    if (outcome instanceof Promise) {
      return outcome.then((passed) => {
        if (!passed) {
          ctx.addIssue(refinementIssue(params));
        }
      });
    }

    if (!outcome) {
      ctx.addIssue(refinementIssue(params));
    }
    return;
  });

  return withSensitiveMethods(refined);
}

/**
 * Attach `refineSensitive` to a schema this package builds.
 *
 * The method is non-enumerable so that it does not show up when a schema is
 * spread, inspected, or serialized by tooling that walks own properties.
 *
 * @internal
 */
export function withSensitiveMethods<C extends SensitivityClass, Input>(
  schema: z.ZodType<SensitiveString<C>, Input>
): SensitiveSchema<C, Input> {
  const refine: SensitiveSchemaMethods<C, Input>['refineSensitive'] = (check, params) =>
    refineSensitive(schema, check, params);

  Object.defineProperty(schema, 'refineSensitive', {
    value: refine,
    enumerable: false,
    writable: false,
    configurable: true,
  });

  return schema as SensitiveSchema<C, Input>;
}
