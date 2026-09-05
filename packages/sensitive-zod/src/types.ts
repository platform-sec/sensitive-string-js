/**
 * Shared types for the Zod integration.
 *
 * @packageDocumentation
 */

import type { z } from 'zod';
import type {
  RevealContext,
  SensitiveString,
  SensitivityClass,
} from '@platform-sec/sensitive-string-core';

/**
 * A predicate run against the raw value of an already-wrapped SensitiveString.
 *
 * Returning a promise is supported, but only under `parseAsync`. Zod throws
 * `$ZodAsyncError: Encountered Promise during synchronous parse. Use
 * .parseAsync() instead.` if a promise-returning check is reached from
 * `parse()`, so an async check can never be silently skipped.
 */
export type SensitiveCheck = (rawValue: string) => boolean | Promise<boolean>;

/**
 * Options for `refineSensitive`.
 */
export interface RefineSensitiveParams {
  /**
   * The message attached to the issue when the check fails.
   *
   * It must describe the rule, never the value: this string ends up in a
   * `ZodError` that callers routinely log and return to clients.
   */
  message?: string;
  /** Path appended to the issue, for refinements that report against a nested field. */
  path?: (string | number)[];
  /**
   * Stop parsing after this issue rather than collecting further ones.
   *
   * Zod 4 spells this `continue: false` internally and keeps `fatal` as a
   * documented v3 compatibility path. The name stays here because it is the
   * public API of this package, and a test pins that it still aborts.
   */
  fatal?: boolean;
  /**
   * Reveal context used to read the raw value.
   *
   * Left unset, the check reveals under whatever context is ambient, exactly
   * as a `reveal()` written by hand at the same point would. The refinement
   * deliberately does not manufacture a context of its own: a policy that
   * refuses a context-free reveal must keep refusing here too.
   */
  context?: RevealContext;
}

/**
 * A Zod schema that produces a `SensitiveString` of a known class, carrying the
 * refinement helper that reads the raw value under audit.
 *
 * The declared shape is `z.ZodType` rather than the concrete `z.ZodPipe` the
 * factories build, because the intersection with `SensitiveSchemaMethods` needs
 * a name that does not move when a factory changes how it composes. Naming the
 * pipe would put each factory's internal shape in the public type.
 *
 * `refineSensitive` is attached to the schemas this package builds. Standard Zod
 * combinators (`.optional()`, `.array()`, `.default()`) return plain Zod schemas
 * and drop it; apply refinements before those, or call the standalone
 * {@link refineSensitive} function.
 */
export type SensitiveSchema<C extends SensitivityClass, Input = string> = z.ZodType<
  SensitiveString<C>,
  Input
> &
  SensitiveSchemaMethods<C, Input>;

/**
 * Methods added to every schema this package builds.
 */
export interface SensitiveSchemaMethods<C extends SensitivityClass, Input> {
  /**
   * Validate the wrapped value against a predicate that receives the raw string.
   *
   * This is a reveal: the ambient `RevealContext` authorizes it and its
   * `auditReveal` hook records it.
   */
  refineSensitive(check: SensitiveCheck, params?: RefineSensitiveParams): SensitiveSchema<C, Input>;
}
