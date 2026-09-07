import type { SensitivityClass } from '@platform-sec/sensitive-string-core';
import { DrizzleConfigError } from './errors.js';
import type { SensitiveColumnOptions, SensitiveVarcharOptions } from './types.js';

/**
 * Split the two-or-three argument form the column factories accept.
 *
 * `sensitiveText('email')`, `sensitiveText('email', 'credential')`,
 * `sensitiveText('email', { label: 'e' })` and
 * `sensitiveText('email', 'credential', { label: 'e' })` all reach the same
 * place. The two-argument-with-a-class form is the one the roadmap uses; the
 * options form is the one the design document uses; both are shipped rather
 * than one being chosen, because they say different things and neither is
 * shorthand for the other.
 */
export function splitArgs<C extends SensitivityClass, O extends SensitiveColumnOptions>(
  fallbackClass: C,
  klassOrOptions: C | O | undefined,
  maybeOptions: O | undefined
): { klass: C; options: O } {
  if (typeof klassOrOptions === 'string') {
    return { klass: klassOrOptions, options: maybeOptions ?? ({} as O) };
  }
  if (klassOrOptions !== undefined && maybeOptions !== undefined) {
    throw new DrizzleConfigError(
      `A sensitive column was given options twice. Pass the sensitivity class as the second ` +
        `argument and the options as the third, or the options alone as the second.`
    );
  }
  return { klass: fallbackClass, options: klassOrOptions ?? maybeOptions ?? ({} as O) };
}

/**
 * `varchar(n)` when a length was given, a bare `varchar` when it was not.
 *
 * A classified column's SQL type is a standard one, which is what keeps
 * `drizzle-kit generate` producing ordinary migrations: the classification
 * lives in the TypeScript schema and leaves no trace in the database.
 */
export function varcharType(options: SensitiveVarcharOptions): string {
  const { length } = options;
  if (length === undefined) return 'varchar';
  if (!Number.isInteger(length) || length <= 0) {
    throw new DrizzleConfigError(
      `A sensitive varchar column was given length ${String(length)}. A varchar length must be ` +
        `a positive integer.`
    );
  }
  return `varchar(${String(length)})`;
}
