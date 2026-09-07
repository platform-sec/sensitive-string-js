import { sanitizeQueryError as sanitize } from '@platform-sec/sensitive-string-data';
import type { SanitizeShape } from '@platform-sec/sensitive-string-data';

/** What a redacted parameter is replaced with on an error object. */
export const ERROR_PARAMETER_CENSOR = '[REDACTED:drizzle-parameter]';

/** What the rebuilt message says in place of the parameters. */
const MESSAGE_CENSOR = '[REDACTED:drizzle-parameters]';

/** Where Drizzle's message stops being the statement and starts being values. */
const PARAMS_MARKER = '\nparams: ';

/**
 * The message Drizzle built, with the parameters taken back out.
 *
 * `DrizzleQueryError` composes its message as `Failed query: ${query}\nparams:
 * ${params}`, and template interpolation of an array is `Array.prototype.join`,
 * so a one-parameter statement puts the bare revealed value in the message.
 * This is the difference from the equivalent problem in TypeORM, where the
 * plaintext is only a structured property: here it is in the string that goes
 * into every stack trace, every `console.error` and every error tracker that
 * only reads `message`.
 *
 * The query half is kept. It is the statement Drizzle built, with `$1`
 * placeholders rather than values, and it is what makes the error useful.
 */
function sanitizedMessage(message: string): string | undefined {
  // The first occurrence, not the last: a statement holding the marker as text
  // truncates the message early, which loses part of the query and keeps none
  // of the values.
  const at = message.indexOf(PARAMS_MARKER);
  if (at === -1) return undefined;
  return `${message.slice(0, at)}${PARAMS_MARKER}${MESSAGE_CENSOR}`;
}

/**
 * How Drizzle's query error is recognised and what is taken out of it.
 *
 * Structural rather than `instanceof`, because the root entry point of this
 * package imports no `drizzle-orm` at runtime, and because an application with
 * two copies of the ORM in its graph would fail an `instanceof` against the
 * wrong one at exactly the moment it mattered.
 */
const DRIZZLE_QUERY_ERROR: SanitizeShape = {
  name: 'DrizzleQueryError',
  identifyBy: ['query', 'params'],
  parameterKeys: ['params'],
  censor: ERROR_PARAMETER_CENSOR,
  sanitizeMessage: sanitizedMessage,
  stackMarker: PARAMS_MARKER,
  stackWithheld: '    at <stack withheld: it carried the query parameters>',
  fallbackMessage:
    'A Drizzle query failed and its error could not be sanitized, so neither its message nor ' +
    'its parameters are reproduced here.',
};

/**
 * Remove the revealed parameters from a Drizzle query error.
 *
 * `DrizzleQueryError` is thrown for every failing statement on every dialect,
 * and it carries the bound parameters three times: as `params`, an own
 * enumerable property; interpolated into `message`; and in the header of
 * `stack`, which V8 composes once at construction so that reassigning the
 * message afterwards does not move it. By the time the error exists the
 * parameters are the revealed plaintext, because that is what was sent. All
 * three copies are removed; `query`, `cause`, `name` and the frames are kept.
 *
 * A `cause` is left alone. It is the driver's own error, and what a driver puts
 * in it varies: Postgres reports the conflicting value in `detail` for several
 * constraint classes. That is what the scrub fragment covers, on the way out to
 * an error tracker, rather than being guessed at here.
 *
 * Never throws, works through property descriptors so a getter that throws is
 * never invoked, redacts in place where the property allows it and falls back
 * to a copy with the same prototype where it does not. The mechanics are
 * `sensitive-data`'s, shared with the other ORM packages; what is Drizzle's own
 * is the shape above.
 *
 * It has to be called. A `catch` block, or a framework's error filter, is where
 * it goes.
 *
 * @example
 * ```ts
 * try {
 *   await db.insert(users).values(row);
 * } catch (error) {
 *   throw sanitizeQueryError(error);
 * }
 * ```
 */
export function sanitizeQueryError(error: unknown): unknown {
  return sanitize(error, DRIZZLE_QUERY_ERROR);
}
