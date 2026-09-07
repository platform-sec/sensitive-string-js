import { sanitizeQueryError } from '@platform-sec/sensitive-string-data';
import type { SanitizeShape } from '@platform-sec/sensitive-string-data';

/** What a redacted parameter is replaced with on an error object. */
export const ERROR_PARAMETER_CENSOR = '[REDACTED:typeorm-parameter]';

/**
 * How TypeORM's query error is recognised and what is taken out of it.
 *
 * Structural rather than `instanceof`, because this package imports no
 * `typeorm` at runtime, and because an application with two copies of the ORM
 * in its graph would fail an `instanceof` against the wrong one at exactly the
 * moment it mattered.
 *
 * No `sanitizeMessage`, and that is a measurement rather than an omission.
 * TypeORM does not interpolate the parameters into the message the way Drizzle
 * does: the plaintext is a structured property only. Where a driver puts a
 * value into the text, it does so on the nested `driverError`, and Postgres in
 * particular reports the conflicting value in its `detail` for several
 * constraint classes. That is what the scrub fragment covers on the way out to
 * an error tracker.
 */
const TYPEORM_QUERY_ERROR: SanitizeShape = {
  name: 'QueryFailedError',
  identifyBy: ['query', 'parameters'],
  parameterKeys: ['parameters'],
  nestedKeys: ['driverError'],
  censor: ERROR_PARAMETER_CENSOR,
  fallbackMessage: 'A TypeORM query failed and its error could not be sanitized.',
};

/**
 * Remove the revealed parameters from a TypeORM query error.
 *
 * `QueryFailedError` carries `parameters` as an own enumerable property holding
 * the bound values, which by then are the revealed plaintext, on every failing
 * statement on every driver. That is exactly what an error tracker serialises,
 * and it is a structured property rather than a message substring, which makes
 * it both easy to remove and easy to ship by accident. The same property on the
 * nested `driverError` goes with it.
 *
 * Never throws, works through property descriptors so a getter that throws is
 * never invoked, redacts in place where the property allows it and falls back
 * to a copy with the same prototype where it does not, so `instanceof`, `name`,
 * `message` and the stack all survive. If even that fails, a bare `Error`
 * carrying the name is returned rather than the original: an error whose
 * parameters could not be removed is not one to hand onwards.
 *
 * The mechanics are `sensitive-data`'s, shared with the other ORM packages;
 * what is TypeORM's own is the shape above.
 *
 * It has to be called. A `catch` block, or a NestJS exception filter, is where
 * it goes.
 *
 * @example
 * ```ts
 * try {
 *   await repo.insert(row);
 * } catch (error) {
 *   throw sanitizeQueryFailedError(error);
 * }
 * ```
 */
export function sanitizeQueryFailedError(error: unknown): unknown {
  return sanitizeQueryError(error, TYPEORM_QUERY_ERROR);
}
