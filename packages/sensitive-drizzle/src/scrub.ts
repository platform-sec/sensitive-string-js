import type { ScrubPolicy } from '@platform-sec/sensitive-string-scrub';

/**
 * A `sensitive-scrub` policy fragment for Drizzle's query errors.
 *
 * The measurement behind it: `DrizzleQueryError` holds `params`, an own
 * enumerable array of the bound values, which are the revealed plaintext by the
 * time the statement runs. An error tracker serialises own enumerable
 * properties, so the values arrive at the sink intact. This is the same
 * structural shape the TypeORM integration found on `parameters` and the Redis
 * one on a command's `args`, reaching the same place.
 *
 * `sensitive-scrub` does not cover it at its defaults: the value is a correct
 * plaintext string in a property nobody told the scrubber about. A companion
 * test asserts the default policy still misses it, so the day the defaults grow
 * a rule that catches it, the test fails and this fragment retires.
 *
 * The fragment is not a substitute for `sanitizeQueryError()`, and the reason
 * is `message`. Drizzle interpolates the parameters into the message it builds,
 * and V8 bakes that message into `stack`; a key-based scrubber that denied
 * `message` and `stack` would remove the two fields that make an error report
 * worth having. `sanitizeQueryError()` rewrites those two in place, which a
 * scrub policy cannot do, and this fragment covers the structured copy for the
 * errors that never went through it.
 *
 * `query` is here because a statement built by `sql.raw()` can hold a literal
 * that never was a parameter. `cause` is here whole rather than by its
 * interesting properties, because Postgres puts the conflicting value in its
 * `detail` for several constraint classes and each driver names its own fields
 * differently.
 *
 * Everything is a key rather than a path, deliberately. `denyPaths` matches
 * whole dotted paths from the payload root, and a captured error sits at
 * whatever depth the SDK put it. A key matches at any depth, which is the only
 * thing that works for a value carried inside an error.
 *
 * `query` and `cause` are the broad entries, since they match at any depth like
 * the others. Undo either through the mechanism `sensitive-scrub` already has:
 *
 * ```ts
 * mergeScrubPolicy(drizzleScrubFragment, {
 *   allowKeys: [{ key: 'query', reason: 'GraphQL document, no database statement here' }],
 * });
 * ```
 *
 * @example
 * ```ts
 * import { mergeScrubPolicy } from '@platform-sec/sensitive-string-scrub';
 * import { drizzleScrubFragment } from '@platform-sec/sensitive-string-drizzle';
 *
 * const policy = mergeScrubPolicy(myPolicy, drizzleScrubFragment);
 * ```
 */
export const drizzleScrubFragment: ScrubPolicy = {
  denyKeys: ['params', 'query', 'cause'],
};
