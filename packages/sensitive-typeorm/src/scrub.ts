import type { ScrubPolicy } from '@platform-sec/sensitive-string-scrub';

/**
 * A `sensitive-scrub` policy fragment for TypeORM's query errors.
 *
 * The measurement behind it: `QueryFailedError` holds `parameters`, an own
 * enumerable array of the bound values, which are the revealed plaintext by the
 * time the statement runs. An error tracker serialises own enumerable
 * properties, so the values arrive at the sink intact. This is the same
 * structural shape the Redis integration found on a command's `args`, reaching
 * the same place.
 *
 * `sensitive-scrub` does not cover it at its defaults, for the same reason it
 * did not cover that one: the value is a correct plaintext string in a property
 * nobody told the scrubber about. A companion test asserts the default policy
 * still misses it, so the day the defaults grow a rule that catches it, the
 * test fails and this fragment retires.
 *
 * `query` is here because `Raw()` builds SQL with no binding, so a statement
 * can hold a literal that never was a parameter. `driverError` is here whole
 * rather than by its interesting properties, because Postgres puts the
 * conflicting value in its `detail` for several constraint classes and each
 * driver names its own fields differently; the useful part of it, the SQLSTATE,
 * is mirrored on the `QueryFailedError` itself as `code` and survives.
 *
 * Everything is a key rather than a path, deliberately. `denyPaths` matches
 * whole dotted paths from the payload root, and a captured error sits at
 * whatever depth the SDK put it: `extra.driverError.detail` on one tracker,
 * `exception.values.0.mechanism.data` on another. A key matches at any depth,
 * which is the only thing that works for a value carried inside an error.
 *
 * `query` is the broad entry of the three, since it matches at any depth like
 * the others. Undo just that one through the mechanism `sensitive-scrub`
 * already has:
 *
 * ```ts
 * mergeScrubPolicy(typeormScrubFragment, {
 *   allowKeys: [{ key: 'query', reason: 'GraphQL document, no database statement here' }],
 * });
 * ```
 *
 * @example
 * ```ts
 * import { mergeScrubPolicy } from '@platform-sec/sensitive-string-scrub';
 * import { typeormScrubFragment } from '@platform-sec/sensitive-string-typeorm';
 *
 * const policy = mergeScrubPolicy(myPolicy, typeormScrubFragment);
 * ```
 */
export const typeormScrubFragment: ScrubPolicy = {
  denyKeys: ['parameters', 'query', 'driverError'],
};
