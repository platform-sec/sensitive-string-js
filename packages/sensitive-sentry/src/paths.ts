import type { ScrubPolicy } from '@platform-sec/sensitive-string-scrub';

/**
 * Where Sentry puts things.
 *
 * The shared layer owns the key names and the walk. This file is the part that
 * cannot be shared, because it is knowledge of one vendor's payload shape, and
 * it is the whole of what the division in the design's section 2.1 assigns to
 * a vendor package.
 *
 * Measured on `@sentry/node` 10.73.0 against a capturing transport, with the
 * request data integration installed and stock `dataCollection`:
 *
 * ```
 * request.headers.authorization  "Bearer LEAKED_SECRET_abc123xyz"
 * request.headers.cookie         "session=LEAKED_SECRET_abc123xyz"
 * request.cookies.session        "LEAKED_SECRET_abc123xyz"
 * request.url                    "http://127.0.0.1:8080/pay?token=LEAKED_SECRET_abc123xyz&page=2"
 * request.query_string           "token=LEAKED_SECRET_abc123xyz&page=2"
 * request.data.rawToken          "LEAKED_SECRET_abc123xyz"
 * ```
 *
 * The header, cookie and body rows are closed by key name, which the shared
 * denylist already carries. The two URL rows are what this file adds.
 */

/**
 * Positions holding a URL or a query string.
 *
 * Deleting a URL from an error event removes most of its value, so these are
 * rewritten rather than censored: the denied query parameters are replaced and
 * the route survives.
 *
 * `url` and `http.url` are terminal key names rather than paths, because a
 * breadcrumb's URL lives at `breadcrumbs[n].data.url` and a span attribute is
 * one key that happens to contain a dot.
 */
export const SENTRY_URL_KEYS: readonly string[] = [
  'request.url',
  'request.query_string',
  'url',
  'http.url',
  'http.request.url',
];

/**
 * Paths whose whole subtree goes, regardless of the key names inside it.
 *
 * `request.cookies` is the parsed cookie object. Every value in it is a cookie
 * value, and the names are the application's, so no key list describes them.
 * The shared defaults already carry this path, seeded from Rollbar's
 * `requestScrubFields`, which by coincidence rather than agreement is also
 * Sentry's shape. Repeating it here is deliberate: it is Sentry's shape
 * because this file says so, not because another vendor's default happens to
 * match.
 */
export const SENTRY_DENY_PATHS: readonly string[] = ['request.cookies'];

/**
 * The policy this package contributes before the caller's own is merged in.
 */
export const SENTRY_POLICY: ScrubPolicy = {
  denyPaths: SENTRY_DENY_PATHS,
  urlKeys: SENTRY_URL_KEYS,
};
