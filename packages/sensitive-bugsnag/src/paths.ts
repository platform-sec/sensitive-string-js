import type { ScrubPolicy } from '@platform-sec/sensitive-string-scrub';

/**
 * Where Bugsnag puts things.
 *
 * The shared layer owns the key names and the walk. This file is the part that
 * cannot be shared, because it is knowledge of one vendor's payload shape.
 *
 * The wire shape is `Event.prototype.toJSON()`, read off `@bugsnag/js` 8.10.0:
 *
 * ```
 * exceptions  app  device  request  response  breadcrumbs  context
 * groupingHash  groupingDiscriminator  metaData  user  session  featureFlags
 * correlation
 * ```
 *
 * Measured on Node 22.15.0 against `@bugsnag/js` 8.10.0, driving the real SDK
 * to a local HTTP server standing in for the notify endpoint, with the stock
 * `redactedKeys` of `['password']`. Every one of these left the process
 * verbatim:
 *
 * ```
 * request.headers.authorization   "Bearer LEAKED_SECRET_abc123xyz"
 * request.headers.cookie          "session=LEAKED_SECRET_abc123xyz"
 * request.url                     "http://127.0.0.1:8080/pay?token=LEAKED_SECRET_abc123xyz&page=2"
 * request.body.api_key            "LEAKED_SECRET_abc123xyz"
 * response.headers.set-cookie     "s=LEAKED_SECRET_abc123xyz"
 * context                         "/pay?token=LEAKED_SECRET_abc123xyz"
 * user.name                       "LEAKED_SECRET_abc123xyz"
 * metaData.creds.raw_token        "LEAKED_SECRET_abc123xyz"
 * metaData.creds.wire.value       "LEAKED_SECRET_abc123xyz"
 * featureFlags[0].variant         "LEAKED_SECRET_abc123xyz"
 * breadcrumbs[0].metaData.refresh_token
 * ```
 *
 * The headers, the body and the metadata keys are closed by key name, which the
 * shared denylist already carries. The URL rows and the wire-format row are
 * what this package adds.
 */

/**
 * Positions holding a URL, a path with a query, or a bare query string.
 *
 * Deleting a URL from an error report removes most of its value, so these are
 * rewritten rather than censored: the denied query parameters are replaced and
 * the route survives.
 *
 * `context` is here because Bugsnag's own documentation recommends setting it
 * to the current route, and a framework middleware that sets it from the
 * request URL carries the query string with it. Measured: it does, and nothing
 * in the SDK scrubs it.
 *
 * `url` covers a breadcrumb's metadata and the `request.url` of a client
 * plugin, both of which are one key rather than a path.
 */
export const BUGSNAG_URL_KEYS: readonly string[] = ['request.url', 'url', 'context', 'referer'];

/**
 * Paths whose whole subtree goes, regardless of the key names inside it.
 *
 * Deliberately short. Bugsnag assembles no parsed cookie object of its own, so
 * the equivalent of Sentry's `request.cookies` does not exist here, and the
 * `cookie` header is caught by name.
 */
export const BUGSNAG_DENY_PATHS: readonly string[] = ['request.cookies'];

/**
 * Request and response bodies, for a caller who wants them gone rather than
 * scrubbed by key name.
 *
 * Not on by default, and the argument is the one Q4 of the design makes about
 * Sentry's `httpBodies`: a body is arbitrary application shape, and a key
 * denylist over an arbitrary shape is weaker than not collecting it. Sentry
 * offers a collection switch and this package recommends turning it off there.
 * Bugsnag has no such switch, because the application or its framework plugin
 * is what puts a body on the event in the first place, so the only lever here
 * is a path denial and the honest place for it is the caller's own config:
 *
 * ```ts
 * withSensitiveScrubbing(config, { denyPaths: [...BUGSNAG_BODY_PATHS] })
 * ```
 *
 * Silently censoring a body from inside a scrubbing package would empty out
 * most of what makes a 400 report actionable, and a user who found their
 * reports emptier than expected must be able to find the line that did it in
 * their own code.
 */
export const BUGSNAG_BODY_PATHS: readonly string[] = ['request.body', 'response.body'];

/** The policy this package contributes before the caller's own is merged in. */
export const BUGSNAG_POLICY: ScrubPolicy = {
  denyPaths: BUGSNAG_DENY_PATHS,
  urlKeys: BUGSNAG_URL_KEYS,
};
