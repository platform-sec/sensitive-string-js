import type { ScrubPolicy } from '@platform-sec/sensitive-string-scrub';

/**
 * Where Rollbar puts things.
 *
 * This is the thinnest of the vendor packages, and the README says so rather
 * than manufacturing value. Rollbar 3.1.0 ships the best defaults of the three
 * vendors measured: 25 `scrubFields`, 10 `scrubHeaders`, a query-parameter pass
 * over URLs, and a `scrubPaths` option for payload paths. Measured, its own
 * scrub transform runs *before* the user's `transform`, so by the time this
 * package's seam sees the payload the vendor has already censored every name it
 * knows.
 *
 * What is left is real, and it is what this file describes. Measured on Node
 * 22.15.0 against `rollbar` 3.1.0, driving the real SDK to an HTTP server on
 * loopback with stock scrubbing:
 *
 * ```
 * custom.wire.value          "LEAKED_SECRET_abc123xyz"    a serialize() result
 * custom.wrapped             { klass: 'credential', label: 'stripe-key' }
 * ```
 *
 * The first is the shape no key list closes and structural redaction exists
 * for. The second is this vendor's own flattening, and `flattened.ts` is what
 * it takes.
 */

/**
 * Positions holding a URL, a path with a query, or a bare query string.
 *
 * Shorter than the other vendors' lists, because Rollbar already scrubs query
 * parameters by name inside `request.url` and `request.query_string`. These are
 * the ones its own pass does not reach: telemetry entries carry a `url`, and a
 * custom field named for one is the application's own.
 */
export const ROLLBAR_URL_KEYS: readonly string[] = ['url', 'href', 'referer'];

/**
 * Paths whose whole subtree goes.
 *
 * Rollbar's `requestScrubFields` is path-shaped and it applies these itself,
 * through `scrubPaths`, when a caller passes them. It does not apply them by
 * default: measured, `scrubPaths` resolves to `undefined` on a stock client, so
 * the list Rollbar ships as `requestScrubFields` is documentation rather than a
 * default. `withSensitiveScrubbing` passes them, which is one of the few places
 * this package tightens the vendor rather than adding beside it.
 */
export const ROLLBAR_DENY_PATHS: readonly string[] = [
  'request.session.csrf',
  'request.session._csrf',
  'request.params._csrf',
  'request.cookie',
  'request.cookies',
];

/**
 * Regions Rollbar assembles after this package's seam has run.
 *
 * Not a policy entry, and not scrubbable: `addConfiguredOptions` and
 * `addDiagnosticKeys` are the two transforms after `userTransform`, measured,
 * and they write `notifier.configured_options` and `notifier.diagnostic`. The
 * second carries the original error's message and stack verbatim. Neither
 * carries anything the application captured that is not already in the body,
 * and the README says both are outside what this package can reach.
 */
export const ROLLBAR_UNREACHABLE_PATHS: readonly string[] = [
  'notifier.configured_options',
  'notifier.diagnostic',
];

/** The policy this package contributes before the caller's own is merged in. */
export const ROLLBAR_POLICY: ScrubPolicy = {
  denyPaths: ROLLBAR_DENY_PATHS,
  urlKeys: ROLLBAR_URL_KEYS,
};
