/**
 * @platform-sec/sensitive-string-rollbar
 *
 * Scrubbing for `rollbar`, on top of the best vendor defaults of the three this
 * repository measured.
 *
 * This is a thin package and it should be. Measured on Node 22.15.0 against
 * `rollbar` 3.1.0, driving the real SDK to an HTTP server on loopback with
 * stock settings, the vendor's own scrub already closed the headers, the body
 * keys and the query parameter:
 *
 * ```
 * request.headers.authorization   "********"
 * request.headers.cookie          "********"
 * request.url                     "http://127.0.0.1:8080/pay?token=********&page=2"
 * custom.password                 "********"
 * ```
 *
 * Two things it did not close, and they are what this package is for:
 *
 * ```
 * custom.wire.value      "LEAKED_SECRET_abc123xyz"
 * custom.wrapped         { klass: "credential", label: "stripe-key" }
 * ```
 *
 * The first is a `serialize()` result, whose raw value no key list describes.
 * The second is this vendor flattening a `SensitiveString` into its own
 * enumerable properties instead of honouring `toJSON()`: the value is safe,
 * because it lives in an ES2022 private field, and the label is not.
 *
 * @example
 * ```ts
 * import Rollbar from 'rollbar';
 * import { withSensitiveScrubbing } from '@platform-sec/sensitive-string-rollbar';
 *
 * const rollbar = new Rollbar(
 *   withSensitiveScrubbing(
 *     { accessToken: process.env.ROLLBAR_TOKEN },
 *     { denyKeys: ['x-internal-signature'] }
 *   )
 * );
 * ```
 *
 * @packageDocumentation
 */

export {
  COVERED_SEAMS,
  EXCLUDED_SEAMS,
  REPORT_KEY,
  RollbarScrubbingError,
  isApplied,
  withSensitiveScrubbing,
} from './install.js';
export type { RollbarConfig, Scrubbed } from './install.js';

export {
  ROLLBAR_DENY_PATHS,
  ROLLBAR_POLICY,
  ROLLBAR_UNREACHABLE_PATHS,
  ROLLBAR_URL_KEYS,
} from './paths.js';

export { restoreMarkers } from './flattened.js';
export type { RestoredMarkers } from './flattened.js';

// Re-exported so a caller configures the policy without a second install.
export type {
  PayloadKind,
  ScrubPolicy,
  ScrubReport,
  ValuePatternName,
} from '@platform-sec/sensitive-string-scrub';
