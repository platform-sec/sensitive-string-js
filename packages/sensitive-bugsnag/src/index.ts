/**
 * @platform-sec/sensitive-string-bugsnag
 *
 * Scrubbing for `@bugsnag/js`, at every callback the SDK offers and inside its
 * own encoder, rather than at one of the two.
 *
 * The leak this closes is not unredacted `SensitiveString` instances. Measured
 * on Node 22.15.0 against `@bugsnag/js` 8.10.0 at stock settings, driving the
 * real SDK to a local HTTP server standing in for the notify endpoint, this is
 * what left the process:
 *
 * ```
 * request.headers.authorization   "Bearer LEAKED_SECRET_abc123xyz"
 * request.headers.cookie          "session=LEAKED_SECRET_abc123xyz"
 * request.url                     "http://127.0.0.1:8080/pay?token=LEAKED_SECRET_abc123xyz&page=2"
 * response.headers.set-cookie     "s=LEAKED_SECRET_abc123xyz"
 * context                         "/pay?token=LEAKED_SECRET_abc123xyz"
 * user.name                       "LEAKED_SECRET_abc123xyz"
 * metaData.creds.raw_token        "LEAKED_SECRET_abc123xyz"
 * metaData.creds.wire.value       "LEAKED_SECRET_abc123xyz"
 * ```
 *
 * Bugsnag's own `redactedKeys` did catch `password`, which is its entire
 * default list, and it does not apply outside `metaData`, the breadcrumb
 * metadata, `request` and `response` in any case. This package changes that
 * vendor's behaviour more than any other in the repository, and its README says
 * which keys it added and how to take one back.
 *
 * The `metaData.creds.wire.value` row is the one no key list closes: a
 * `serialize()` result is a plain object carrying the raw value by design, and
 * it is what structural redaction is for.
 *
 * @example
 * ```ts
 * import Bugsnag from '@bugsnag/js';
 * import { withSensitiveScrubbing } from '@platform-sec/sensitive-string-bugsnag';
 *
 * Bugsnag.start(
 *   withSensitiveScrubbing(
 *     { apiKey: process.env.BUGSNAG_KEY! },
 *     { denyKeys: ['x-internal-signature'] }
 *   )
 * );
 * ```
 *
 * @packageDocumentation
 */

export {
  COVERED_CALLBACKS,
  EXCLUDED_CALLBACKS,
  BugsnagScrubbingError,
  isApplied,
  withSensitiveScrubbing,
} from './install.js';
export type { BugsnagConfig, Scrubbed } from './install.js';

export {
  BUGSNAG_BODY_PATHS,
  BUGSNAG_DENY_PATHS,
  BUGSNAG_POLICY,
  BUGSNAG_URL_KEYS,
} from './paths.js';

export {
  CLASSES_KEY,
  LABELS_KEY,
  MARKER_CLASSES_KEY,
  MARKER_KEY,
  REPORT_SECTION,
  SCRUB_FAILED_KEY,
  VALUE_SHAPES_KEY,
} from './event.js';

// Re-exported so a caller configures the policy without a second install.
export type {
  PayloadKind,
  ScrubPolicy,
  ScrubReport,
  ValuePatternName,
} from '@platform-sec/sensitive-string-scrub';
