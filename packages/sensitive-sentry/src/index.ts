/**
 * @platform-sec/sensitive-string-sentry
 *
 * Scrubbing for `@sentry/node`, at every seam the SDK offers rather than the
 * one that is famous.
 *
 * The leak this closes is not unredacted `SensitiveString` instances. Measured
 * on `@sentry/node` 10.73.0 at stock defaults, with no `sendDefaultPii` and no
 * `dataCollection`, a single inbound request puts this in the outgoing event:
 *
 * ```
 * request.headers.authorization  "Bearer LEAKED_SECRET_abc123xyz"
 * request.headers.cookie         "session=LEAKED_SECRET_abc123xyz"
 * request.cookies.session        "LEAKED_SECRET_abc123xyz"
 * request.url                    "http://127.0.0.1:8080/pay?token=LEAKED_SECRET_abc123xyz"
 * request.query_string           "token=LEAKED_SECRET_abc123xyz"
 * ```
 *
 * The application never wrapped any of it, so there is no `SensitiveString`
 * anywhere in that event and nothing for the library to redact. The bearer
 * token left the process because an error happened.
 *
 * @example
 * ```ts
 * import * as Sentry from '@sentry/node';
 * import { withSensitiveScrubbing } from '@platform-sec/sensitive-string-sentry';
 *
 * Sentry.init(
 *   withSensitiveScrubbing(
 *     { dsn: process.env.SENTRY_DSN },
 *     { denyKeys: ['x-internal-signature'] }
 *   )
 * );
 * ```
 *
 * @packageDocumentation
 */

export {
  COVERED_HOOKS,
  SentryScrubbingError,
  isApplied,
  withSensitiveScrubbing,
} from './install.js';
export { INTEGRATION_NAME, sensitiveScrubbingIntegration } from './integration.js';
export { TIGHTENED_CATEGORIES, recommendedDataCollection } from './collection.js';
export { SENTRY_DENY_PATHS, SENTRY_POLICY, SENTRY_URL_KEYS } from './paths.js';
export {
  CLASSES_TAG,
  LABELS_TAG,
  MARKER_CLASSES_TAG,
  MARKER_TAG,
  SCRUB_FAILED_TAG,
} from './stub.js';

// Re-exported so a caller configures the policy without a second install.
export type { ScrubPolicy, ScrubReport, PayloadKind } from '@platform-sec/sensitive-string-scrub';
