/**
 * @platform-sec/sensitive-string-scrub
 *
 * The shared layer under the error tracking and APM integrations: one payload
 * walk, one denylist, one never-throw contract, so five vendor packages do not
 * grow five denylists that disagree.
 *
 * The leak these packages exist for is not unredacted `SensitiveString`
 * instances. Measured across `@sentry/node` 10.73.0, `@bugsnag/js` 8.10.0 and
 * `rollbar` 3.1.0, a wrapped value is already safe on every path tested,
 * because each vendor's terminal serialization honours `toJSON()`. The leak is
 * the raw strings nobody wrapped, sitting beside the wrapped ones: an
 * `authorization` header, a `cookie`, and a `token` query parameter, captured
 * verbatim at stock defaults because an error happened.
 *
 * Three stages:
 *
 * 1. Structural redaction, over `redactCopy`. Defence in depth, and the only
 *    defence for a `serialize()` result, which is the one shape `toJSON()`
 *    cannot save.
 * 2. The key and path denylist. This is the stage that closes the measured
 *    leak.
 * 3. Seam coverage, which is not a transform but the vendor suite's assertion
 *    that stages 1 and 2 ran on every payload shape the SDK can emit.
 *
 * @example
 * ```ts
 * import { resolveScrubPolicy, guardedScrub } from '@platform-sec/sensitive-string-scrub';
 *
 * const policy = resolveScrubPolicy({ denyKeys: ['x-internal-signature'] });
 * const scrub = guardedScrub({ kind: 'event', policy, stub: buildStub });
 *
 * const safe = scrub(event);
 * ```
 *
 * @packageDocumentation
 */

export type {
  PayloadKind,
  ScrubAllowance,
  ScrubPolicy,
  ScrubReport,
  ResolvedScrubPolicy,
} from './types.js';

export {
  DEFAULT_CENSOR,
  ScrubPolicyError,
  mergeScrubPolicy,
  resolveScrubPolicy,
} from './policy.js';

export {
  DEFAULT_DENY_KEYS,
  DEFAULT_DENY_PATHS,
  ROLLBAR_REPRODUCED,
  denied,
  isUrlPosition,
  pathDenied,
  scrubUrl,
} from './deny.js';

export { failedReport, scrubPayload } from './walk.js';

export { composeAfter, guardedScrub } from './failure.js';
export type { GuardedResult, GuardedScrubOptions, StubBuilder } from './failure.js';
