import { failedReport, scrubPayload } from './walk.js';
import type { PayloadKind, ResolvedScrubPolicy, ScrubReport } from './types.js';

/**
 * The never-throw contract.
 *
 * Measured on `@sentry/node` 10.73.0: a `beforeSend` that throws drops the
 * original event and sends a replacement event describing the scrubber's own
 * exception, and `captureException` does not throw to the caller. That is
 * fail-closed on content, which is right, and a bad outcome anyway. The error
 * the user needed to see is gone, the alert that fires names the scrubber, and
 * the behaviour is one vendor's internals rather than a contract another
 * vendor shares.
 *
 * So no hook body here throws. On an internal failure the payload is replaced
 * by a stub the vendor package builds: enough to know an error of this shape
 * happened, and nothing that was in it. The signal survives, the payload does
 * not.
 *
 * The stub is not the same as returning null. Returning null tells the vendor
 * the payload was deliberately discarded and it is counted as a client-side
 * drop. Losing the error entirely is the outcome this file exists to avoid.
 */

/**
 * How a vendor package builds its minimal replacement payload.
 *
 * Returning `null` drops the payload, which is the right answer for a kind
 * whose loss carries no information: a span, a log line or a metric that goes
 * missing is indistinguishable from one that was sampled away. A stub is worth
 * building where the loss does carry information, which is an error report and
 * the position of a breadcrumb in a timeline. The vendor package decides per
 * kind, because only it knows which of its payloads the SDK will even accept a
 * `null` for.
 */
export type StubBuilder<P> = (payload: P, error: unknown) => P | null;

export interface GuardedScrubOptions<P> {
  readonly kind: PayloadKind;
  readonly policy: ResolvedScrubPolicy;
  /**
   * Builds the replacement payload when scrubbing throws. Must not itself
   * reach into the payload for anything but a type, a grouping hash, and a
   * message it has censored.
   */
  readonly stub: StubBuilder<P>;
  /**
   * Whether a successful scrub calls `onScrub`. Default true.
   *
   * A vendor may run the scrubber at more than one seam over the same
   * payload: one that sees it first and reports, and a backstop that catches
   * whatever a later hook added. Only the reporting seam calls `onScrub`, so
   * a report still means one payload. A failure reports from either, because
   * a scrubber broken on one shape is a bug worth an alert wherever it breaks.
   */
  readonly reportSuccess?: boolean;
}

/** What a guarded scrub produced, and what was in the payload. */
export interface GuardedResult<P> {
  /**
   * The scrubbed payload, the stub when scrubbing threw, or `null` when the
   * stub threw as well. Only the last case drops the payload, and it means two
   * independent failures.
   */
  readonly payload: P | null;
  readonly report: ScrubReport;
}

/**
 * Wrap `scrubPayload` so the hook it is installed in cannot throw.
 *
 * The report comes back rather than only reaching `onScrub`, because a vendor
 * package turns it into metadata on the payload it is about to send and
 * `onScrub` belongs to the caller.
 */
export function guardedScrub<P>({
  kind,
  policy,
  stub,
  reportSuccess = true,
}: GuardedScrubOptions<P>) {
  return (payload: P): GuardedResult<P> => {
    try {
      const { payload: scrubbed, report } = scrubPayload(payload, policy, kind);

      if (reportSuccess) {
        reportScrub(policy, report);
      }

      return { payload: scrubbed as P, report };
    } catch (error) {
      return recover(payload, error, kind, policy, stub);
    }
  };
}

function recover<P>(
  payload: P,
  error: unknown,
  kind: PayloadKind,
  policy: ResolvedScrubPolicy,
  stub: StubBuilder<P>
): GuardedResult<P> {
  const report = failedReport(kind, policy);

  reportScrub(policy, report);

  try {
    return { payload: stub(payload, error), report };
  } catch {
    // Scrubbing failed and so did describing the failure. There is no payload
    // left that anything has vouched for, so nothing is sent. This is the one
    // path that loses the report, and it takes two independent bugs.
    return { payload: null, report };
  }
}

/**
 * Call `onScrub`, and swallow what it throws.
 *
 * Invariant 10 is that no hook body throws, and a reporting callback is inside
 * the hook body. A failure here is also the one failure with nowhere to go:
 * reporting that the reporter threw would call the reporter.
 *
 * Exported because `guardedScrub` does not fit every vendor. A vendor whose
 * callback contract is "mutate the payload you were given and return a
 * boolean", which is Bugsnag's, has no replacement payload to hand back and
 * runs its own guard; it still has to report the same way, and one swallow rule
 * is better than two.
 */
export function reportScrub(policy: ResolvedScrubPolicy, report: ScrubReport): void {
  if (policy.onScrub === undefined) {
    return;
  }

  try {
    policy.onScrub(report);
  } catch {
    // Deliberately empty. See above.
  }
}

/**
 * Compose a user-supplied hook behind a scrubbing hook.
 *
 * The user's hook runs after the scrubber, on the already-scrubbed payload, so
 * a hook that adds context cannot add it behind the scrubber's back. A user
 * hook returning null or undefined still drops the payload, which is the
 * vendor's own contract and not something to paper over. A user hook that
 * throws is caught here, because a hook body that throws is the failure this
 * file exists to prevent, and the scrubbed payload is sent without whatever
 * the user's hook meant to add.
 */
export function composeAfter<P, R>(
  scrub: (payload: P) => P | null,
  user: ((payload: P, hint: R) => P | null | undefined | PromiseLike<P | null>) | undefined
): (payload: P, hint: R) => P | null | PromiseLike<P | null> {
  return (payload, hint) => {
    const scrubbed = scrub(payload);

    if (scrubbed === null || user === undefined) {
      return scrubbed;
    }

    try {
      const result = user(scrubbed, hint);

      // `beforeSend` may return a promise, so a hook can also fail by
      // rejecting. A rejection reaches the SDK as a dropped payload, which is
      // the outcome the try/catch above exists to prevent, and a synchronous
      // catch does not see it.
      if (isThenable<P>(result)) {
        return Promise.resolve(result).then(
          (resolved) => resolved ?? null,
          () => scrubbed
        );
      }

      return result ?? null;
    } catch {
      return scrubbed;
    }
  };
}

function isThenable<P>(value: unknown): value is PromiseLike<P | null | undefined> {
  return (
    value !== null &&
    typeof value === 'object' &&
    typeof (value as PromiseLike<unknown>).then === 'function'
  );
}
