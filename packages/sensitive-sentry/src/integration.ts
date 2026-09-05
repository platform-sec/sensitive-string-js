import * as Sentry from '@sentry/node';
import type { Breadcrumb, Event, NodeOptions } from '@sentry/node';
import {
  guardedScrub,
  mergeReports,
  type ResolvedScrubPolicy,
} from '@platform-sec/sensitive-string-scrub';

import { buildEventStub, tagEvent } from './stub.js';

export const INTEGRATION_NAME = 'SensitiveScrubbing';

/**
 * The SDK's integration type, read off the option that takes them.
 *
 * `@sentry/node` re-exports its integration factories but not the
 * `Integration` interface itself, which lives in `@sentry/core`. Deriving it
 * from `NodeOptions` keeps `@sentry/core` out of this package's dependencies
 * and keeps the type tied to the option it has to satisfy.
 */
export type SentryIntegration = Extract<
  NonNullable<NodeOptions['integrations']>,
  readonly unknown[]
>[number];

/**
 * The integration that puts the scrubber last among the event processors.
 *
 * Two ordering bugs are available on day one to anyone told to "add this
 * integration", and both are closed by the same measurement.
 *
 * An integration's `processEvent` runs in registration order, so a scrubber
 * written as a `processEvent` is only as early or as late as the user's array
 * puts it. Measured on `@sentry/node` 10.73.0: an integration listed before
 * `extraErrorDataIntegration()` does not see the `contexts.<ErrorName>` that
 * integration writes, and one listed after does. Since that context is exactly
 * where a custom property on a thrown error lands, raw values included, a
 * scrubber that runs too early misses the position most worth covering.
 *
 * A scope event processor, though, runs after every integration's
 * `processEvent`, and an integration can register one from its own `setup()`.
 * Measured: an integration listed first, registering a processor from
 * `setup()`, still sees `contexts.Error`. So the scrubber takes the last
 * position regardless of where the user's array puts the integration that
 * installed it.
 *
 * The event processor is also the seam that still holds live `SensitiveString`
 * instances. By `beforeSend` the SDK has normalized the event through its JSON
 * form and every instance is already the string its `toJSON()` produced, which
 * is safe but leaves stage 1 nothing to act on there.
 */
export function sensitiveScrubbingIntegration(policy: ResolvedScrubPolicy): SentryIntegration {
  const scrub = guardedScrub<Event>({ kind: 'event', policy, stub: buildEventStub });

  // The breadcrumbs on an event have already been through this package's own
  // `beforeBreadcrumb`, where stage 1 wrote a marker everywhere a wrapped value
  // stood. A marker sighting is meant to be evidence that some *other*
  // integration sent a placeholder where a value belonged, so counting these
  // would have the package manufacturing that evidence about itself: measured,
  // two breadcrumbs each holding one wrapped value produced
  // `sensitive.marker_seen: 2` on an event that had no marker of its own.
  //
  // The pass is kept rather than dropped, because it is what catches a
  // breadcrumb an event processor registered before this one added straight to
  // `event.breadcrumbs`, which never went through `addBreadcrumb`. It reports
  // nothing on its own, and `mergeReports` folds its classes and denied keys
  // into the event's report while leaving the marker count alone.
  //
  // `onScrub` is dropped rather than suppressed with `reportSuccess` alone.
  // Invariant 18 is one report per payload including on the failure path, and
  // the failure path of `guardedScrub` reports whatever `reportSuccess` says,
  // so a breadcrumb region that threw would have produced a second call for the
  // same event. `mergeReports` carries `failed` into the event's own report,
  // which is where a caller learns about it.
  const scrubCrumbs = guardedScrub<Breadcrumb[] | undefined>({
    kind: 'breadcrumb',
    policy: { ...policy, onMarker: 'ignore', onScrub: undefined },
    stub: () => [],
    reportSuccess: false,
  });

  return {
    name: INTEGRATION_NAME,
    setup() {
      Sentry.addEventProcessor((event) => {
        // `Event` is a plain object, so the breadcrumbs can be lifted out and
        // put back. `exactOptionalPropertyTypes` is on, so an event that never
        // had the key must not come back carrying it as undefined.
        const { breadcrumbs, ...rest } = event;
        const { payload, report } = scrub(rest);
        const crumbs = scrubCrumbs(breadcrumbs);

        if (payload === null) {
          return tagEvent(payload, report, policy);
        }

        const reassembled =
          crumbs.payload === undefined
            ? payload
            : ({ ...payload, breadcrumbs: crumbs.payload } as Event);

        return tagEvent(reassembled, mergeReports(report, crumbs.report), policy);
      });
    },
  };
}
