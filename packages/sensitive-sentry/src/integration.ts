import * as Sentry from '@sentry/node';
import type { Event, NodeOptions } from '@sentry/node';
import { guardedScrub, type ResolvedScrubPolicy } from '@platform-sec/sensitive-string-scrub';

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

  return {
    name: INTEGRATION_NAME,
    setup() {
      Sentry.addEventProcessor((event) => {
        const { payload, report } = scrub(event);

        return tagEvent(payload, report, policy);
      });
    },
  };
}
