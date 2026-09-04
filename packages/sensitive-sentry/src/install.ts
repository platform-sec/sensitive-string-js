import type { NodeOptions } from '@sentry/node';
import {
  DEFAULT_CENSOR,
  composeAfter,
  guardedScrub,
  mergeScrubPolicy,
  resolveScrubPolicy,
  type PayloadKind,
  type ResolvedScrubPolicy,
  type ScrubPolicy,
} from '@platform-sec/sensitive-string-scrub';

import {
  INTEGRATION_NAME,
  sensitiveScrubbingIntegration,
  type SentryIntegration,
} from './integration.js';
import { SENTRY_POLICY } from './paths.js';
import {
  SCRUB_FAILED_TAG,
  type SentrySpan,
  buildBreadcrumbStub,
  buildEventStub,
  buildSpanStub,
  dropPayload,
} from './stub.js';

/**
 * Every `before*` option `@sentry/node` 10.73.0 declares.
 *
 * `seams.test-d.ts` asserts, at the type level against the SDK's own
 * `NodeOptions`, that this list is neither missing a hook nor naming one the
 * SDK does not have. A seventh hook in a future SDK minor fails compilation of
 * the test suite with the new hook's name in the failure, which is worth more
 * than any runtime assertion because it fires on `pnpm update` rather than on
 * the first event that uses the new path.
 *
 * Two of the six arrived after the others, and the shipped declarations still
 * carry deprecated `beforeSendMetric` and `enableMetrics` copies inside
 * `_experiments` pointing at the top-level options that replaced them. A
 * package that covers the seams which existed when it was written and is then
 * installed against a newer SDK covers less than it claims and says nothing
 * about it. That is the failure mode the type check exists for.
 */
export const COVERED_HOOKS = [
  'beforeSend',
  'beforeSendTransaction',
  'beforeSendSpan',
  'beforeSendLog',
  'beforeSendMetric',
  'beforeBreadcrumb',
] as const;

/**
 * Which payload kind each hook carries, and what a failed scrub leaves behind.
 *
 * The failure behaviour is per kind because the SDK's tolerance for a dropped
 * payload is per kind, measured on `@sentry/node` 10.73.0:
 *
 * | Hook | `null` accepted | Failure behaviour |
 * |---|---|---|
 * | `beforeSend` | yes | Stub, because losing an error is what 2.6 exists to avoid |
 * | `beforeBreadcrumb` | yes | Stub, so the timeline keeps its position |
 * | `beforeSendSpan` | **no** | Stub, and see below |
 * | `beforeSendTransaction` | yes, silently | Drop |
 * | `beforeSendLog` | yes, with an outcome recorded | Drop |
 * | `beforeSendMetric` | yes, with an outcome recorded | Drop |
 *
 * A span cannot be dropped. Returning `null` logs "Returning null from
 * `beforeSendSpan` is disallowed" and then pushes the original, unscrubbed span
 * into the envelope, so `null` on this hook is a fail-open path and never
 * appears here.
 *
 * A transaction, log or metric is dropped rather than stubbed because a stub
 * would have to be a valid payload of that shape and a malformed one is worse
 * than an absent one. Losing one is what sampling already does routinely, and
 * the failure is still reported through `onScrub`.
 */
const HOOK_SPECS = {
  beforeSend: { kind: 'event', stub: buildEventStub },
  beforeSendTransaction: { kind: 'transaction', stub: dropPayload },
  beforeSendSpan: { kind: 'span', stub: buildSpanStub },
  beforeSendLog: { kind: 'log', stub: dropPayload },
  beforeSendMetric: { kind: 'metric', stub: dropPayload },
  beforeBreadcrumb: { kind: 'breadcrumb', stub: buildBreadcrumbStub },
} as const satisfies Record<
  (typeof COVERED_HOOKS)[number],
  { kind: PayloadKind; stub: (payload: never, error: unknown) => unknown }
>;

/** Marks an options object this function already produced. */
const APPLIED = Symbol.for('@platform-sec/sensitive-string-sentry.applied');

/** Raised at init for a configuration this package will not scrub around. */
export class SentryScrubbingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SentryScrubbingError';
  }
}

/**
 * Wrap a Sentry options object so every payload the SDK emits is scrubbed.
 *
 * The entry point is an options wrapper rather than an integration because the
 * measurements force it. An integration cannot cover `beforeBreadcrumb`, which
 * is a client option rather than an integration hook, and an integration's own
 * `processEvent` runs wherever the user's array puts it. Both are closed here:
 * the six client hooks are composed at `init`, and the appended integration
 * registers a scope event processor from its `setup()`, which runs after every
 * integration regardless of ordering.
 *
 * A hook the caller supplied is composed, never replaced, and runs after the
 * scrubber on the already-scrubbed payload, so a hook that adds context cannot
 * add it behind the scrubber's back. A caller hook returning null still drops
 * the payload.
 *
 * @param options - The options the caller would have passed to `Sentry.init`
 * @param policy - What to scrub, merged over this package's Sentry-shaped
 *                 defaults and the shared denylist
 * @returns A new options object. The input is not modified.
 *
 * @throws SentryScrubbingError when `sendDefaultPii: true` is set.
 *
 * @example
 * ```ts
 * Sentry.init(
 *   withSensitiveScrubbing(
 *     { dsn: process.env.SENTRY_DSN, beforeSend(event) { return event; } },
 *     { denyKeys: ['x-internal-signature'] }
 *   )
 * );
 * ```
 */
export function withSensitiveScrubbing(
  options: NodeOptions = {},
  policy: ScrubPolicy = {}
): NodeOptions {
  if (isApplied(options)) {
    // Idempotent. Applying twice would wrap each hook twice, which is
    // harmless, and append the integration twice, which is not: the scrubber
    // would run as two scope processors and report every payload twice.
    return options;
  }

  assertNoBlanketPii(options);

  const resolved = resolveScrubPolicy(mergeScrubPolicy(SENTRY_POLICY, policy));

  const wrapped: NodeOptions = {
    ...options,
    integrations: withIntegration(options.integrations, resolved),
    // `beforeSend` is the backstop, not the reporting seam. The integration's
    // scope event processor already scrubbed and reported this event; see
    // `backstop` for why running again is still worth it and why it stays
    // quiet.
    beforeSend: hook(backstop(resolved), 'beforeSend', options.beforeSend, false),
    beforeSendTransaction: hook(resolved, 'beforeSendTransaction', options.beforeSendTransaction),
    beforeSendSpan: spanHook(resolved, options.beforeSendSpan),
    beforeSendLog: hook(resolved, 'beforeSendLog', options.beforeSendLog),
    beforeSendMetric: hook(resolved, 'beforeSendMetric', options.beforeSendMetric),
    beforeBreadcrumb: hook(resolved, 'beforeBreadcrumb', options.beforeBreadcrumb),
  } as NodeOptions;

  Object.defineProperty(wrapped, APPLIED, { value: true, enumerable: false });

  return wrapped;
}

/** Whether `withSensitiveScrubbing` already produced this options object. */
export function isApplied(options: NodeOptions): boolean {
  return (options as Record<symbol, unknown>)[APPLIED] === true;
}

/**
 * `sendDefaultPii: true` is refused rather than scrubbed harder.
 *
 * It enables every collection category, bodies included, and in v10 it is a
 * deprecated option whose interaction with `dataCollection` is
 * version-dependent. A user who wants everything collected and then scrubbed
 * by key name should say so by setting `dataCollection` explicitly, where the
 * decision is visible in their own code.
 */
function assertNoBlanketPii(options: NodeOptions): void {
  if (options.sendDefaultPii === true) {
    throw new SentryScrubbingError(
      'sendDefaultPii: true enables every collection category and is deprecated in v10. ' +
        'Set dataCollection explicitly instead, or spread recommendedDataCollection from this package.'
    );
  }
}

/**
 * Append the scrubbing integration, whatever form the caller's option took.
 *
 * `integrations` is an array or a function over the default array. The
 * function form has to be preserved, because a caller using it is filtering
 * the defaults and replacing it with an array would undo that.
 */
function withIntegration(
  existing: NodeOptions['integrations'],
  policy: ResolvedScrubPolicy
): NodeOptions['integrations'] {
  const append = (integrations: SentryIntegration[]): SentryIntegration[] =>
    integrations.some((integration) => integration.name === INTEGRATION_NAME)
      ? integrations
      : [...integrations, sensitiveScrubbingIntegration(policy)];

  if (typeof existing === 'function') {
    return (defaults: SentryIntegration[]) => append(existing(defaults));
  }

  return append(existing ?? []);
}

/**
 * The policy `beforeSend` runs under.
 *
 * An event reaches `beforeSend` having already passed the scope event
 * processor this package installed, so two things have to change or the
 * second pass reports fiction.
 *
 * Marker counting goes off. A marker sighting means a marker arrived in
 * *captured* data, which is evidence that some other integration sent a
 * placeholder where a value belonged. By `beforeSend` the earlier pass has
 * written a marker everywhere a wrapped value stood, so every sighting here
 * would be this package's own: the smoke test that found this reported three
 * markers on an event whose only markers were stage 1's.
 *
 * `onScrub` goes quiet on success, so one payload produces one report. The
 * failure path still reports, because a scrubber that breaks here is a bug
 * whether or not an earlier seam succeeded.
 *
 * The pass itself is kept. Scope event processors run in registration order,
 * so an application calling `Sentry.addEventProcessor` after `init` gets a
 * processor that runs after this package's, and `beforeSend` is the only seam
 * left that sees what it added.
 */
function backstop(policy: ResolvedScrubPolicy): ResolvedScrubPolicy {
  return { ...policy, onMarker: 'ignore' };
}

/**
 * Build one composed hook.
 *
 * Stage 1 runs at every seam, including the ones measured to be normalized
 * already. It is cheap, and "already normalized" is a property of one version
 * rather than a documented contract: `beforeSendLog` and `beforeSendMetric`
 * were both measured handing over live instances, which the design had
 * recorded as unmeasured and assumed otherwise.
 *
 * No hook tags. Tags are an event field, and the event is tagged by the scope
 * event processor, which is the seam that still sees classes and labels. By
 * `beforeSend` every instance is a string and the report has nothing left to
 * say about them.
 */
function hook<H extends (typeof COVERED_HOOKS)[number]>(
  policy: ResolvedScrubPolicy,
  name: H,
  user: NodeOptions[H],
  reportSuccess = true
): NodeOptions[H] {
  const scrub = scrubberFor(policy, name, reportSuccess);

  return composeAfter(scrub, user as never) as NodeOptions[H];
}

function scrubberFor(
  policy: ResolvedScrubPolicy,
  name: (typeof COVERED_HOOKS)[number],
  reportSuccess = true
): (payload: never) => never | null {
  const spec = HOOK_SPECS[name];

  const scrub = guardedScrub<never>({
    kind: spec.kind,
    policy,
    stub: spec.stub as never,
    reportSuccess,
  });

  return (payload: never) => scrub(payload).payload;
}

/**
 * `beforeSendSpan`, which must never answer `null`.
 *
 * Two ways a composed hook would otherwise return one, and both send the
 * caller the opposite of what they asked for. The scrubber answers `null` only
 * when scrubbing and then stubbing both threw, and the SDK's response is to
 * send the original span, unscrubbed. A caller's own hook answering `null`
 * means they wanted the span dropped, and the SDK's response is the same, so
 * their drop becomes an unscrubbed send.
 *
 * Neither is a decision this package can make on the SDK's behalf, but it can
 * refuse to be the reason a raw span is emitted. In both cases the span this
 * package produced is sent instead: content emptied on the first path, fully
 * scrubbed on the second. The caller's intent to drop is not honoured, because
 * `@sentry/node` 10.73.0 does not offer that on this hook, and both the SDK's
 * own warning and this package's README say so.
 */
function spanHook(
  policy: ResolvedScrubPolicy,
  user: NodeOptions['beforeSendSpan']
): NodeOptions['beforeSendSpan'] {
  const scrub = scrubberFor(policy, 'beforeSendSpan');

  const guarded = ((span: SentrySpan): SentrySpan => {
    const scrubbed = scrub(span as never) ?? lastResortSpanStub();

    if (user === undefined) {
      return scrubbed;
    }

    try {
      return user(scrubbed) ?? scrubbed;
    } catch {
      return scrubbed;
    }
  }) as NonNullable<NodeOptions['beforeSendSpan']>;

  return preserveStreamingMarker(guarded, user);
}

/**
 * Keep span streaming working for anyone who had it.
 *
 * `spanStreamingIntegration` sets `traceLifecycle` back to `'static'` when a
 * `beforeSendSpan` is installed that was not marked by the SDK's
 * `withStreamedSpan`. This package installs one unconditionally, so without
 * this it would silently turn streaming off for every caller who opted in.
 *
 * The marker is applied when the caller supplied no hook of their own, where
 * this package is the only reason one exists, and when the caller's hook
 * already carried it. It is deliberately not applied when the caller's own
 * hook is unmarked: the SDK's fallback and its warning are aimed at them, and
 * suppressing that would silently run their stream-unaware callback under
 * streaming.
 */
function preserveStreamingMarker(
  wrapper: NonNullable<NodeOptions['beforeSendSpan']>,
  user: NodeOptions['beforeSendSpan']
): NodeOptions['beforeSendSpan'] {
  if (user !== undefined && user._streamed !== true) {
    return wrapper;
  }

  // Non-enumerable, matching how the SDK's own `withStreamedSpan` sets it.
  Object.defineProperty(wrapper, '_streamed', { value: true });

  return wrapper;
}

/**
 * The span sent when even the stub builder threw.
 *
 * `buildSpanStub` reads every field through a guard, so reaching this means
 * something well outside the payload went wrong. It still cannot answer
 * `null`, and it must not touch the span it failed on, so it names nothing.
 */
function lastResortSpanStub(): SentrySpan {
  return {
    span_id: '',
    trace_id: '',
    start_timestamp: 0,
    description: DEFAULT_CENSOR,
    data: { [SCRUB_FAILED_TAG]: true },
  };
}
