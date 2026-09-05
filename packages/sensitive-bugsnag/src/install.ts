import type { Breadcrumb, Config, Event, Session } from '@bugsnag/js';
import {
  failedReport,
  mergeReports,
  mergeScrubPolicy,
  reportScrub,
  resolveScrubPolicy,
  scrubPayload,
  type ResolvedScrubPolicy,
  type ScrubPolicy,
  type ScrubReport,
} from '@platform-sec/sensitive-string-scrub';

import {
  annotateEvent,
  emptyBreadcrumb,
  emptyEvent,
  emptySession,
  readBreadcrumb,
  readEvent,
  readEventBreadcrumbs,
  readSession,
  writeBreadcrumb,
  writeEvent,
  writeEventBreadcrumbs,
  writeSession,
  type BreadcrumbSnapshot,
  type EventSnapshot,
} from './event.js';
import { BUGSNAG_POLICY } from './paths.js';

/**
 * The options object `Bugsnag.start` accepts.
 *
 * `@bugsnag/js` re-exports `@bugsnag/browser` and declares `start` as taking
 * `string | BrowserConfig | NodeConfig`, but names neither config type in its
 * own entry point. Deriving the union from the function keeps `@bugsnag/node`
 * out of this package's dependencies and ties the type to the call that has to
 * accept what this wrapper returns.
 */
type BugsnagStart = (typeof import('@bugsnag/js'))['default']['start'];

/** The config union, with the plain-api-key form of `start` removed. */
export type BugsnagConfig = Exclude<Parameters<BugsnagStart>[0], string>;

/**
 * What `withSensitiveScrubbing` hands back: the caller's own config type, plus
 * the four options it sets.
 *
 * The caller's type is preserved so a config with extra fields does not lose
 * them, and the four are added because returning the input type alone would
 * hide the very options this function exists to write.
 */
export type Scrubbed<C> = C &
  Pick<Config, 'onError' | 'onBreadcrumb' | 'onSession' | 'redactedKeys'>;

/**
 * The callbacks this package composes.
 *
 * Bugsnag's seam inventory is three config callbacks rather than Sentry's six
 * `before*` options, and it is not a `before*` family, so `seams.test-d.ts`
 * checks it against the SDK's own config keys with an explicit list of the
 * `on*` options that are deliberately not payload seams.
 */
export const COVERED_CALLBACKS = ['onError', 'onBreadcrumb', 'onSession'] as const;

/**
 * The `on*` config options that are not payload seams, named so the type check
 * fails on a fourth rather than passing because the list happened to grow.
 *
 * `onUncaughtException` and `onUnhandledRejection` are Node-only and fire
 * *after* an event has been delivered, with the delivery error. They receive no
 * payload to scrub and returning from one changes nothing that is sent.
 */
export const EXCLUDED_CALLBACKS = ['onUncaughtException', 'onUnhandledRejection'] as const;

/** Marks a config object this function already produced. */
const APPLIED = Symbol.for('@platform-sec/sensitive-string-bugsnag.applied');

/** Raised at start for a configuration this package will not scrub around. */
export class BugsnagScrubbingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BugsnagScrubbingError';
  }
}

/**
 * Wrap a Bugsnag config so every payload the SDK emits is scrubbed.
 *
 * ```ts
 * Bugsnag.start(withSensitiveScrubbing({ apiKey: process.env.BUGSNAG_KEY! }, policy));
 * ```
 *
 * Two things happen, and both are needed rather than either.
 *
 * The three callbacks are composed, which is what reaches live
 * `SensitiveString` instances, the URL query parameters no key list can
 * express, and the regions Bugsnag's own redaction does not cover.
 *
 * `redactedKeys` gains the resolved denylist, which is what reaches inside the
 * encoder. Measured on `@bugsnag/js` 8.10.0, `redactedKeys` applies only under
 * `events.[].metaData`, `events.[].breadcrumbs.[].metaData`, `events.[].request`
 * and `events.[].response`, and its default is the single key `password`; the
 * callbacks are what covers `context`, `user`, `featureFlags` and the exception
 * itself. Feeding one key list into both is the point of a shared
 * `DEFAULT_DENY_KEYS`.
 *
 * A callback you supply is composed, never replaced, and runs **before** the
 * scrubber. That is the opposite of this repository's Sentry package and it is
 * forced by the same reasoning: measured, Bugsnag runs config callbacks in
 * order and the scrubber has to hold the last position it can reach, so that a
 * callback of yours cannot add raw data behind its back.
 *
 * @param config - The config you would have passed to `Bugsnag.start`
 * @param policy - What to scrub, merged over this package's Bugsnag-shaped
 *                 defaults and the shared denylist
 * @returns A new config object. The input is not modified.
 *
 * @throws BugsnagScrubbingError when `redactedKeys` is set to something the
 *         SDK would reject, since a rejected value silently falls back to the
 *         default of one key.
 */
export function withSensitiveScrubbing<C extends BugsnagConfig>(
  config: C,
  policy: ScrubPolicy = {}
): Scrubbed<C> {
  if (isApplied(config)) {
    // Idempotent. Applying twice would append a second scrubber to `onError`,
    // which would report every payload twice and count the first pass's own
    // markers as sightings.
    return config;
  }

  const resolved = resolveScrubPolicy(mergeScrubPolicy(BUGSNAG_POLICY, policy));

  const wrapped = {
    ...config,
    redactedKeys: unionRedactedKeys(config.redactedKeys, resolved),
    onError: [...asArray(config.onError), eventCallback(resolved)],
    onBreadcrumb: [...asArray(config.onBreadcrumb), breadcrumbCallback(resolved)],
    onSession: [...asArray(config.onSession), sessionCallback(resolved)],
  } as Scrubbed<C>;

  Object.defineProperty(wrapped, APPLIED, { value: true, enumerable: false });

  return wrapped;
}

/** Whether `withSensitiveScrubbing` already produced this config object. */
export function isApplied(config: BugsnagConfig): boolean {
  return (config as unknown as Record<symbol, unknown>)[APPLIED] === true;
}

/**
 * Add the resolved denylist to the caller's `redactedKeys`.
 *
 * The resolved list rather than `DEFAULT_DENY_KEYS`, so a caller's `allowKeys`
 * takes a key back from both stages instead of only from the walk. A caller's
 * own entries survive, `RegExp` entries included, because `redactedKeys` accepts
 * both and this package's `denyKeys` accepts only names.
 *
 * @throws BugsnagScrubbingError when the caller's entries are not strings or
 *         regular expressions. The SDK validates the same thing and falls back
 *         to its default of `['password']` with a warning, which is a silent
 *         downgrade of the whole list this function just built.
 */
function unionRedactedKeys(
  existing: Config['redactedKeys'],
  policy: ResolvedScrubPolicy
): (string | RegExp)[] {
  const supplied = existing ?? [];

  if (!Array.isArray(supplied)) {
    throw new BugsnagScrubbingError('redactedKeys should be an array of strings or regexes');
  }

  for (const entry of supplied) {
    if (typeof entry !== 'string' && !(entry instanceof RegExp)) {
      throw new BugsnagScrubbingError(
        'redactedKeys should be an array of strings or regexes; the SDK falls back to ' +
          "its default of ['password'] for an invalid list, which would silently undo this package"
      );
    }
  }

  const names = new Set(supplied.filter((entry): entry is string => typeof entry === 'string'));
  const merged: (string | RegExp)[] = [...supplied];

  for (const key of policy.denyKeys) {
    if (!names.has(key)) {
      merged.push(key);
    }
  }

  return merged;
}

/** Normalize the `callback | callback[] | undefined` shape every seam option takes. */
function asArray<T>(value: T | T[] | undefined): T[] {
  if (value === undefined) {
    return [];
  }

  return Array.isArray(value) ? [...value] : [value];
}

/**
 * The event seam.
 *
 * Two walks rather than one, and the second is a backstop in the sense the
 * Sentry package's `beforeSend` is.
 *
 * The event's own regions are walked under the caller's policy and reported.
 * The breadcrumbs are walked separately with marker counting off, because every
 * breadcrumb on the event has already passed through this package's own
 * `onBreadcrumb`, where stage 1 wrote a marker everywhere a wrapped value
 * stood. Counted here, each of those would be reported as a marker that arrived
 * in captured data, which is evidence of a different integration failing, and
 * this package would be manufacturing that evidence about itself.
 *
 * The pass is kept because it is the only seam that sees a breadcrumb an
 * earlier `onError` callback pushed onto `event.breadcrumbs` directly, which
 * never went through `leaveBreadcrumb` and so never saw `onBreadcrumb`.
 */
function eventCallback(policy: ResolvedScrubPolicy): (event: Event) => boolean {
  const crumbPolicy = backstop(policy);

  return (event: Event): boolean => {
    let report: ScrubReport;

    try {
      const { payload, report: primary } = scrubPayload(readEvent(event), policy, 'event');
      const crumbs = scrubPayload(readEventBreadcrumbs(event), crumbPolicy, 'breadcrumb');

      writeEvent(event, payload as EventSnapshot);
      writeEventBreadcrumbs(event, crumbs.payload);
      report = mergeReports(primary, crumbs.report);
    } catch {
      report = failedReport('event', policy);

      try {
        emptyEvent(event);
      } catch {
        // Scrubbing failed and so did describing the failure. There is no
        // payload left that anything has vouched for, so nothing is sent. This
        // is the one path that loses the error, and it takes two independent
        // bugs.
        reportScrub(policy, report);

        return false;
      }
    }

    reportScrub(policy, report);
    annotateEvent(event, report, policy.reportLabels);

    return true;
  };
}

/** The breadcrumb seam, which is where a breadcrumb is scrubbed before it enters the buffer. */
function breadcrumbCallback(policy: ResolvedScrubPolicy): (crumb: Breadcrumb) => boolean {
  return (crumb: Breadcrumb): boolean => {
    let report: ScrubReport;

    try {
      const { payload, report: scrubbed } = scrubPayload(
        readBreadcrumb(crumb),
        policy,
        'breadcrumb'
      );

      writeBreadcrumb(crumb, payload as BreadcrumbSnapshot);
      report = scrubbed;
    } catch {
      report = failedReport('breadcrumb', policy);
      emptyBreadcrumb(crumb);
    }

    reportScrub(policy, report);

    // Always kept. A breadcrumb's value is its position in the timeline, and
    // returning `false` would remove that as well as the data.
    return true;
  };
}

/**
 * The session seam.
 *
 * Measured on `@bugsnag/js` 8.10.0, the Node notifier's session payload carries
 * no application data at all: `{ notifier, device: {}, app: { releaseStage,
 * version, type }, sessionCounts }`, assembled from configuration rather than
 * from the session objects this callback sees. The seam is composed anyway,
 * because the session object does carry the user and "this build does not
 * transmit it" is a property of one version.
 */
function sessionCallback(policy: ResolvedScrubPolicy): (session: Session) => boolean {
  return (session: Session): boolean => {
    let report: ScrubReport;

    try {
      const { payload, report: scrubbed } = scrubPayload(readSession(session), policy, 'session');

      writeSession(session, payload as Record<string, unknown>);
      report = scrubbed;
    } catch {
      report = failedReport('session', policy);
      emptySession(session);
    }

    reportScrub(policy, report);

    return true;
  };
}

/**
 * The policy a second pass over the same payload runs under.
 *
 * Marker counting off, for the reason `eventCallback` gives.
 */
function backstop(policy: ResolvedScrubPolicy): ResolvedScrubPolicy {
  return { ...policy, onMarker: 'ignore' };
}
