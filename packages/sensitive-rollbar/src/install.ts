import type RollbarClient from 'rollbar';
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

import { restoreMarkers } from './flattened.js';
import { ROLLBAR_POLICY } from './paths.js';

/** The options object `new Rollbar(...)` and `rollbar.configure(...)` accept. */
export type RollbarConfig = RollbarClient.Configuration;

/**
 * What `withSensitiveScrubbing` hands back: the caller's own config type, plus
 * the options it sets.
 *
 * The caller's type is preserved so a config with extra fields does not lose
 * them, and the rest are added because returning the input type alone would
 * hide the very options this function exists to write.
 */
export type Scrubbed<C> = C &
  Pick<
    RollbarConfig,
    'transform' | 'scrubFields' | 'scrubHeaders' | 'scrubPaths' | 'overwriteScrubFields'
  >;

/** The payload a `transform` receives, which is Rollbar's own `Dictionary`. */
type Payload = Record<string, unknown>;

/**
 * The seams this package composes.
 *
 * One. Rollbar has a single hook over the outgoing payload and it is
 * `transform`, measured at position 11 of the 14 transforms the Node notifier
 * installs.
 */
export const COVERED_SEAMS = ['transform'] as const;

/**
 * The seams that are deliberately not composed, named so the type check fails
 * on a new one rather than passing because the list happened to grow.
 *
 * `checkIgnore` is a queue predicate, not a transform. Measured: every
 * transform runs before the queue is reached, so by the time `checkIgnore` sees
 * an item this package has already scrubbed it, and its return value decides
 * whether to send rather than what to send. Composing it would add a seam that
 * has nothing left to do.
 *
 * `filterTelemetry` decides whether a telemetry event is recorded at all.
 * Telemetry reaches the payload at `body.telemetry`, which the composed
 * `transform` walks like anything else.
 *
 * `addRequestData` is a caller's own request assembler, running at transform
 * position 6. Wrapping it would scrub the request twice and would not reach a
 * caller who does not supply one.
 *
 * `onSendCallback` and `transformSpan` are outside the error payload: the first
 * fires after a send, the second belongs to the tracing option group.
 */
export const EXCLUDED_SEAMS = [
  'checkIgnore',
  'filterTelemetry',
  'addRequestData',
  'onSendCallback',
] as const;

/** Marks a config object this function already produced. */
const APPLIED = Symbol.for('@platform-sec/sensitive-string-rollbar.applied');

/** Raised at construction for a configuration this package will not scrub around. */
export class RollbarScrubbingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RollbarScrubbingError';
  }
}

/**
 * Wrap a Rollbar config so the outgoing payload is scrubbed.
 *
 * ```ts
 * const rollbar = new Rollbar(withSensitiveScrubbing({ accessToken }, policy));
 * ```
 *
 * This is the thinnest of the vendor packages and the README says so. Rollbar
 * 3.1.0 ships the best defaults measured, its own scrub runs before this
 * package's seam, and what is added on top is four things:
 *
 * 1. Structural redaction, which is what a `serialize()` result needs. Measured:
 *    the wire format's `value` reaches the wire intact under stock scrubbing,
 *    because no key list describes it.
 * 2. The redaction marker, put back where this vendor flattened one away. See
 *    `flattened.ts`, which is also where the label leak that finding closes is
 *    described.
 * 3. The never-throw contract, which matters more here than anywhere else.
 *    Measured: a `transform` that throws makes Rollbar log, set
 *    `options.transform = null` for the life of the process, and send the
 *    original untransformed item. One exception and scrubbing is off, silently,
 *    forever. A caller's own transform is called inside the guard for exactly
 *    this reason.
 * 4. The extra key names, the path list Rollbar ships but does not apply, and
 *    the seam inventory.
 *
 * A `transform` you supply is composed, never replaced, and runs **before** the
 * scrubber, so that it cannot add raw data behind the scrubber's back. If it
 * throws or rejects, the failure is swallowed here rather than reaching Rollbar,
 * because Rollbar's response to it would be to disable this package.
 *
 * @param config - The config you would have passed to `new Rollbar(...)`
 * @param policy - What to scrub, merged over this package's Rollbar-shaped
 *                 defaults and the shared denylist
 * @returns A new config object. The input is not modified.
 *
 * @throws RollbarScrubbingError when `overwriteScrubFields` is already set
 *         alongside a policy that takes a default key back, since the two
 *         answers to "who owns the scrub list" cannot both be honoured.
 */
export function withSensitiveScrubbing<C extends RollbarConfig>(
  config: C,
  policy: ScrubPolicy = {}
): Scrubbed<C> {
  if (isApplied(config)) {
    // Idempotent. Applying twice would nest the scrubber inside itself, which
    // would report every payload twice and count the first pass's own markers
    // as sightings.
    return config;
  }

  const merged = mergeScrubPolicy(ROLLBAR_POLICY, policy);
  const resolved = resolveScrubPolicy(merged);
  const takesKeysBack = (policy.allowKeys ?? []).length > 0;

  if (takesKeysBack && config.overwriteScrubFields === false) {
    throw new RollbarScrubbingError(
      'allowKeys cannot take a key back while overwriteScrubFields is false: Rollbar would ' +
        'concatenate its own defaults back onto the list. Drop one of the two.'
    );
  }

  const wrapped = {
    ...config,
    scrubFields: scrubFieldsFor(config, resolved),
    scrubHeaders: [...resolved.denyKeys],
    scrubPaths: [...new Set([...(config.scrubPaths ?? []), ...resolved.denyPaths])],
    transform: composedTransform(resolved, config.transform),
    // Only when the caller asked for a key back. Rollbar concatenates a
    // supplied `scrubFields` onto its own defaults, measured at 25 + 1 = 26, so
    // by default this package adds to the vendor's list and leaves it
    // authoritative. `allowKeys` is the one operation that cannot work that
    // way, and a caller who writes one has said which key and why.
    ...(takesKeysBack ? { overwriteScrubFields: true } : {}),
  } as Scrubbed<C>;

  Object.defineProperty(wrapped, APPLIED, { value: true, enumerable: false });

  return wrapped;
}

/** Whether `withSensitiveScrubbing` already produced this config object. */
export function isApplied(config: RollbarConfig): boolean {
  return (config as unknown as Record<symbol, unknown>)[APPLIED] === true;
}

/**
 * The `scrubFields` this package passes.
 *
 * The whole resolved list, plus whatever the caller already had. What differs
 * between the two modes is not this list but who owns it, which
 * `overwriteScrubFields` decides at the call site.
 *
 * Without `allowKeys`, Rollbar concatenates its own 25 defaults onto this,
 * measured at 25 + 1 = 26 for a single supplied name, so about 25 of the
 * entries end up duplicated. Rollbar compiles two regular expressions per entry
 * per payload, which makes the duplicates a real cost rather than none, and it
 * is paid on the error path against a network round trip that dominates it by
 * orders of magnitude.
 *
 * Passing only the difference would avoid it and is not worth the risk: the
 * difference can only be computed against this repository's reproduction of the
 * vendor's list, `deny.test.ts` asserts that the reproduction is a *superset*
 * of what the installed `rollbar` ships, and a superset assertion does not
 * notice a name the vendor removes. Subtracting a name the vendor no longer
 * carries would silently stop scrubbing it.
 *
 * With `allowKeys`, the concatenation would put the allowed key straight back,
 * so the caller's own entries have to survive an overwrite as well. They asked
 * for one key back, not for their list to be replaced by this package's.
 */
function scrubFieldsFor(config: RollbarConfig, policy: ResolvedScrubPolicy): string[] {
  return [...new Set([...(config.scrubFields ?? []), ...policy.denyKeys])];
}

/**
 * The composed transform.
 *
 * The caller's runs first and the scrubber second, so the scrubber holds the
 * last position in the only seam Rollbar offers. That is the opposite of this
 * repository's Sentry package, where `beforeSend` is a backstop behind a scope
 * processor that already ran, and it is the same choice the Bugsnag package
 * makes for the same reason: with one seam, last is the only position worth
 * having.
 *
 * Nothing here throws, and that matters more for this vendor than for any
 * other. Measured on `rollbar` 3.1.0: `userTransform` catches, logs "Error
 * while calling custom transform() function. Removing custom transform().",
 * sets `options.transform = null`, and calls back with the **original,
 * untransformed item**. So one exception out of this function would send that
 * payload raw and turn scrubbing off for every payload after it, for the life
 * of the process, with a log line as the only evidence.
 */
function composedTransform(
  policy: ResolvedScrubPolicy,
  user: RollbarConfig['transform']
): NonNullable<RollbarConfig['transform']> {
  return (data: Payload, item: Payload): void | Promise<void> => {
    if (user === undefined) {
      scrub(data, policy);

      return;
    }

    let response: unknown;

    try {
      response = user(data, item);
    } catch {
      // The caller's transform failed. Their additions are lost, the scrub is
      // not, and Rollbar never learns it could disable this package.
      scrub(data, policy);

      return;
    }

    if (!isThenable(response)) {
      scrub(data, policy);

      return;
    }

    // An async transform is awaited by Rollbar, and a resolved value replaces
    // the payload outright. Whatever object it ends up sending is the one that
    // has to be scrubbed, so the scrub follows the await and follows the
    // substitution.
    return Promise.resolve(response).then(
      (resolved) => {
        const replacement = replacementFrom(resolved);

        scrub(replacement ?? data, policy);

        // The published type says `Promise<void>`, and the implementation uses
        // a truthy resolved value to replace the payload outright. Only an
        // object is passed through: a transform that resolves to `true`, which
        // an `async` function returning a boolean does, would otherwise put
        // that boolean where the payload belongs.
        return replacement as void;
      },
      () => {
        scrub(data, policy);
      }
    );
  };
}

/** A resolved value Rollbar would accept as a replacement payload, or `undefined`. */
function replacementFrom(resolved: unknown): Payload | undefined {
  return resolved !== null && typeof resolved === 'object' ? (resolved as Payload) : undefined;
}

/**
 * Scrub one payload in place, and report.
 *
 * In place because Rollbar's contract is that the transform mutates the object
 * it was handed: the return value is ignored for a synchronous transform, and
 * the object `userTransform` passes is a clone the SDK made for this purpose.
 * Nothing reachable from the caller is touched, and the walk itself never
 * mutates its input in any case; only the top-level keys of the clone are
 * reassigned from the scrubbed copy.
 */
function scrub(data: Payload, policy: ResolvedScrubPolicy): void {
  let report: ScrubReport;

  try {
    const { payload, report: scrubbed } = scrubPayload(data, policy, 'event');
    const restored = restoreMarkers(payload);

    replaceContents(data, payload);
    report = fold(scrubbed, restored);
  } catch {
    report = failedReport('event', policy);
    empty(data);
  }

  reportScrub(policy, report);
  annotate(data, report, policy.reportLabels);
}

/** The metadata key this package writes its report under. */
export const REPORT_KEY = 'sensitive';

/**
 * Write what the report found onto the payload.
 *
 * Rollbar has no tags, and `data.custom` is what its UI surfaces as searchable
 * per-occurrence data, so a key of this package's own there is the equivalent
 * of Sentry's `sensitive.*` tags.
 *
 * Classes are on by default and labels are not, per Q7 and for the reason
 * `flattened.ts` gives at length: on this vendor a label reaches the wire by
 * accident unless something stops it.
 */
function annotate(data: Payload, report: ScrubReport, reportLabels: boolean): void {
  const section: Record<string, unknown> = {};

  if (report.failed) {
    section['scrub_failed'] = true;
  }

  if (report.classes.size > 0) {
    section['classes'] = [...report.classes].sort().join(',');
  }

  if (reportLabels && report.labels !== undefined && report.labels.length > 0) {
    section['labels'] = [...report.labels].sort().join(',');
  }

  if (report.deniedValues.length > 0) {
    section['value_shapes'] = [...report.deniedValues].sort().join(',');
  }

  if (report.markersSeen > 0) {
    section['marker_seen'] = report.markersSeen;

    if (report.markerClasses.size > 0) {
      section['marker_classes'] = [...report.markerClasses].sort().join(',');
    }
  }

  if (Object.keys(section).length === 0) {
    return;
  }

  try {
    const custom = data['custom'];
    const target_ =
      custom !== null && typeof custom === 'object' ? (custom as Record<string, unknown>) : {};

    target_[REPORT_KEY] = section;
    data['custom'] = target_;
  } catch {
    // A frozen payload. The report still reached `onScrub`.
  }
}

/** Copy a scrubbed payload's own keys onto the object Rollbar will send. */
function replaceContents(data: Payload, scrubbed: unknown): void {
  if (scrubbed === null || typeof scrubbed !== 'object' || scrubbed === data) {
    return;
  }

  for (const [key, value] of Object.entries(scrubbed)) {
    data[key] = value;
  }
}

/**
 * Strip every region that holds application data, in place.
 *
 * The stub of the design's section 2.6, in the form a vendor that mutates its
 * payload takes one. What survives is the envelope Rollbar needs to file the
 * occurrence at all and the fact that an error happened; what goes is
 * everything that was captured.
 */
function empty(data: Payload): void {
  // Every write is guarded individually, and nothing here throws. There is no
  // failure answer left behind this one: throwing out of the transform would
  // make Rollbar send the original, unscrubbed item and disable the transform
  // for the life of the process, so the worst outcome available is also the one
  // an exception would produce. A key that refuses to be deleted stays, and the
  // rest still go.
  for (const key of ownKeys(data)) {
    if (!KEPT_ON_FAILURE.has(key)) {
      drop(data, key);
    }
  }

  write(data, 'body', { message: { body: '[SCRUBBED]' } });
  write(data, 'custom', { [REPORT_KEY]: { scrub_failed: true } });
}

function ownKeys(data: Payload): string[] {
  try {
    return Object.keys(data);
  } catch {
    return [];
  }
}

function drop(data: Payload, key: string): void {
  try {
    delete data[key];
  } catch {
    // A non-configurable property. It stays, and the rest still go.
  }
}

function write(data: Payload, key: string, value: unknown): void {
  try {
    data[key] = value;
  } catch {
    // Frozen or accessor-only.
  }
}

/**
 * What a stripped payload keeps.
 *
 * Enough for Rollbar to accept the occurrence and file it in the right project
 * at the right level, and nothing the application put there. `uuid` is the
 * deduplication key and `timestamp` is what orders it.
 *
 * `notifier` is kept because at this point it holds the name and version and
 * nothing else. Rollbar writes `notifier.configured_options` and
 * `notifier.diagnostic` at transform positions 12 and 13, after this seam, and
 * the second carries the original error's message and stack. A stripped
 * occurrence therefore still arrives with that block, which is the same region
 * `ROLLBAR_UNREACHABLE_PATHS` names and the README lists as out of reach.
 */
const KEPT_ON_FAILURE = new Set([
  'environment',
  'level',
  'language',
  'framework',
  'platform',
  'notifier',
  'timestamp',
  'uuid',
  'server',
]);

/**
 * Fold the marker restoration's findings into the report the seam will publish.
 *
 * `mergeReports` from the shared layer takes two reports, so the restoration's
 * counts are dressed as one. Its markers are empty by construction: a restored
 * marker is this package's own output, and counting it would be manufacturing
 * evidence that some other integration failed.
 */
function fold(report: ScrubReport, restored: ReturnType<typeof restoreMarkers>): ScrubReport {
  if (restored.instances === 0) {
    return report;
  }

  const secondary: ScrubReport = {
    kind: report.kind,
    instances: restored.instances,
    // The one cast in this package, and the only place a class name recovered
    // from a payload becomes core's closed `SensitivityClass` union. The name
    // was read out of an object Rollbar built from a wrapped value's own
    // properties, so in practice it is one of the two, and `flattened.ts`
    // explains why it is not validated against them: a class added to core
    // later must keep being recognized rather than start leaking its label
    // again. Nothing downstream does anything with the name but sort it and
    // join it into a string.
    classes: restored.classes as ScrubReport['classes'],
    labels: [...restored.labels],
    deniedKeys: [],
    deniedValues: [],
    markersSeen: 0,
    markerClasses: new Set(),
    failed: false,
  };

  return mergeReports(report, secondary);
}

function isThenable(value: unknown): value is PromiseLike<unknown> {
  return (
    value !== null &&
    typeof value === 'object' &&
    typeof (value as PromiseLike<unknown>).then === 'function'
  );
}
