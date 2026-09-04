import type { Breadcrumb, Event } from '@sentry/node';
import {
  DEFAULT_CENSOR,
  type ResolvedScrubPolicy,
  type ScrubReport,
} from '@platform-sec/sensitive-string-scrub';

/** The tag saying a scrub failed and the payload was replaced. */
export const SCRUB_FAILED_TAG = 'sensitive.scrub_failed';

/** The tag naming the sensitivity classes that were in scope. */
export const CLASSES_TAG = 'sensitive.classes';

/** The tag naming the labels that were in scope, when the caller opts in. */
export const LABELS_TAG = 'sensitive.labels';

/** The tag reporting a redaction marker found in captured data. */
export const MARKER_TAG = 'sensitive.marker_seen';

/** The tag naming the classes those markers named. */
export const MARKER_CLASSES_TAG = 'sensitive.marker_classes';

/**
 * The replacement event sent when scrubbing an event throws.
 *
 * Enough to know an error of this shape happened, and nothing that was in it:
 * the exception type, the fingerprint if one was already computed, the level,
 * and a tag saying why the rest is missing. No message, because a message is
 * assembled from application data and there is no scrubbed copy of it to draw
 * on. No `extra`, no `contexts`, no `request`, no breadcrumbs.
 *
 * Not the same as returning null. Null tells Sentry the event was deliberately
 * discarded and it is counted as a client-side drop. Losing the error entirely
 * is the outcome this exists to avoid, and it is what would happen otherwise:
 * measured on `@sentry/node` 10.73.0, a `beforeSend` that throws drops the
 * original event and sends a replacement describing the scrubber's exception,
 * so the alert that fires names the wrong thing.
 */
export function buildEventStub(event: Event): Event {
  const stub: Event = { tags: { [SCRUB_FAILED_TAG]: 'true' } };

  // `exactOptionalPropertyTypes` is on across the repository, so an absent
  // field has to be absent rather than present and undefined.
  copyDefined(event, stub, ['event_id', 'timestamp', 'platform', 'level', 'fingerprint']);

  const type = event.exception?.values?.[0]?.type;

  if (type !== undefined) {
    stub.exception = { values: [{ type, value: DEFAULT_CENSOR }] };
  }

  return stub;
}

/** A breadcrumb the scrubber could not finish: the category and level survive, the data does not. */
export function buildBreadcrumbStub(breadcrumb: Breadcrumb): Breadcrumb {
  const stub: Breadcrumb = {
    message: DEFAULT_CENSOR,
    data: { [SCRUB_FAILED_TAG]: true },
  };

  copyDefined(breadcrumb, stub, ['type', 'category', 'level', 'timestamp']);

  return stub;
}

function copyDefined<T extends object>(from: T, to: T, keys: readonly (keyof T)[]): void {
  for (const key of keys) {
    if (from[key] !== undefined) {
      to[key] = from[key];
    }
  }
}

/**
 * Write what the report found onto the event, as tags.
 *
 * Classes are on by default and labels are not. A class name comes from the
 * policy registry, is not a value, and in a normal application there are two
 * of them, so the tag is cheap and its cardinality is bounded by something the
 * application controls deliberately. A label is a user-supplied string and is
 * high cardinality, and the secrets manager design already has a rule against
 * a derived label carrying an account, project or tenancy identifier. Sending
 * labels to a third party by default would make this package the thing that
 * punishes a label somebody chose before that rule existed.
 *
 * A marker sighting is tagged rather than thrown on. `[REDACTED:credential]`
 * in a captured 401 response body means an HTTP client sent the placeholder as
 * a bearer token; the same string in a captured SQL parameter means an ORM
 * persisted it. The error tracker is the one component positioned to notice,
 * and throwing here would suppress the report of the very incident the marker
 * is evidence of.
 */
export function tagEvent(
  event: Event | null,
  report: ScrubReport,
  policy: ResolvedScrubPolicy
): Event | null {
  if (event === null) {
    return null;
  }

  const tags: Record<string, string> = {};

  if (report.failed) {
    tags[SCRUB_FAILED_TAG] = 'true';
  }

  if (report.classes.size > 0) {
    tags[CLASSES_TAG] = [...report.classes].sort().join(',');
  }

  if (policy.reportLabels && report.labels !== undefined && report.labels.length > 0) {
    tags[LABELS_TAG] = [...report.labels].sort().join(',');
  }

  if (report.markersSeen > 0) {
    tags[MARKER_TAG] = String(report.markersSeen);

    if (report.markerClasses.size > 0) {
      tags[MARKER_CLASSES_TAG] = [...report.markerClasses].sort().join(',');
    }
  }

  if (Object.keys(tags).length === 0) {
    return event;
  }

  return { ...event, tags: { ...event.tags, ...tags } };
}
