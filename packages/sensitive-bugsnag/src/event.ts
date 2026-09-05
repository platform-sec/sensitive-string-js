import type { Breadcrumb, Event, Session } from '@bugsnag/js';
import { DEFAULT_CENSOR, type ScrubReport } from '@platform-sec/sensitive-string-scrub';

/**
 * Projecting a Bugsnag payload into something the shared walk can scrub, and
 * putting the result back.
 *
 * Every other vendor package in this repository hands a payload to
 * `scrubPayload` and returns the copy it gets back. Bugsnag cannot: its
 * callbacks receive a class instance and return a boolean, and the SDK keeps
 * using the instance it gave you. `redactCopy` deliberately builds a plain
 * object, which would strip the `toJSON()` that defines the wire shape, so the
 * copy can never be the thing that is sent.
 *
 * So this file does the one thing the design's invariant 9 carves out: it
 * mutates the event it was given, and nothing else. The rule it follows is that
 * every write is an assignment of a value the scrubber built, never a write
 * *through* something the caller still holds. `event.originalError` is the
 * caller's own `Error`, measured and reachable from the event, and nothing here
 * touches it.
 *
 * The region list is `Event.prototype.toJSON()`, read off `@bugsnag/js` 8.10.0.
 * Reading it from the wire shape rather than from the class's own fields is
 * what keeps a field that is captured but never sent, `originalError` and
 * `_handledState` among them, out of both the scrub and the report.
 */

/**
 * The scrubbable regions of an event, keyed by their names on the wire.
 *
 * Breadcrumbs are not here. They reach the event already scrubbed, because they
 * passed through this package's `onBreadcrumb` when they were created, and a
 * second pass over them has to run with marker counting off or it reports the
 * first pass's own markers as evidence that some other integration failed.
 * `readEventBreadcrumbs` is that separate pass.
 */
export interface EventSnapshot {
  exceptions: unknown;
  app: unknown;
  device: unknown;
  request: unknown;
  response: unknown;
  context: unknown;
  groupingHash: unknown;
  metaData: unknown;
  user: unknown;
  featureFlags: unknown;
}

/** The metadata section this package writes its report into. */
export const REPORT_SECTION = 'sensitive';

/** The report keys, which are what an operator filters on in the Bugsnag UI. */
export const CLASSES_KEY = 'classes';
export const LABELS_KEY = 'labels';
export const MARKER_KEY = 'marker_seen';
export const MARKER_CLASSES_KEY = 'marker_classes';
export const VALUE_SHAPES_KEY = 'value_shapes';
export const SCRUB_FAILED_KEY = 'scrub_failed';

/**
 * A breadcrumb as the walk should see it.
 *
 * `metadata` on the class, `metaData` on the wire. The projection uses the
 * class's name, because a caller writing a `denyPaths` entry is looking at the
 * object their `onBreadcrumb` receives.
 */
export interface BreadcrumbSnapshot {
  message: unknown;
  metadata: unknown;
}

/**
 * Read the live regions of an event.
 *
 * Live, not copied: stage 1 only has something to act on while the
 * `SensitiveString` instances are still instances, and `onError` is measured to
 * hand them over as instances. The walk copies before it writes, so handing it
 * live references is safe and is the only way the class list is populated at
 * all.
 */
export function readEvent(event: Event): EventSnapshot {
  return {
    exceptions: read(event, 'errors'),
    app: read(event, 'app'),
    device: read(event, 'device'),
    request: read(event, 'request'),
    response: read(event, 'response'),
    context: read(event, 'context'),
    groupingHash: read(event, 'groupingHash'),
    metaData: readMetadata(event),
    user: safely(() => event.getUser()),
    featureFlags: safely(() => event.getFeatureFlags()),
  };
}

/**
 * Write a scrubbed snapshot back onto the event.
 *
 * Through the public API wherever the SDK offers one, which is metadata, the
 * user and the feature flags. The rest are public fields on the `Event` class
 * and are assigned directly.
 *
 * Breadcrumbs go through `writeEventBreadcrumbs`, separately and for a
 * different reason: they are replaced rather than mutated, because
 * `event.breadcrumbs` is a shallow slice of the client's own buffer, measured,
 * so every `Breadcrumb` instance in it belongs to the client and is shared with
 * every later event. Writing scrubbed metadata into one would reach state the
 * caller still holds, which is the one thing this file may not do.
 */
export function writeEvent(event: Event, snapshot: EventSnapshot): void {
  assign(event, 'errors', snapshot.exceptions);
  assign(event, 'app', snapshot.app);
  assign(event, 'device', snapshot.device);
  assign(event, 'request', snapshot.request);
  assign(event, 'response', snapshot.response);
  assign(event, 'context', snapshot.context);
  assign(event, 'groupingHash', snapshot.groupingHash);

  writeMetadata(event, snapshot.metaData);
  writeUser(event, snapshot.user);
  writeFeatureFlags(event, snapshot.featureFlags);
}

/**
 * Strip every region that holds application data, in place.
 *
 * The stub of the design's section 2.6, in the only form a vendor that mutates
 * its payload can take one: there is no replacement object to return, so the
 * replacement is this event with nothing in it. What survives is that an error
 * of this class happened and where in the code it was thrown, which is what
 * keeps the alert pointing at the right thing. What goes is everything that was
 * captured.
 *
 * Not the same as returning `false` from `onError`. That tells Bugsnag the
 * event was deliberately discarded, and losing the error entirely is the
 * outcome this exists to avoid.
 */
export function emptyEvent(event: Event): void {
  // `overwrite`, not `assign`: clearing a region is exactly the case `assign`
  // refuses, because it cannot tell an absent region from one it failed to
  // read. Here the intent is unambiguous.
  overwrite(event, 'request', undefined);
  overwrite(event, 'response', undefined);
  overwrite(event, 'context', DEFAULT_CENSOR);
  overwrite(event, 'groupingHash', undefined);
  overwrite(event, 'breadcrumbs', []);

  safely(() => {
    for (const error of event.errors) {
      error.errorMessage = DEFAULT_CENSOR;
      // Frame positions survive, so the report still groups and still points at
      // a line. `code` is the surrounding source, which `sendCode` collects and
      // which is application text.
      for (const frame of error.stacktrace) {
        delete frame.code;
      }
    }
  });

  safely(() => {
    for (const section of Object.keys(readMetadata(event) ?? {})) {
      event.clearMetadata(section);
    }
  });

  safely(() => {
    event.setUser(undefined, undefined, undefined);
  });
  safely(() => {
    event.clearFeatureFlags();
  });
}

/**
 * Write what the report found onto the event, as a metadata section.
 *
 * Bugsnag has no tags, and its metadata sections are what the UI groups and
 * filters on, so a section of this package's own is the equivalent of Sentry's
 * `sensitive.*` tags.
 *
 * Classes are on by default and labels are not. A class name comes from the
 * policy registry, is not a value, and in a normal application there are two of
 * them. A label is a user-supplied string, it is high cardinality, and the
 * secrets manager design already has a rule against a derived label carrying an
 * account, project or tenancy identifier; sending them to a third party by
 * default would make this package the thing that punishes a label somebody
 * chose before that rule existed.
 *
 * A marker sighting is recorded, never thrown on. `[REDACTED:credential]` in a
 * captured 401 body means an HTTP client sent the placeholder as a bearer
 * token, and the error tracker is the one component positioned to notice.
 *
 * Written after scrubbing, so the section is the report rather than something
 * the walk then walks.
 */
export function annotateEvent(event: Event, report: ScrubReport, reportLabels: boolean): void {
  const section: Record<string, unknown> = {};

  if (report.failed) {
    section[SCRUB_FAILED_KEY] = true;
  }

  if (report.classes.size > 0) {
    section[CLASSES_KEY] = [...report.classes].sort().join(',');
  }

  if (reportLabels && report.labels !== undefined && report.labels.length > 0) {
    section[LABELS_KEY] = [...report.labels].sort().join(',');
  }

  if (report.deniedValues.length > 0) {
    section[VALUE_SHAPES_KEY] = [...report.deniedValues].sort().join(',');
  }

  if (report.markersSeen > 0) {
    section[MARKER_KEY] = report.markersSeen;

    if (report.markerClasses.size > 0) {
      section[MARKER_CLASSES_KEY] = [...report.markerClasses].sort().join(',');
    }
  }

  if (Object.keys(section).length === 0) {
    return;
  }

  safely(() => {
    event.addMetadata(REPORT_SECTION, section);
  });
}

/** Read a session's regions. The wire names again, per the session payload shape. */
export function readSession(session: Session): Record<string, unknown> {
  return {
    app: read(session, 'app'),
    device: read(session, 'device'),
    user: read(session, '_user'),
  };
}

/**
 * Write a scrubbed session back.
 *
 * `_user` has no public setter, and it is assigned rather than written through:
 * the client builds it as a fresh object per session, measured, so replacing it
 * reaches nothing the caller holds.
 *
 * Worth knowing what this is and is not for. Measured on `@bugsnag/js` 8.10.0,
 * the Node notifier's session payload is `{ notifier, device: {}, app: {
 * releaseStage, version, type }, sessionCounts }`: the user never leaves the
 * process on this platform. The seam is composed anyway, because "the current
 * build does not transmit it" is a property of one version and covering every
 * seam the SDK offers is the point.
 */
export function writeSession(session: Session, snapshot: Record<string, unknown>): void {
  assign(session, 'app', snapshot['app']);
  assign(session, 'device', snapshot['device']);
  assign(session, '_user', snapshot['user']);
}

/** Read a breadcrumb's regions. */
export function readBreadcrumb(breadcrumb: Breadcrumb): BreadcrumbSnapshot {
  return {
    message: read(breadcrumb, 'message'),
    metadata: read(breadcrumb, 'metadata'),
  };
}

/**
 * Write a scrubbed breadcrumb back.
 *
 * Assignment, never a write through `breadcrumb.metadata`. Measured: the
 * `Breadcrumb` constructor stores the metadata object the caller passed to
 * `leaveBreadcrumb` by reference, so mutating it in place would rewrite the
 * application's own object. The scrubbed copy is a different object, so
 * assigning it leaves the caller's untouched.
 */
export function writeBreadcrumb(breadcrumb: Breadcrumb, snapshot: BreadcrumbSnapshot): void {
  assign(breadcrumb, 'message', snapshot.message);
  assign(breadcrumb, 'metadata', snapshot.metadata);
}

/** A breadcrumb the scrubber could not finish: the position in the timeline survives, the data does not. */
export function emptyBreadcrumb(breadcrumb: Breadcrumb): void {
  overwrite(breadcrumb, 'message', DEFAULT_CENSOR);
  overwrite(breadcrumb, 'metadata', { [SCRUB_FAILED_KEY]: true });
}

/** A session the scrubber could not finish. */
export function emptySession(session: Session): void {
  overwrite(session, '_user', {});
}

/**
 * The breadcrumbs on an event, projected so the walk sees the same field names
 * an `onBreadcrumb` callback does.
 */
export function readEventBreadcrumbs(event: Event): BreadcrumbSnapshot[] {
  return safely(() => event.breadcrumbs?.map((crumb) => readBreadcrumb(crumb))) ?? [];
}

/**
 * Replace the event's breadcrumbs with scrubbed clones.
 *
 * The clone keeps the prototype, because the wire shape of a breadcrumb is its
 * `toJSON()` and a plain object would send `metadata` where Bugsnag expects
 * `metaData`. It is a clone rather than a mutation because the instances belong
 * to the client's shared buffer.
 *
 * A breadcrumb reaching here is already scrubbed in the usual case: it passed
 * through the composed `onBreadcrumb` when it was created. This is what catches
 * one an `onError` callback added directly to `event.breadcrumbs`, which is a
 * documented thing to do and does not go through `leaveBreadcrumb`.
 */
export function writeEventBreadcrumbs(event: Event, scrubbed: unknown): void {
  if (!Array.isArray(scrubbed)) {
    return;
  }

  safely(() => {
    const crumbs = event.breadcrumbs;

    if (!Array.isArray(crumbs)) {
      return;
    }

    event.breadcrumbs = crumbs.map((crumb, index) => {
      const snapshot = scrubbed[index] as BreadcrumbSnapshot | undefined;

      if (snapshot === undefined) {
        return crumb;
      }

      const clone = Object.assign(
        Object.create(Object.getPrototypeOf(crumb) as object) as Breadcrumb,
        crumb
      );

      writeBreadcrumb(clone, snapshot);

      return clone;
    });
  });
}

/**
 * Every metadata section, read through the public getter.
 *
 * `getMetadata(section)` with no key returns the section object. There is no
 * public way to list the sections, so the field is read directly and the result
 * is treated as a plain record; a build that renames it yields no sections
 * rather than an exception, and the canary sweep is what would notice.
 */
function readMetadata(event: Event): Record<string, unknown> | undefined {
  const metadata = read(event, '_metadata');

  return metadata !== null && typeof metadata === 'object'
    ? (metadata as Record<string, unknown>)
    : undefined;
}

/**
 * Replace each metadata section with its scrubbed form.
 *
 * `clearMetadata` then `addMetadata`, because `addMetadata` merges into what is
 * already there and a merge would leave the unscrubbed value in place under any
 * key the scrub did not rewrite.
 */
function writeMetadata(event: Event, scrubbed: unknown): void {
  if (scrubbed === null || typeof scrubbed !== 'object') {
    return;
  }

  for (const [section, values] of Object.entries(scrubbed)) {
    safely(() => {
      event.clearMetadata(section);

      if (values !== null && typeof values === 'object') {
        event.addMetadata(section, values as Record<string, unknown>);
      }
    });
  }
}

function writeUser(event: Event, scrubbed: unknown): void {
  if (scrubbed === null || typeof scrubbed !== 'object') {
    return;
  }

  const user = scrubbed as { id?: unknown; email?: unknown; name?: unknown };

  safely(() => {
    event.setUser(asString(user.id), asString(user.email), asString(user.name));
  });
}

/**
 * Replace the feature flags with their scrubbed forms.
 *
 * A variant is a value the application chose and has no key name to match on,
 * so in practice this is stage 1's seam: a wrapped value used as a variant
 * becomes its marker here and nothing else changes.
 */
function writeFeatureFlags(event: Event, scrubbed: unknown): void {
  if (!Array.isArray(scrubbed)) {
    return;
  }

  safely(() => {
    event.clearFeatureFlags();
    event.addFeatureFlags(
      scrubbed.filter(
        (flag): flag is { name: string; variant?: string | null } =>
          flag !== null &&
          typeof flag === 'object' &&
          typeof (flag as { name: unknown }).name === 'string'
      )
    );
  });
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

/**
 * Read a property, treating a refusal as absence.
 *
 * A callback runs against objects this package did not create, and one of them
 * may be a Proxy or carry a throwing getter. A region that refuses the question
 * is left out of the snapshot, and therefore left alone, rather than taking out
 * the whole scrub.
 */
function read(target: object, key: string): unknown {
  try {
    return (target as Record<string, unknown>)[key];
  } catch {
    return undefined;
  }
}

/**
 * Write a scrubbed value back, skipping `undefined`.
 *
 * `undefined` means the snapshot did not carry this region, and the two ways
 * that happens want the same answer. The region was genuinely absent, in which
 * case writing `undefined` changes nothing; or the read was refused by a
 * throwing getter or a Proxy, in which case the region is still there and
 * unscrubbed, and deleting it would be a silent write of somebody else's data
 * out of the event. Leaving it is the wrong answer too, but it is the wrong
 * answer this file can be sure about: the guard around the seam turns a scrub
 * that could not read the payload into the stub, and `emptyEvent` clears
 * through `overwrite` rather than through this.
 */
function assign(target: object, key: string, value: unknown): void {
  if (value === undefined) {
    return;
  }

  overwrite(target, key, value);
}

/** Write a value back whatever it is, treating a refusal as a no-op. */
function overwrite(target: object, key: string, value: unknown): void {
  try {
    (target as Record<string, unknown>)[key] = value;
  } catch {
    // A frozen or accessor-only field. Nothing was written, which is the same
    // outcome as a region that was never in the snapshot.
  }
}

/**
 * Run a write, swallowing what it throws.
 *
 * Every caller is inside a vendor callback, and invariant 10 is that no callback
 * body throws. A single region that refuses to be written is a smaller problem
 * than a scrub that gives up on the whole event, and the guard around the seam
 * turns the latter into the stub anyway.
 */
function safely<T>(body: () => T): T | undefined {
  try {
    return body();
  } catch {
    return undefined;
  }
}
