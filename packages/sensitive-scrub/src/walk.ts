import {
  SensitiveString,
  redactCopy,
  sensitiveClassesIn,
  type SensitivityClass,
} from '@platform-sec/sensitive-string-core';

import { denied, isUrlPosition, scrubUrl } from './deny.js';
import type { PayloadKind, ResolvedScrubPolicy, ScrubReport } from './types.js';
import { matchValue } from './values.js';

/**
 * The staged walk over a captured payload.
 *
 * Two traversals, one per stage, and the report is accumulated during the
 * second rather than computed by a third:
 *
 * 1. `redactCopy` replaces every `SensitiveString` and every `serialize()`
 *    result. This is core's walk, not a copy of it. It keeps prototypes, keeps
 *    an object referenced twice as one shared reference, and does not mutate
 *    its input. `redactInStructure` is the log-line walk and is wrong here: it
 *    replaces a repeat visit with `'[Circular]'`, which corrupts a payload that
 *    legitimately holds the same object at two paths, and it drops symbol keys.
 *
 * 2. One walk over the original and the copy together applies the denylist to
 *    the copy and reads the report off the original. Reading the report off the
 *    original is not an optimisation, it is the only correct order: a marker
 *    sighting means a marker arrived in *captured* data, which is evidence that
 *    some other integration sent a placeholder where a value belonged, and
 *    stage 1 has by then written markers of its own everywhere a wrapped value
 *    stood. Counted after stage 1, every sighting would be this package's own.
 *
 * The pairing also decides what may be written to. `redactCopy` builds a fresh
 * object or array for everything it descends into and returns the same
 * reference for everything it passes through, so `copy !== original` is an
 * exact test for "this node is ours to modify". Nothing reachable from the
 * caller's payload is ever mutated.
 */

/** Own enumerable string keys, or `null` when the value is not a walkable structure. */
type Entries = readonly (readonly [string, unknown])[];

/**
 * A redaction marker sitting in captured data.
 *
 * Anchored to the two shapes this library produces, `[REDACTED]` and
 * `[REDACTED:<class>]`. A custom policy can produce any string it likes, so
 * this is a recognizer for the defaults rather than a proof of absence, and
 * the report says "seen", not "none".
 */
const MARKER = /\[REDACTED(?::([^\]\s]{1,64}))?\]/g;

/**
 * Read a named property, treating a refusal as absence.
 *
 * The same rule as core's `probeProperty`, which is not exported. A walk runs
 * against objects the library did not create, and a Proxy may throw for an
 * unknown name rather than answering `undefined`; envalid's `cleanEnv()`
 * result is the case that found it. An object that refuses the question is
 * walked like any other object rather than failing the whole scrub.
 */
function probe(value: object, name: string): unknown {
  try {
    return (value as Record<string, unknown>)[name];
  } catch {
    return undefined;
  }
}

/**
 * The entries to descend into, or `null` for a leaf.
 *
 * Only arrays and objects, and only the own enumerable string keys, which is
 * what `JSON.stringify` visits and what `redactCopy` copied. A value that
 * refuses enumeration is treated as a leaf rather than taking out the scrub.
 */
function entriesOf(value: unknown): Entries | null {
  if (value === null || typeof value !== 'object') {
    return null;
  }

  try {
    return Object.entries(value);
  } catch {
    return null;
  }
}

interface Accumulator {
  /**
   * Originals already surveyed, so an object referenced at two paths counts
   * once. `redactCopy` keeps a shared reference shared, and a value held twice
   * is one value.
   */
  readonly surveyed: WeakSet<object>;
  instances: number;
  readonly classes: Set<SensitivityClass>;
  readonly labels: Set<string>;
  readonly deniedKeys: Set<string>;
  readonly deniedValues: Set<string>;
  markersSeen: number;
  readonly markerClasses: Set<string>;
}

/**
 * Scrub one payload and describe what was in it.
 *
 * @param payload - The payload as the vendor's hook handed it over
 * @param policy - A policy already resolved by `resolveScrubPolicy`
 * @param kind - Which of the vendor's payload shapes this is
 * @returns The scrubbed payload and the report. The input is not modified.
 */
export function scrubPayload(
  payload: unknown,
  policy: ResolvedScrubPolicy,
  kind: PayloadKind
): { payload: unknown; report: ScrubReport } {
  const accumulator: Accumulator = {
    surveyed: new WeakSet(),
    instances: 0,
    classes: new Set(),
    labels: new Set(),
    deniedKeys: new Set(),
    deniedValues: new Set(),
    markersSeen: 0,
    markerClasses: new Set(),
  };

  // Stage 1.
  const copy = redactCopy(payload);

  // Stage 2, and the report. The root is surveyed here because `visit`
  // surveys the children it iterates, which is what lets a denied or
  // URL-rewritten child still be counted before it is replaced.
  survey(payload, copy, accumulator, policy);

  const scrubbed = visit(payload, copy, '', policy, accumulator, new WeakSet());

  return { payload: scrubbed, report: buildReport(kind, policy, accumulator, false) };
}

/**
 * Describe a payload that was never scrubbed, for the failure path.
 *
 * `failed: true` with empty counts. A scrubber failing on every payload of one
 * shape is a bug worth an alert, and it is invisible if the only evidence is a
 * slightly smaller event.
 */
export function failedReport(kind: PayloadKind, policy: ResolvedScrubPolicy): ScrubReport {
  return buildReport(
    kind,
    policy,
    {
      surveyed: new WeakSet(),
      instances: 0,
      classes: new Set(),
      labels: new Set(),
      deniedKeys: new Set(),
      deniedValues: new Set(),
      markersSeen: 0,
      markerClasses: new Set(),
    },
    true
  );
}

/**
 * Fold a second pass's findings into the report a seam will publish.
 *
 * A vendor package sometimes has to walk one payload in more than one piece.
 * The reason is always the same: a region of the payload has already been
 * through this library's own scrubber at an earlier seam, so stage 1 has
 * written a marker everywhere a wrapped value stood in it, and a marker
 * sighting means a marker arrived in *captured* data, which is evidence that
 * some other integration sent a placeholder where a value belonged. A pass over
 * such a region runs with `onMarker: 'ignore'` and its findings arrive here.
 *
 * So the markers come from the primary report alone, and everything else is the
 * union. Invariant 18 is one report per payload, and this is what keeps that
 * true when the walk had to happen twice.
 *
 * @param primary - The pass over the regions the seam sees first
 * @param secondary - A pass over a region an earlier seam already scrubbed
 */
export function mergeReports(primary: ScrubReport, secondary: ScrubReport): ScrubReport {
  const labels =
    primary.labels === undefined
      ? undefined
      : [...new Set([...primary.labels, ...(secondary.labels ?? [])])];

  const merged = {
    kind: primary.kind,
    instances: primary.instances + secondary.instances,
    classes: new Set([...primary.classes, ...secondary.classes]),
    deniedKeys: [...new Set([...primary.deniedKeys, ...secondary.deniedKeys])],
    deniedValues: [...new Set([...primary.deniedValues, ...secondary.deniedValues])],
    markersSeen: primary.markersSeen,
    markerClasses: primary.markerClasses,
    failed: primary.failed || secondary.failed,
  };

  // `exactOptionalPropertyTypes` is on, so `labels` is absent rather than
  // present and undefined when the caller did not opt in.
  return labels === undefined ? merged : { ...merged, labels };
}

function buildReport(
  kind: PayloadKind,
  policy: ResolvedScrubPolicy,
  accumulator: Accumulator,
  failed: boolean
): ScrubReport {
  const base = {
    kind,
    instances: accumulator.instances,
    classes: accumulator.classes,
    deniedKeys: [...accumulator.deniedKeys],
    deniedValues: [...accumulator.deniedValues],
    markersSeen: policy.onMarker === 'ignore' ? 0 : accumulator.markersSeen,
    markerClasses: policy.onMarker === 'ignore' ? new Set<string>() : accumulator.markerClasses,
    failed,
  };

  // `exactOptionalPropertyTypes` is on, so `labels` is absent rather than
  // present and undefined when the caller did not opt in.
  return policy.reportLabels ? { ...base, labels: [...accumulator.labels] } : base;
}

/**
 * Walk one node of the original alongside its counterpart in the copy.
 *
 * @returns What belongs at this position in the scrubbed payload.
 */
function visit(
  original: unknown,
  copy: unknown,
  path: string,
  policy: ResolvedScrubPolicy,
  accumulator: Accumulator,
  seen: WeakSet<object>
): unknown {
  if (copy === original || copy === null || typeof copy !== 'object') {
    // Either a leaf, or something `redactCopy` passed through by reference:
    // a Date, a RegExp, a URL, an Error, a typed array, a stream. Not ours to
    // modify, and by `redactCopy`'s contract not something that reaches a
    // `SensitiveString` on the JSON path either. A Map or a Set comes back as
    // a redacted copy instead, and reaches the loop below with no own
    // enumerable keys, which is what `JSON.stringify` sees of it too: the
    // denylist has no key names to apply inside one.
    return copy;
  }

  // A shared reference reached a second time. The copy is the same object as
  // the one already scrubbed, so there is nothing left to do and counting it
  // again would inflate the report. A cycle terminates here too.
  if (seen.has(copy)) {
    return copy;
  }
  seen.add(copy);

  const copyEntries = entriesOf(copy);

  if (copyEntries === null) {
    return copy;
  }

  const container = copy as Record<string, unknown>;

  for (const [key, child] of copyEntries) {
    const childPath = path === '' ? key : `${path}.${key}`;
    const childOriginal = childOf(original, key);

    // Before the branches below, so a value about to be censored still
    // contributes its class to the report. An operator wants to know a
    // credential was in scope whether or not a key name caught it.
    const redactedByStageOne = survey(childOriginal, child, accumulator, policy);

    // A value stage 1 already replaced keeps the marker its own policy chose.
    // `[REDACTED:credential]` and the censor are equally safe and the marker
    // says more: it tells an operator which class stood here. Censoring over
    // it would trade that away for uniformity.
    if (!redactedByStageOne && denied(key, childPath, policy.denyKeys, policy.denyPaths)) {
      // Replaced, never deleted. An absent key and a censored key look the
      // same to a reader of the event and mean different things to somebody
      // debugging why a header was not sent at all.
      container[key] = policy.censor;
      accumulator.deniedKeys.add(key);
      continue;
    }

    if (typeof child === 'string' && isUrlPosition(key, childPath, policy.urlKeys)) {
      const scrubbedUrl = scrubUrl(child, policy.denyKeys, policy.censor);

      if (scrubbedUrl !== null) {
        container[key] = scrubbedUrl.value;

        for (const name of scrubbedUrl.replaced) {
          accumulator.deniedKeys.add(name);
        }

        continue;
      }
    }

    // After the URL branch, so a position whose route is worth keeping is
    // rewritten rather than censored whole. The shipped patterns are anchored
    // and none of them describes a URL, so the two do not compete in practice;
    // the order is what settles it when a caller's own pattern does. Skipped
    // for a value stage 1 already replaced, for the reason the denylist skips
    // it: the marker names a class and the censor does not.
    if (!redactedByStageOne && typeof child === 'string' && policy.denyValues.length > 0) {
      const shape = matchValue(child, policy.denyValues);

      if (shape !== null) {
        container[key] = policy.censor;
        accumulator.deniedValues.add(shape.name);
        continue;
      }
    }

    container[key] = visit(childOriginal, child, childPath, policy, accumulator, seen);
  }

  return copy;
}

/**
 * The node in the original that corresponds to a key in the copy.
 *
 * The two structures line up because `redactCopy` copies own enumerable string
 * keys and nothing else. When they do not, because the original refused the
 * read, the survey sees `undefined` and reports nothing, which is the same
 * answer it gives for a key that was genuinely absent.
 */
function childOf(original: unknown, key: string): unknown {
  if (original === null || typeof original !== 'object') {
    return undefined;
  }

  return probe(original, key);
}

/**
 * Read the report's facts off one original node.
 *
 * Three findings, and each is discriminated without importing anything from
 * core beyond the four names invariant 12 allows:
 *
 * - A `SensitiveString`, by `instanceof`. Its class and label are public.
 * - A `serialize()` result, by the one other case in which `redactCopy` turns
 *   an object into a string. `sensitiveClassesIn` answers in constant time for
 *   a node carrying the wire marker, because it recognizes it and returns.
 * - A redaction marker in a captured string, which is not this package's
 *   output because this reads the payload as it arrived.
 *
 * @returns Whether stage 1 replaced this node, which is what tells the caller
 *          that the denylist has nothing left to do here.
 */
function survey(
  original: unknown,
  copy: unknown,
  accumulator: Accumulator,
  policy: ResolvedScrubPolicy
): boolean {
  const isObject = typeof original === 'object' && original !== null;

  // A value held at two paths is one value. Counting it twice would inflate
  // the report, and `redactCopy` keeps a shared reference shared.
  const repeat = isObject && accumulator.surveyed.has(original);

  if (isObject && !repeat) {
    accumulator.surveyed.add(original);
  }

  if (original instanceof SensitiveString) {
    // The generic parameter is unbound at this point, so `klass` widens to
    // `any` without the annotation. Core's own walks narrow it the same way.
    const wrapped = original as SensitiveString<SensitivityClass>;

    if (!repeat) {
      accumulator.instances += 1;
      accumulator.classes.add(wrapped.klass);

      if (wrapped.label !== undefined) {
        accumulator.labels.add(wrapped.label);
      }
    }

    return true;
  }

  // The one other case in which `redactCopy` turns an object into a string is
  // a `serialize()` result, whose raw value `JSON.stringify` would otherwise
  // emit faithfully.
  if (isObject && typeof copy === 'string') {
    if (!repeat) {
      accumulator.instances += 1;

      for (const klass of sensitiveClassesIn(original)) {
        accumulator.classes.add(klass);
      }

      const label = probe(original, 'label');

      if (typeof label === 'string') {
        accumulator.labels.add(label);
      }
    }

    return true;
  }

  if (typeof original === 'string' && policy.onMarker !== 'ignore') {
    countMarkers(original, accumulator);
  }

  return false;
}

function countMarkers(value: string, accumulator: Accumulator): void {
  // A fresh lastIndex per subject: the regex is global and shared.
  MARKER.lastIndex = 0;

  let match = MARKER.exec(value);

  while (match !== null) {
    accumulator.markersSeen += 1;

    if (match[1] !== undefined) {
      accumulator.markerClasses.add(match[1]);
    }

    match = MARKER.exec(value);
  }
}
