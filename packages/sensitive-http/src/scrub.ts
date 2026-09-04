import type { SensitiveString, SensitivityClass } from '@platform-sec/sensitive-string-core';

import { SensitiveScrubError } from './errors.js';

/**
 * The plan, and what it is for.
 *
 * A revealed value does not stop existing when the request is sent. Measured on
 * axios 1.20.0, got 16.0.0 and ky 2.1.0, it survives on the rejection in
 * `error.config.headers`, `error.options.headers` and `error.request` and, for
 * the first two, on the **resolution** as well, so `console.log(res)` after a
 * successful call prints the credential and no error ever existed for an error
 * handler to scrub.
 *
 * The obvious fix is to search the settled object for the raw value. That
 * requires holding the raw value across the settlement path, which is the thing
 * being avoided. So the walker records where it revealed instead: a position,
 * and the redacted form of the value that went there. The scrub then overwrites
 * exactly those positions and never sees a raw value at all.
 */

/** One recorded reveal: where it went, and what to put back. */
export interface PlanEntry {
  /** Header name (lowercased), query key, or dot path into the body. */
  readonly position: string;
  /**
   * Which half of the request it went into.
   *
   * Carried on the entry rather than inferred from which of the three lists
   * holds the position, because a request can legitimately name the same thing
   * twice: `headers: { token }` and `searchParams: { token }` both record the
   * position `token`, and inferring the section then answers `header` for both,
   * so the query lookup finds nothing and the scrub falls back to a generic
   * marker instead of the value's own class.
   */
  readonly section: PlanSection;
  readonly klass: SensitivityClass;
  /**
   * The value's own redacted form, captured at reveal time.
   *
   * The class marker rather than an empty string, so an operator reading a
   * scrubbed log sees that a value was there and was removed, which is a
   * different thing from the header being missing.
   */
  readonly marker: string;
}

/** Where the reveal happened, which decides which client property the scrub rewrites. */
export type PlanSection = 'header' | 'query' | 'body';

export interface ScrubPlan {
  /** Header names whose values were revealed for this request, lowercased. */
  readonly headers: readonly string[];
  /** Dot paths in the request body whose values were revealed. */
  readonly bodyPaths: readonly string[];
  /** Query parameter names whose values were revealed. */
  readonly queryKeys: readonly string[];
  /** Every entry, in the order the walker recorded it. */
  readonly entries: readonly PlanEntry[];
}

/** Nothing was revealed, so the client's own objects are returned untouched. */
export function planIsEmpty(plan: ScrubPlan): boolean {
  return plan.entries.length === 0;
}

/** The redacted replacement for a recorded position, or undefined if not recorded. */
export function markerFor(
  plan: ScrubPlan,
  section: PlanSection,
  position: string
): string | undefined {
  const wanted = section === 'header' ? position.toLowerCase() : position;

  return plan.entries.find((entry) => entry.section === section && entry.position === wanted)
    ?.marker;
}

/**
 * The write side of a plan, handed to the walker.
 *
 * It never receives a raw value: `record` takes the instance and reads its
 * redacted form through `String()`, which is what `toString()` already
 * produces.
 */
export interface PlanRecorder {
  record(position: string, value: SensitiveString<SensitivityClass>): void;
}

export class PlanBuilder {
  readonly #headers: string[] = [];
  readonly #bodyPaths: string[] = [];
  readonly #queryKeys: string[] = [];
  readonly #entries: PlanEntry[] = [];

  /** A recorder bound to one section of the request. */
  section(kind: PlanSection): PlanRecorder {
    return {
      record: (position, value) => {
        this.#push(kind, position, value);
      },
    };
  }

  #push(kind: PlanSection, position: string, value: SensitiveString<SensitivityClass>): void {
    const normalized = kind === 'header' ? position.toLowerCase() : position;
    const list =
      kind === 'header' ? this.#headers : kind === 'query' ? this.#queryKeys : this.#bodyPaths;

    if (!list.includes(normalized)) {
      list.push(normalized);
    }

    this.#entries.push({
      position: normalized,
      section: kind,
      klass: value.klass,
      // `String()` goes through `toString()`, which redacts. No raw value is
      // read here and none is retained by the plan.
      marker: String(value),
    });
  }

  build(): ScrubPlan {
    return {
      headers: [...this.#headers],
      bodyPaths: [...this.#bodyPaths],
      queryKeys: [...this.#queryKeys],
      entries: [...this.#entries],
    };
  }
}

/** The empty plan, for a request that carried nothing sensitive. */
export const EMPTY_PLAN: ScrubPlan = Object.freeze({
  headers: Object.freeze([]),
  bodyPaths: Object.freeze([]),
  queryKeys: Object.freeze([]),
  entries: Object.freeze([]),
});

/**
 * Overwrite every planned header in a header bag, whatever shape it is.
 *
 * Handles a plain record, a `Headers`, and axios's `AxiosHeaders`, because the
 * five client packages hand this three different things and the difference is
 * not interesting enough to repeat five times. Missing headers are skipped:
 * a client is free not to have kept the header at all, and that is the outcome
 * this function wants.
 */
export function scrubHeaderBag(bag: unknown, plan: ScrubPlan): void {
  if (bag === null || typeof bag !== 'object') {
    return;
  }

  for (const name of plan.headers) {
    const marker = markerFor(plan, 'header', name) ?? '[REDACTED]';

    if (typeof (bag as Headers).set === 'function' && typeof (bag as Headers).get === 'function') {
      try {
        (bag as Headers).set(name, marker);
      } catch {
        // A frozen or immutable bag. The assertion below reports it.
      }

      continue;
    }

    const record = bag as Record<string, unknown>;

    for (const key of Object.keys(record)) {
      if (key.toLowerCase() === name) {
        // A frozen or read-only bag throws here under ESM's strict mode, and a
        // scrub that throws turns a settled call into a `TypeError` from inside
        // machinery the caller never asked for. `assertHeadersScrubbed` is what
        // decides whether the object is safe to hand back; this only tries.
        try {
          record[key] = marker;
        } catch {
          // Reported by the assertion, not here.
        }
      }
    }
  }
}

/** Read a header out of any of the three bag shapes, for the post-scrub assertion. */
export function readHeader(bag: unknown, name: string): unknown {
  if (bag === null || typeof bag !== 'object') {
    return undefined;
  }

  if (typeof (bag as Headers).get === 'function') {
    try {
      return (bag as Headers).get(name) ?? undefined;
    } catch {
      return undefined;
    }
  }

  const record = bag as Record<string, unknown>;

  for (const key of Object.keys(record)) {
    if (key.toLowerCase() === name) {
      return record[key];
    }
  }

  return undefined;
}

/** Overwrite every planned body path in a structure the client kept. */
export function scrubBody(body: unknown, plan: ScrubPlan): unknown {
  if (typeof body === 'string') {
    // Already serialized. There is no path to address, and rewriting JSON text
    // by string surgery would be worse than replacing it wholesale.
    return plan.bodyPaths.length > 0 ? '[REDACTED:body]' : body;
  }

  if (body === null || typeof body !== 'object') {
    return body;
  }

  for (const path of plan.bodyPaths) {
    try {
      setByPath(body, path, markerFor(plan, 'body', path) ?? '[REDACTED]');
    } catch {
      // Same reasoning as the header bag: a frozen body is reported by the
      // suite's leak walk rather than by an exception from inside the scrub.
    }
  }

  return body;
}

/** Overwrite every planned query key in a `URLSearchParams` or a plain record. */
export function scrubQuery(query: unknown, plan: ScrubPlan): void {
  if (query === null || typeof query !== 'object') {
    return;
  }

  for (const key of plan.queryKeys) {
    const marker = markerFor(plan, 'query', key) ?? '[REDACTED]';

    try {
      if (query instanceof URLSearchParams) {
        if (query.has(key)) {
          query.set(key, marker);
        }

        continue;
      }

      const record = query as Record<string, unknown>;

      if (Object.prototype.hasOwnProperty.call(record, key)) {
        record[key] = marker;
      }
    } catch {
      // Same reasoning as the header bag.
    }
  }
}

/**
 * Rewrite the planned query parameters inside a URL string the client kept.
 *
 * The wrapper merges the revealed query into the URL before handing it over,
 * which is what every client wants, and which means the URL is a third place
 * the value survives: axios keeps it as `config.url` on both settlement paths,
 * and got as `options.url`. Found by the error-scrub suite rather than by
 * reading the client, which is the usual way this class of leak turns up.
 */
export function scrubUrlString(url: unknown, plan: ScrubPlan): unknown {
  if (typeof url !== 'string' || plan.queryKeys.length === 0) {
    return url;
  }

  try {
    const parsed = new URL(url);
    let touched = false;

    for (const key of plan.queryKeys) {
      if (parsed.searchParams.has(key)) {
        parsed.searchParams.set(key, markerFor(plan, 'query', key) ?? '[REDACTED]');
        touched = true;
      }
    }

    return touched ? parsed.toString() : url;
  } catch {
    // Not parseable as an absolute URL, so the query cannot be rewritten
    // key by key. Dropping it whole is the only safe answer.
    const cut = url.indexOf('?');

    return cut === -1 ? url : `${url.slice(0, cut)}?[REDACTED]`;
  }
}

/**
 * Replace a revealed URL wherever a client interpolated it into a message.
 *
 * got 16's `HTTPError` message is `Request failed with status code 401
 * (Unauthorized): POST <full url>`, so a credential in a query parameter is in
 * the message text itself, which no property rewrite reaches. The design's
 * table recorded got's message as clean, and it is, for a credential in a
 * header; this is the query case that table did not cover.
 *
 * The raw URL is passed in by the caller, which still holds it for the duration
 * of the call. Nothing here retains it.
 */
export function scrubMessage(error: unknown, rawUrl: string, safeUrl: string): void {
  if (rawUrl === safeUrl || error === null || typeof error !== 'object') {
    return;
  }

  // `stack` as well as `message`. V8 renders the stack once, at construction,
  // with the message baked into its first line, so rewriting only `message`
  // leaves the value in every `console.error` and every reporter that prints a
  // stack, which is all of them.
  for (const field of ['message', 'stack'] as const) {
    const text = (error as Record<string, unknown>)[field];

    if (typeof text !== 'string' || !text.includes(rawUrl)) {
      continue;
    }

    try {
      (error as Record<string, unknown>)[field] = text.split(rawUrl).join(safeUrl);
    } catch {
      // A frozen error. Nothing else here can help, and the client packages
      // assert on the outcome rather than on this having succeeded.
    }
  }
}

/**
 * Assert that the scrub took, and refuse to hand back the object if it did not.
 *
 * It checks that each planned position now holds its marker rather than
 * searching for a raw value, because the plan deliberately does not hold raw
 * values. The stronger statement, that a canary appears nowhere in
 * `util.inspect(value, { depth: 8 })` or in `error.toJSON()`, is what the
 * security suites assert, and each of those assertions fails against a bare
 * client today.
 *
 * @throws SensitiveScrubError, on both settlement paths. On the success path
 *   that turns a 200 into a rejection, which is the one place these packages
 *   destroy a working call to keep a guarantee.
 */
export function assertHeadersScrubbed(
  bag: unknown,
  plan: ScrubPlan,
  client: string,
  where: string
): void {
  for (const name of plan.headers) {
    const marker = markerFor(plan, 'header', name);
    const current = readHeader(bag, name);

    if (current === undefined || current === null) {
      continue;
    }

    if (typeof current !== 'string' || (marker !== undefined && current !== marker)) {
      throw new SensitiveScrubError(client, `${where}.headers['${name}']`);
    }
  }
}

function setByPath(target: object, path: string, value: string): void {
  const parts = splitPath(path);
  let cursor: unknown = target;

  for (const part of parts.slice(0, -1)) {
    if (cursor === null || typeof cursor !== 'object') {
      return;
    }

    cursor = (cursor as Record<string, unknown>)[part];
  }

  const last = parts[parts.length - 1];

  if (last === undefined || cursor === null || typeof cursor !== 'object') {
    return;
  }

  if (!Object.prototype.hasOwnProperty.call(cursor, last)) {
    return;
  }

  (cursor as Record<string, unknown>)[last] = value;
}

/** `a.b[0].c` into `['a', 'b', '0', 'c']`, matching the paths the walker records. */
export function splitPath(path: string): string[] {
  const parts: string[] = [];

  for (const segment of path.split('.')) {
    const match = /^([^[\]]*)((?:\[\d+\])*)$/.exec(segment);

    if (match === null) {
      parts.push(segment);
      continue;
    }

    if (match[1] !== undefined && match[1] !== '') {
      parts.push(match[1]);
    }

    for (const index of (match[2] ?? '').matchAll(/\[(\d+)\]/g)) {
      const captured = index[1];

      if (captured !== undefined) {
        parts.push(captured);
      }
    }
  }

  return parts;
}
