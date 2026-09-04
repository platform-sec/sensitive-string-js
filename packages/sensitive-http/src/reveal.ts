import { Readable } from 'node:stream';

import { SensitiveString } from '@platform-sec/sensitive-string-core';
import type { RevealContext, SensitivityClass } from '@platform-sec/sensitive-string-core';

import { isAuthHeader, renderAuthHeader } from './auth.js';
import { UnserializableBodyError } from './errors.js';
import { assertNoMarker } from './marker.js';
import type { PlanRecorder } from './scrub.js';
import type { SensitiveHeaders, SensitiveQuery } from './types.js';

/**
 * The one walker. Every reveal these packages perform goes through it.
 *
 * It differs from the sketch in INTEGRATION_IDEAS.md in three ways, each of
 * which was a measured leak:
 *
 * - It descends into class instances by own enumerable properties, the same
 *   walk `redactInStructure` performs. A walk that descends only into objects
 *   whose prototype is `Object.prototype` returns every DTO untouched, and a
 *   DTO-shaped codebase is the normal case.
 * - It refuses a `Map` or a `Set` rather than passing it through. axios
 *   serializes a `Map` in a JSON body to `{}`, so the field is not redacted,
 *   it is gone.
 * - It builds a new structure. The caller's objects are never mutated, so the
 *   revealed values are not reachable from anything the caller still holds.
 */

/**
 * `instanceof SensitiveString` narrows to `SensitiveString<any>`, because the
 * class is generic in its sensitivity class and the check says nothing about
 * which one. The predicate names the union instead, so nothing downstream of
 * the narrowing is typed `any`. The same shape `sensitive-testing` uses.
 */
export function isSensitive(value: unknown): value is SensitiveString<SensitivityClass> {
  return value instanceof SensitiveString;
}

/**
 * Values a client knows how to send, and that a rebuild would corrupt.
 *
 * `Date` is on the list for a blunt reason: it has no own enumerable
 * properties, so the generic branch would turn it into `{}` and destroy it,
 * which is the same silent data loss the `Map` refusal exists to prevent.
 * `Buffer` and every other `ArrayBufferView` are on it because a client sends
 * them as bytes. `FormData` and `URLSearchParams` are on it because they are
 * already-stringified containers: an instance put into one became a marker
 * before the walker ever ran, so there is nothing left to reveal, and the
 * marker is the only evidence. That is what the guard scan in `prepare` is for.
 */
function isPassThrough(value: object): boolean {
  if (
    value instanceof Date ||
    value instanceof RegExp ||
    value instanceof URL ||
    value instanceof URLSearchParams ||
    value instanceof ArrayBuffer ||
    ArrayBuffer.isView(value) ||
    value instanceof Readable
  ) {
    return true;
  }

  const global = globalThis as {
    ReadableStream?: unknown;
    Blob?: unknown;
    FormData?: unknown;
    Headers?: unknown;
    Request?: unknown;
  };

  return (
    (typeof global.ReadableStream === 'function' && value instanceof ReadableStream) ||
    (typeof global.Blob === 'function' && value instanceof Blob) ||
    (typeof global.FormData === 'function' && value instanceof FormData) ||
    (typeof global.Headers === 'function' && value instanceof Headers) ||
    (typeof global.Request === 'function' && value instanceof Request)
  );
}

/** Containers a JSON body cannot represent, and that a client silently drops. */
function refusedContainer(value: object): string | undefined {
  if (value instanceof Map) {
    return 'Map';
  }

  if (value instanceof Set) {
    return 'Set';
  }

  if (value instanceof WeakMap) {
    return 'WeakMap';
  }

  if (value instanceof WeakSet) {
    return 'WeakSet';
  }

  if (value instanceof Promise) {
    return 'Promise';
  }

  return typeof value === 'function' ? 'Function' : undefined;
}

/**
 * Reveal every `SensitiveString` reachable from `value` into a fresh structure.
 *
 * @param value - The caller's headers, query or body. Not mutated.
 * @param ctx - The per-attempt context, so the audit record names the host.
 * @param plan - The write side of the scrub plan, recorded as the walk goes.
 * @param path - Dot path of `value`, used for plan positions and for errors.
 *
 * @throws UnserializableBodyError for a `Map`, `Set` or function value.
 * @throws ExpiredSensitiveValueError from core, before any byte is written,
 *   when a value's deadline has passed.
 */
export function revealOutgoing(
  value: unknown,
  ctx: RevealContext,
  plan: PlanRecorder,
  path = '',
  seen: WeakMap<object, unknown> = new WeakMap()
): unknown {
  if (isSensitive(value)) {
    plan.record(path, value);

    return value.reveal(ctx);
  }

  if (value === null || typeof value !== 'object') {
    if (typeof value === 'function') {
      throw new UnserializableBodyError(path, 'Function');
    }

    return value;
  }

  // A body may legitimately share a reference or contain a cycle. Without this
  // the adversarial cycle test overflows the stack instead of passing. The map
  // is populated before the children are walked, which is how `redactCopy`
  // handles the same problem in core.
  const existing = seen.get(value);

  if (existing !== undefined) {
    return existing;
  }

  const refused = refusedContainer(value);

  if (refused !== undefined) {
    throw new UnserializableBodyError(path, refused);
  }

  if (isPassThrough(value)) {
    return value;
  }

  if (Array.isArray(value)) {
    const out: unknown[] = [];
    seen.set(value, out);

    value.forEach((item, index) => {
      out[index] = revealOutgoing(item, ctx, plan, `${path}[${index}]`, seen);
    });

    return out;
  }

  // Own enumerable properties, the same walk `redactInStructure` performs, so a
  // class-instance body is revealed rather than shipped as markers. A prototype
  // getter holding an instance is not visited, matching `redactInStructure`,
  // and each README says so.
  const out: Record<string, unknown> = {};
  seen.set(value, out);

  for (const [key, item] of entriesOf(value)) {
    out[key] = revealOutgoing(item, ctx, plan, path === '' ? key : `${path}.${key}`, seen);
  }

  return out;
}

/**
 * `Object.entries`, with a getter that throws treated as absence.
 *
 * An ORM produces an object with an enumerable getter that throws for a
 * relation that was not loaded, and `Object.entries` invokes every one of them.
 * A throw from a getter must not be able to turn a request into an exception
 * from inside a walk the caller did not ask for.
 */
function entriesOf(value: object): [string, unknown][] {
  let keys: string[];

  try {
    keys = Object.keys(value);
  } catch {
    return [];
  }

  const out: [string, unknown][] = [];

  for (const key of keys) {
    try {
      out.push([key, (value as Record<string, unknown>)[key]]);
    } catch {
      // Unreadable. Skipping it is safe: there is nothing to reveal in a value
      // that cannot be read, and the client will hit the same getter itself.
    }
  }

  return out;
}

/**
 * Reveal a header record into strings, guarding each rendered value.
 *
 * Here rather than in `request.ts` so that every call to `reveal()` in this
 * package lives in this module or in `auth.ts`. That is not a style rule: the
 * suite asserts it with a source scan, so the two modules that can produce a
 * raw value are the two modules a reviewer has to read.
 */
export function revealHeaders(
  headers: SensitiveHeaders | undefined,
  context: RevealContext,
  recorder: PlanRecorder,
  scanOptions: { base64: boolean }
): Record<string, string> {
  const out: Record<string, string> = {};

  for (const [name, value] of Object.entries(headers ?? {})) {
    if (value === undefined || value === null) {
      // An absent optional header is absent rather than empty.
      continue;
    }

    let rendered: string;

    if (isAuthHeader(value)) {
      rendered = renderAuthHeader(value, name, context, recorder);
    } else if (isSensitive(value)) {
      recorder.record(name, value);
      rendered = value.reveal(context);
    } else {
      rendered = String(value);
    }

    assertNoMarker(rendered, `header '${name}'`, scanOptions);
    out[name] = rendered;
  }

  return out;
}

/** Reveal a query record into primitives, which is what got's own validator demands. */
export function revealQuery(
  query: SensitiveQuery | undefined,
  context: RevealContext,
  recorder: PlanRecorder,
  scanOptions: { base64: boolean }
): [string, string][] {
  if (query === undefined) {
    return [];
  }

  const out: [string, string][] = [];

  for (const [key, value] of Object.entries(query)) {
    for (const item of Array.isArray(value) ? value : [value]) {
      if (item === undefined || item === null) {
        continue;
      }

      let rendered: string;

      if (isSensitive(item)) {
        recorder.record(key, item);
        rendered = item.reveal(context);
      } else {
        rendered = String(item);
      }

      assertNoMarker(rendered, `query parameter '${key}'`, scanOptions);
      out.push([key, rendered]);
    }
  }

  return out;
}

/** Reveal a form record and encode it, so the guard reads the encoding it produced. */
export function revealForm(
  form: SensitiveQuery | undefined,
  context: RevealContext,
  recorder: PlanRecorder,
  scanOptions: { base64: boolean }
): string | undefined {
  if (form === undefined) {
    return undefined;
  }

  const params = new URLSearchParams();

  for (const [key, value] of revealQuery(form, context, recorder, scanOptions)) {
    params.append(key, value);
  }

  const text = params.toString();

  // Percent-encoded, which is the encoding `%5BREDACTED%3Acredential%5D` hides
  // in and which a literal-only scan misses.
  assertNoMarker(text, 'form body', scanOptions);

  return text;
}
