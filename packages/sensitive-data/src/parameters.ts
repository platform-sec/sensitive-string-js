import { SensitiveString, containsRedactionMarker } from '@platform-sec/sensitive-string-core';

/**
 * The bound parameters of a statement, on their way to a driver or to a log.
 *
 * Two questions, asked at two different seams, over the same values. Below the
 * ORM: is anything here still a `SensitiveString`, or a string that is already
 * a redaction marker? Either one means a value reached the driver through a
 * path with no column behind it, and both are refusals. At the query logger:
 * which of these can be printed?
 *
 * Both were written twice, once against TypeORM and once against Drizzle, and
 * each copy covered a shape the other missed. The walk here is the union. What
 * stays with each consumer is its error type and its censor text, because those
 * are what a caller catches and greps for.
 */

/** Why a parameter was refused. */
export type OffenceKind = 'instance' | 'marker';

/** Where the offending value was, and what it was. */
export interface Offence {
  /** Position within the bag: `2`, `email`, `0.filters[1]`. */
  readonly path: string;
  readonly kind: OffenceKind;
}

/**
 * Whether descending into this value could find anything.
 *
 * Arrays and plain objects only. A `Date`, a `Buffer` or a driver's own wrapper
 * holds no `SensitiveString`, and walking a `Buffer`'s indices would cost more
 * than the statement it is about to be bound to. Checked before a walk starts,
 * so the common parameter shapes allocate nothing.
 */
function isWalkable(value: object): boolean {
  if (Array.isArray(value)) return true;
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/** Find the first value inside a container that must not reach the driver. */
function findOffender(value: unknown, path: string, seen: WeakSet<object>): Offence | undefined {
  if (value instanceof SensitiveString) return { path, kind: 'instance' };
  if (typeof value === 'string') {
    return containsRedactionMarker(value) ? { path, kind: 'marker' } : undefined;
  }
  if (typeof value !== 'object' || value === null) return undefined;
  if (seen.has(value)) return undefined;
  if (!isWalkable(value)) return undefined;

  seen.add(value);

  if (Array.isArray(value)) {
    for (const [index, item] of value.entries()) {
      const found = findOffender(item, `${path}[${String(index)}]`, seen);
      if (found !== undefined) return found;
    }
    return undefined;
  }

  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    const found = findOffender(item, `${path}.${key}`, seen);
    if (found !== undefined) return found;
  }
  return undefined;
}

/** Check one bound value, allocating nothing unless it is a container. */
function checkOne(value: unknown, path: string): Offence | undefined {
  if (value === null || value === undefined) return undefined;
  if (value instanceof SensitiveString) return { path, kind: 'instance' };
  if (typeof value === 'string') {
    return containsRedactionMarker(value) ? { path, kind: 'marker' } : undefined;
  }
  if (typeof value !== 'object' || !isWalkable(value)) return undefined;

  return findOffender(value, path, new WeakSet<object>());
}

/**
 * The entries of a parameter bag, whatever shape it arrived in.
 *
 * Three shapes, because the two consumers this was extracted from each covered
 * only what their own driver could reach and each missed what the other saw.
 * An array is the usual one. A named map is what `DataSource.query(sql, { e })`
 * hands a runner unchanged, and `better-sqlite3` rejects named placeholders, so
 * the driver an application develops against is often not the one that would
 * have shown the hole. A `Map` is neither, and costs one `instanceof` to cover.
 *
 * Every other object is walked by its own enumerable entries without a
 * prototype check, so a class instance and a bag from another realm are covered
 * rather than passed over. Refusing has to be exhaustive; only a primitive is
 * skipped, and a primitive holds nothing.
 */
export function parameterEntries(params: unknown): [string, unknown][] {
  if (Array.isArray(params)) return params.map((value, index) => [String(index), value]);
  if (params instanceof Map) {
    return [...params.entries()].map(([key, value]) => [String(key), value] as [string, unknown]);
  }
  if (typeof params !== 'object' || params === null) return [];
  return Object.entries(params as Record<string, unknown>);
}

/**
 * The first parameter that must not reach the driver, or `undefined`.
 *
 * Reporting rather than throwing, so each consumer raises its own error type
 * with its own message. A caller that wants the refusal wraps this in three
 * lines; a caller that wants to warn instead can.
 */
export function findUnsafeParameter(params: unknown): Offence | undefined {
  for (const [path, value] of parameterEntries(params)) {
    const found = checkOne(value, path);
    if (found !== undefined) return found;
  }
  return undefined;
}

/**
 * Replace the parameters of a statement that must not be logged as they are.
 *
 * Strings go, everything else stays. A classified column's revealed value is
 * always a string, so the ids, the timestamps and the booleans that make a log
 * entry useful survive, and the one shape that could carry a secret does not.
 *
 * A `SensitiveString` and a string holding a redaction marker are replaced
 * whatever `redactStrings` says. An instance among the parameters means the
 * column mapping never ran, and a marker means a column is already corrupt;
 * neither should reach a log looking ordinary.
 *
 * The identity of the bag is preserved when nothing changed, so a logger that
 * was going to print the parameters unchanged is handed the same object rather
 * than a copy of it.
 *
 * @param redactStrings - Censor every string, not only the recognisable ones.
 *   Driven by {@link touchesClassifiedColumn} at the call site, or by a
 *   consumer's own always-on option.
 */
export function redactParameters(params: unknown, redactStrings: boolean, censor: string): unknown {
  let changed = false;

  const redactOne = (value: unknown): unknown => {
    if (value instanceof SensitiveString) {
      changed = true;
      return censor;
    }
    if (typeof value === 'string' && (redactStrings || containsRedactionMarker(value))) {
      changed = true;
      return censor;
    }
    return value;
  };

  if (Array.isArray(params)) {
    const out: unknown[] = params.map(redactOne);
    return changed ? out : params;
  }

  // A named bag, rebuilt as a plain object. The walk above covers more shapes
  // than this does, deliberately: refusing has to be exhaustive, whereas a log
  // line that keeps the shape it arrived in is only a nicety, and rebuilding a
  // `Map` or a class instance as a plain object would change what the inner
  // logger sees.
  if (typeof params !== 'object' || params === null) return params;
  const proto: unknown = Object.getPrototypeOf(params);
  if (proto !== Object.prototype && proto !== null) return params;

  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(params as Record<string, unknown>)) {
    out[key] = redactOne(value);
  }
  return changed ? out : params;
}
