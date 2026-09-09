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

/**
 * Whether this value is an offence in itself, ignoring anything inside it.
 *
 * The kind alone, with no position: on the path that matters the answer is
 * `undefined` and a position would be something to describe and throw away.
 */
function scalarOffence(value: unknown): OffenceKind | undefined {
  if (value instanceof SensitiveString) return 'instance';
  if (typeof value === 'string') return containsRedactionMarker(value) ? 'marker' : undefined;
  return undefined;
}

/** Whether a walk should go inside this value at all. */
function descendable(value: unknown): value is object {
  return typeof value === 'object' && value !== null && isWalkable(value);
}

/** A cycle guard seeded with the container that is about to be walked. */
function marksFor(container: object): WeakSet<object> {
  const marks = new WeakSet<object>();
  marks.add(container);
  return marks;
}

/**
 * Find the first value inside a container that must not reach the driver.
 *
 * The path is built as the stack unwinds rather than carried down it, and the
 * cycle guard is created on the first descent rather than on entry. Both are
 * the same trade: a bag with nothing wrong in it is the overwhelming case, and
 * it should pay for neither the positions it will not name nor the cycles it
 * cannot have. A bag with something wrong in it pays one object and one string
 * per level on the way out, which is a cost paid once, on the way to throwing.
 *
 * `seen` is `undefined` only in the outermost frame. Anything deeper was
 * reached by the descent below, which creates the guard before it recurses, so
 * every frame that could meet a cycle has one.
 */
function findOffender(container: object, seen: WeakSet<object> | undefined): Offence | undefined {
  let marks = seen;

  if (Array.isArray(container)) {
    for (let index = 0; index < container.length; index++) {
      const item: unknown = container[index];

      const kind = scalarOffence(item);
      if (kind !== undefined) return { path: `[${String(index)}]`, kind };
      if (!descendable(item)) continue;

      marks ??= marksFor(container);
      if (marks.has(item)) continue;
      marks.add(item);

      const found = findOffender(item, marks);
      if (found !== undefined) return { path: `[${String(index)}]${found.path}`, kind: found.kind };
    }

    return undefined;
  }

  const bag = container as Record<string, unknown>;

  // `Object.keys` rather than `Object.entries`: the same own enumerable
  // string-keyed properties, without a two-element array built per property.
  for (const key of Object.keys(bag)) {
    const item: unknown = bag[key];

    const kind = scalarOffence(item);
    if (kind !== undefined) return { path: `.${key}`, kind };
    if (!descendable(item)) continue;

    marks ??= marksFor(container);
    if (marks.has(item)) continue;
    marks.add(item);

    const found = findOffender(item, marks);
    if (found !== undefined) return { path: `.${key}${found.path}`, kind: found.kind };
  }

  return undefined;
}

/**
 * Check one bound value, allocating nothing unless it is a container.
 *
 * The path returned is relative to the value, so it is empty for the value
 * itself. {@link findUnsafeParameter} prepends the position in the bag.
 */
function checkOne(value: unknown): Offence | undefined {
  if (value === null || value === undefined) return undefined;

  const kind = scalarOffence(value);
  if (kind !== undefined) return { path: '', kind };
  if (!descendable(value)) return undefined;

  return findOffender(value, undefined);
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
 *
 * {@link findUnsafeParameter} does not call this. It reads the same three
 * shapes itself, in place, because materialising an entry array per statement
 * is most of what it used to cost. The two are held in agreement by a test that
 * runs both over the same bags rather than by one calling the other, so a shape
 * added here has to be added there as well.
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
 *
 * Reads the bag in place rather than through {@link parameterEntries}: this
 * runs per statement, and the entry array that function builds was the largest
 * part of the cost for the bag shape almost every statement has, a short list
 * of scalars. The two must agree on which shapes are read, and a test asserts
 * that they do.
 *
 * Measured on Node 22.15.0 over a clean bag, which is every bag in a working
 * application, median of seven rounds each in its own process:
 *
 * | bag | carrying entries and paths | reading in place |
 * |---|---|---|
 * | 5 scalars | 237 ns | 81 ns |
 * | 30 scalars | 1071 ns | 639 ns |
 * | 6 named scalars | 486 ns | 201 ns |
 * | 3 params, one nested array | 532 ns | 162 ns |
 * | one 4-level nesting | 1017 ns | 372 ns |
 *
 * Whether that is worth having depends on the driver, and it is worth saying so
 * rather than quoting the ratio alone: against a networked Postgres a saved
 * 300 ns is invisible, while against in-process `better-sqlite3`, where a small
 * query is single-digit microseconds, it is a few percent of the statement.
 */
export function findUnsafeParameter(params: unknown): Offence | undefined {
  if (Array.isArray(params)) {
    for (let index = 0; index < params.length; index++) {
      const found = checkOne(params[index]);
      if (found !== undefined) return { path: `${String(index)}${found.path}`, kind: found.kind };
    }

    return undefined;
  }

  if (params instanceof Map) {
    for (const [key, value] of params) {
      const found = checkOne(value);
      if (found !== undefined) return { path: `${String(key)}${found.path}`, kind: found.kind };
    }

    return undefined;
  }

  if (typeof params !== 'object' || params === null) return undefined;

  const bag = params as Record<string, unknown>;

  for (const key of Object.keys(bag)) {
    const found = checkOne(bag[key]);
    if (found !== undefined) return { path: `${key}${found.path}`, kind: found.kind };
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
