import { SensitiveString, containsRedactionMarker } from '@platform-sec/sensitive-string-core';
import { classifiedColumnNames } from './column.js';
import { DrizzleParameterRefusedError } from './errors.js';
import type { LoggerLike, SensitiveLoggerOptions } from './types.js';

/** What a redacted parameter is replaced with. */
export const PARAMETER_CENSOR = '[REDACTED:drizzle-parameter]';

/** How much of a statement a refusal quotes. */
const STATEMENT_LIMIT = 200;

/** Marks a logger this package built, so `checkSchema()` can recognise one. */
export const SENSITIVE_LOGGER = Symbol.for('platform-sec.sensitive-string.drizzle.logger');

/**
 * Every identifier in a statement, lowercased.
 *
 * Quoted in three dialects and bare, because the statement Drizzle built quotes
 * its own identifiers and a statement a caller wrote by hand may not. Parsing
 * SQL properly is not on the table here and would not help: the question is
 * only whether a classified name appears at all.
 */
const IDENTIFIER = /"([^"]+)"|`([^`]+)`|\[([^\]]+)\]|([A-Za-z_][A-Za-z0-9_$]*)/g;

/**
 * Whether a statement mentions a column name this package has classified.
 *
 * Deliberately generous, and generous in the safe direction: a log entry that
 * loses its parameters is an inconvenience, one that keeps a password is an
 * incident. It answers yes for any statement naming a classified column
 * anywhere in it, including one that only joins the table, and it answers yes
 * for an unrelated table whose column happens to share the name.
 *
 * It cannot see which parameter belongs to which column, so the censoring it
 * drives is positional-blind: a statement that touches a classified column
 * loses all of its string parameters. Recovering the mapping would mean
 * parsing the statement, and a parser that is wrong once is worse than a rule
 * that is coarse always.
 */
export function touchesClassifiedColumn(
  statement: string,
  extra: ReadonlySet<string> = new Set()
): boolean {
  if (typeof statement !== 'string' || statement === '') return false;
  const classified = classifiedColumnNames();
  if (classified.size === 0 && extra.size === 0) return false;
  for (const match of statement.matchAll(IDENTIFIER)) {
    const name = (match[1] ?? match[2] ?? match[3] ?? match[4])?.toLowerCase();
    if (name === undefined) continue;
    if (classified.has(name) || extra.has(name)) return true;
  }
  return false;
}

/** Refuse one parameter, or return. */
function assertOne(value: unknown, at: number | string, statement: string): void {
  if (value instanceof SensitiveString) {
    throw new DrizzleParameterRefusedError(at, 'instance', truncate(statement));
  }
  // An array or JSON column is serialised before the parameter array exists,
  // and a `SensitiveString` serialises as its marker, so a value nested inside
  // one arrives here as a marker embedded in a longer string with no instance
  // left to recognise. Containment rather than equality is what covers those,
  // and it covers the other direction of the same mistake as well: a value
  // serialised somewhere upstream, about to be stored or compared as a marker.
  if (typeof value === 'string' && containsRedactionMarker(value)) {
    throw new DrizzleParameterRefusedError(at, 'marker', truncate(statement));
  }
}

/**
 * The values of a parameter bag, whatever shape it arrived in.
 *
 * Drizzle hands `logQuery` an array on every path measured on 0.45.2, and this
 * understands an object and a `Map` as well. Not speculation: the equivalent
 * guard in `sensitive-typeorm` shipped understanding only arrays, and the shape
 * it missed was the one its development driver could not reach, so the hole was
 * invisible to its suite. One `Array.isArray` to not repeat that is a good
 * trade.
 *
 * Every object is walked by its own enumerable entries, without a prototype
 * check, so a class instance and a bag from another realm are covered rather
 * than passed over. Only a primitive is skipped, and a primitive cannot hold
 * anything.
 */
function entriesOf(params: unknown): [number | string, unknown][] {
  if (Array.isArray(params)) return params.map((value, index) => [index, value]);
  if (params instanceof Map) {
    return [...params.entries()].map(([key, value]) => [String(key), value]);
  }
  if (typeof params !== 'object' || params === null) return [];
  return Object.entries(params as Record<string, unknown>);
}

/**
 * Refuse a parameter bag that still holds an unwrapped value.
 *
 * Called with what Drizzle is about to hand the driver: placeholders already
 * filled, column mappings already applied. Anything still an instance at this
 * point reached here through a path that had no column behind it.
 *
 * @throws DrizzleParameterRefusedError On the first offending parameter.
 */
export function assertParametersSafe(statement: string, params: unknown): void {
  for (const [at, value] of entriesOf(params)) assertOne(value, at, statement);
}

function truncate(statement: string): string {
  if (typeof statement !== 'string') return '(not a string)';
  return statement.length <= STATEMENT_LIMIT
    ? statement
    : `${statement.slice(0, STATEMENT_LIMIT)}...`;
}

/**
 * Replace the parameters of a statement that touches a classified column.
 *
 * Strings go, everything else stays. A classified column's revealed value is
 * always a string, so the ids, the timestamps and the booleans that make a log
 * entry useful survive, and the one shape that could carry a secret does not.
 */
export function redactParameters(params: unknown, touched: boolean, redactAll: boolean): unknown {
  let changed = false;
  const redactOne = (value: unknown): unknown => {
    if (value instanceof SensitiveString) {
      changed = true;
      return PARAMETER_CENSOR;
    }
    if (typeof value === 'string' && (touched || redactAll || containsRedactionMarker(value))) {
      changed = true;
      return PARAMETER_CENSOR;
    }
    return value;
  };

  if (Array.isArray(params)) {
    const out: unknown[] = params.map(redactOne);
    return changed ? out : params;
  }
  // A named bag, rebuilt as a plain object. The guard walks more shapes than
  // this does, deliberately: refusing has to be exhaustive, whereas a log line
  // that keeps the shape it arrived in is only a nicety, and rebuilding a
  // `Map` or a class instance as one would change what the inner logger sees.
  if (typeof params !== 'object' || params === null) return params;
  const proto: unknown = Object.getPrototypeOf(params);
  if (proto !== Object.prototype && proto !== null) return params;
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(params as Record<string, unknown>)) {
    out[key] = redactOne(value);
  }
  return changed ? out : params;
}

/**
 * A Drizzle `Logger` that is this package's parameter guard.
 *
 * It is a security control, not a diagnostic, and the naming is the one place
 * this package asks you to hold something odd in your head. Drizzle calls
 * `logQuery(sql, params)` from inside every prepared query's execute path, with
 * the parameters in their final form and immediately before the driver call, on
 * every session including the ones a transaction opens for itself. That is the
 * only seam in the ORM with all four of those properties, and two of the paths
 * this package has to cover are visible from nowhere else:
 *
 * - a value interpolated into a `sql` template, which Drizzle binds with no
 *   column behind it, so no `mapToDriverValue` runs;
 * - a prepared statement whose predicate is `eq(col, sql.placeholder('x'))`,
 *   where the value arrives at `execute({ x })` after the statement was built
 *   and is substituted into the parameter array without passing through the
 *   column. This is the form Drizzle's own documentation recommends for hot
 *   queries.
 *
 * Both hand a `SensitiveString` to the driver. `better-sqlite3` throws,
 * `pg` binds the JSON of its `toJSON()`, and `mysql2` escapes its enumerable
 * properties into the statement.
 *
 * Install it where the database is constructed. It cannot be installed
 * afterwards: the dialect sessions capture the logger at construction, and a
 * transaction on `node-postgres` builds a fresh session from the options the
 * first one was given, so assigning to `db.session.logger` covers the outer
 * session and nothing inside a transaction. `checkSchema()` verifies it is
 * there.
 *
 * @example
 * ```ts
 * const db = drizzle(pool, { schema, logger: sensitiveLogger() });
 * ```
 *
 * @example Keeping query logging, without the plaintext
 * ```ts
 * const db = drizzle(pool, {
 *   schema,
 *   logger: sensitiveLogger({ inner: new DefaultLogger() }),
 * });
 * ```
 */
export function sensitiveLogger(options: SensitiveLoggerOptions = {}): LoggerLike {
  const refuse = options.refuse ?? true;
  const redactAll = options.redactAllParameters ?? false;
  const inner = options.inner;
  const extra = new Set((options.alsoClassified ?? []).map((name) => name.toLowerCase()));

  const logger: LoggerLike = {
    logQuery(query: string, params: unknown[]): void {
      // The refusal comes first and is not conditional on there being an inner
      // logger. A deployment that wants no query logging still wants the guard,
      // and it is the reason this object exists.
      if (refuse) assertParametersSafe(query, params);
      if (inner === undefined) return;
      inner.logQuery(
        query,
        redactParameters(params, touchesClassifiedColumn(query, extra), redactAll) as unknown[]
      );
    },
  };

  Object.defineProperty(logger, SENSITIVE_LOGGER, {
    value: { refuse },
    enumerable: false,
    writable: false,
    configurable: false,
  });
  return logger;
}

/** Whether a value is a logger this package built, and whether it refuses. */
export function loggerBrand(value: unknown): { refuse: boolean } | undefined {
  if (typeof value !== 'object' || value === null) return undefined;
  const brand: unknown = (value as Record<symbol, unknown>)[SENSITIVE_LOGGER];
  if (typeof brand !== 'object' || brand === null) return undefined;
  return { refuse: (brand as { refuse?: boolean }).refuse === true };
}
