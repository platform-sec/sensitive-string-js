import {
  findUnsafeParameter,
  redactParameters as redactBag,
  touchesClassifiedColumn as touches,
  truncateStatement,
} from '@platform-sec/sensitive-string-data';
import { classifiedColumnNames } from './column.js';
import { DrizzleParameterRefusedError } from './errors.js';
import type { LoggerLike, SensitiveLoggerOptions } from './types.js';

/** What a redacted parameter is replaced with. */
export const PARAMETER_CENSOR = '[REDACTED:drizzle-parameter]';

/** Marks a logger this package built, so `checkSchema()` can recognise one. */
export const SENSITIVE_LOGGER = Symbol.for('platform-sec.sensitive-string.drizzle.logger');

export function touchesClassifiedColumn(
  statement: string,
  extra: ReadonlySet<string> = new Set()
): boolean {
  const classified = classifiedColumnNames();
  if (classified.size === 0 && extra.size === 0) return false;
  return touches(statement, { columns: classified }) || touches(statement, { columns: extra });
}

/**
 * Refuse a parameter bag that still holds an unwrapped value.
 *
 * Called with what Drizzle is about to hand the driver: placeholders already
 * filled, column mappings already applied. Anything still an instance at this
 * point reached here through a path that had no column behind it.
 *
 * The walk is `sensitive-data`'s, which descends into a nested container and
 * covers a `Map` and a bag whose prototype is not `Object.prototype`. The first
 * of those this package did not have and the last two the TypeORM package did
 * not, and neither suite could see what its own driver could not reach.
 *
 * @throws DrizzleParameterRefusedError On the first offending parameter.
 */
export function assertParametersSafe(statement: string, params: unknown): void {
  const found = findUnsafeParameter(params);
  if (found !== undefined) {
    throw new DrizzleParameterRefusedError(found.path, found.kind, truncateStatement(statement));
  }
}

/**
 * Replace the parameters of a statement that touches a classified column.
 *
 * Strings go, everything else stays. A classified column's revealed value is
 * always a string, so the ids, the timestamps and the booleans that make a log
 * entry useful survive, and the one shape that could carry a secret does not.
 */
export function redactParameters(params: unknown, touched: boolean, redactAll: boolean): unknown {
  return redactBag(params, touched || redactAll, PARAMETER_CENSOR);
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
