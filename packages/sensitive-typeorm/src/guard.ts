import { SensitiveString, containsRedactionMarker } from '@platform-sec/sensitive-string-core';
import { TypeOrmParameterRefusedError } from './errors.js';

/**
 * Whether a guard is still installed, read by the wrappers it left on runners.
 *
 * A cell rather than a captured boolean because it is shared: the runner keeps
 * it, and the guard's uninstall flips it. That is what lets the uninstall be
 * O(1) and hold no reference to any runner. See `guardParameters`.
 */
interface GuardState {
  active: boolean;
}

/**
 * Marks a query runner this package has already wrapped, and carries the state
 * that says whether the wrapper still checks anything.
 *
 * Required rather than tidy. The SQLite family's driver caches one query runner
 * and returns it from every `createQueryRunner()` call, measured on
 * `better-sqlite3` under TypeORM 1.1.1, so a wrapper that did not check would
 * layer itself once per call and eventually recurse as deep as the process had
 * made queries. `pg` builds a fresh runner each time and would never have shown
 * it.
 */
const WRAPPED = Symbol.for('platform-sec.sensitive-string.typeorm.guarded-runner');

/**
 * The part of TypeORM's `QueryRunner` the guard replaces.
 *
 * `never[]` for the trailing arguments rather than `unknown[]`, so a real
 * `QueryRunner` is assignable to this: `stream` takes two optional callbacks,
 * and a parameter typed `unknown` would not accept a `Function`.
 *
 * `parameters` is `unknown` rather than `unknown[]` because TypeORM's own type
 * is a lie about what arrives. `DataSource.query` declares
 * `parameters?: any[] | ObjectLiteral` and hands the runner whichever it was
 * given, so a named parameter map reaches this method as a plain object.
 */
interface QueryRunnerLike {
  query(query: string, parameters?: unknown, ...rest: never[]): unknown;
  stream?: (query: string, parameters?: unknown, ...rest: never[]) => unknown;
  [WRAPPED]?: GuardState;
}

/**
 * The part of TypeORM's `DataSource` the guard wraps.
 *
 * Structural and deliberately loose: this package imports no `typeorm`, and an
 * application with two copies of the ORM in its graph must still be able to
 * hand either one over.
 */
export interface GuardableDataSource {
  createQueryRunner(...args: never[]): unknown;
}

/** How much of a statement a refusal quotes. Enough to find it, short enough to log. */
const STATEMENT_LIMIT = 200;

function truncate(statement: string): string {
  const text = typeof statement === 'string' ? statement : String(statement);
  return text.length <= STATEMENT_LIMIT ? text : `${text.slice(0, STATEMENT_LIMIT)}...`;
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
function findOffender(
  value: unknown,
  path: string,
  seen: WeakSet<object>
): { path: string; kind: 'instance' | 'marker' } | undefined {
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
      const found = findOffender(item, `${path}[${index}]`, seen);
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

/**
 * Check one bound value, allocating nothing unless it is a container.
 *
 * @throws TypeOrmParameterRefusedError If it is an instance or holds a marker.
 */
function checkParameter(value: unknown, path: string, statement: string): void {
  if (value === null || value === undefined) return;
  if (value instanceof SensitiveString) {
    throw new TypeOrmParameterRefusedError(path, 'instance', truncate(statement));
  }
  if (typeof value === 'string') {
    if (containsRedactionMarker(value)) {
      throw new TypeOrmParameterRefusedError(path, 'marker', truncate(statement));
    }
    return;
  }
  if (typeof value !== 'object' || !isWalkable(value)) return;

  const found = findOffender(value, path, new WeakSet<object>());
  if (found !== undefined) {
    throw new TypeOrmParameterRefusedError(found.path, found.kind, truncate(statement));
  }
}

/**
 * Check one statement's bound parameters, and refuse the ones that would
 * corrupt or leak.
 *
 * Both shapes TypeORM passes are checked. The array is the usual one; the named
 * parameter map is the other, because `DataSource.query(sql, { e: value })`
 * hands the runner that object unchanged and a check that only understood
 * arrays would let every value in it through. `better-sqlite3` rejects named
 * placeholders, so this is one more case where the driver an application
 * develops against is not the one that would have shown the hole.
 *
 * Exported so a caller who builds their own query runner, or who wants the
 * check somewhere else entirely, does not have to reimplement it.
 *
 * @throws TypeOrmParameterRefusedError On the first offending parameter.
 */
export function assertParametersSafe(statement: string, parameters: unknown): void {
  if (typeof parameters !== 'object' || parameters === null) return;

  if (Array.isArray(parameters)) {
    for (let index = 0; index < parameters.length; index += 1) {
      checkParameter(parameters[index], String(index), statement);
    }
    return;
  }

  // Anything else with a prototype of its own is not a parameter map TypeORM
  // built, and descending into it would walk a driver's internals.
  if (!isWalkable(parameters)) return;
  for (const [key, value] of Object.entries(parameters as Record<string, unknown>)) {
    checkParameter(value, key, statement);
  }
}

/**
 * Refuse a `SensitiveString` or a redaction marker on its way to the driver.
 *
 * This exists because the column transformer is not called for a query
 * builder's named parameters, which is the ORM's most-used query API.
 * `qb.where('u.email = :e', { e: value })` is a SQL fragment and a name, with
 * no `ColumnMetadata` connecting the two, so TypeORM binds the parameter map
 * straight through. What happens next belongs to the driver and the three
 * common ones disagree: `better-sqlite3` throws, `pg` binds
 * `"[REDACTED:sensitive]"` with the quotes `JSON.stringify` added, and `mysql2`
 * stringifies the instance's own enumerable properties. Only the first fails
 * loudly. On the other two the query runs, matches nothing, and an `UPDATE`
 * built the same way stores the marker.
 *
 * The query runner is the only place that sees the parameter map between the
 * query builder and the driver, so this wraps `createQueryRunner` on the
 * `DataSource`. That is an own property on the instance handed in: no prototype
 * is patched, no options are mutated, and nothing process-global is registered.
 * It covers every path, `ds.query()` and a transaction's manager included,
 * because all of them obtain their runner the same way.
 *
 * What it does not cover is a query runner created before it was installed and
 * held across the call. Install it immediately after `initialize()`.
 *
 * @returns A function that stops the checking, on the `DataSource` and on every
 *   runner already handed out. It deliberately does not unwrap those runners:
 *   a guard that remembered them in order to restore them would keep every
 *   query runner the process ever made alive, which on `pg` is one per query.
 *   What is left behind is a wrapper that reads one boolean and delegates.
 *
 * @example
 * ```ts
 * await dataSource.initialize();
 * guardParameters(dataSource);
 * ```
 */
export function guardParameters(dataSource: GuardableDataSource): () => void {
  const own = Object.getOwnPropertyDescriptor(dataSource, 'createQueryRunner');
  const original = dataSource.createQueryRunner.bind(dataSource) as (
    ...args: unknown[]
  ) => QueryRunnerLike;

  const state: GuardState = { active: true };
  // Every cell this guard is answerable for: its own, plus any it adopted from
  // a guard that wrapped the same runner earlier. Cells are two words each and
  // reference no runner, so this holds one entry per guard rather than one per
  // query.
  const owned = new Set<GuardState>([state]);

  const wrapper = (...args: unknown[]): QueryRunnerLike => {
    const runner = original(...args);

    const existing = runner[WRAPPED];
    if (existing !== undefined) {
      // Already wrapped, possibly by a guard that has since been uninstalled.
      // Reactivating its cell is what makes a second install take effect on the
      // runner the SQLite drivers hand back every time.
      existing.active = true;
      owned.add(existing);
      return runner;
    }

    const innerQuery = runner.query.bind(runner);
    runner.query = (query: string, parameters?: unknown, ...rest: never[]) => {
      if (state.active) assertParametersSafe(query, parameters);
      return innerQuery(query, parameters, ...rest);
    };

    if (typeof runner.stream === 'function') {
      const innerStream = runner.stream.bind(runner);
      runner.stream = (query: string, parameters?: unknown, ...rest: never[]) => {
        if (state.active) assertParametersSafe(query, parameters);
        return innerStream(query, parameters, ...rest);
      };
    }

    Object.defineProperty(runner, WRAPPED, {
      value: state,
      enumerable: false,
      configurable: true,
    });

    return runner;
  };

  Object.defineProperty(dataSource, 'createQueryRunner', {
    value: wrapper,
    writable: true,
    enumerable: false,
    configurable: true,
  });

  return () => {
    if (own === undefined) {
      delete (dataSource as Partial<GuardableDataSource>).createQueryRunner;
    } else {
      Object.defineProperty(dataSource, 'createQueryRunner', own);
    }
    for (const cell of owned) cell.active = false;
  };
}
