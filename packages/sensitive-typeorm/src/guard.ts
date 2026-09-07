import { findUnsafeParameter, truncateStatement } from '@platform-sec/sensitive-string-data';
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

/**
 * Check one statement's bound parameters, and refuse the ones that would
 * corrupt or leak.
 *
 * Every shape TypeORM passes is checked. The array is the usual one; the named
 * parameter map is the other, because `DataSource.query(sql, { e: value })`
 * hands the runner that object unchanged and a check that only understood
 * arrays would let every value in it through. `better-sqlite3` rejects named
 * placeholders, so this is one more case where the driver an application
 * develops against is not the one that would have shown the hole.
 *
 * The walk is `sensitive-data`'s, shared with the other ORM packages. It
 * descends into a nested container, terminates on a cycle, and covers a `Map`
 * and a bag whose prototype is not `Object.prototype`, which the version that
 * lived here did not.
 *
 * Exported so a caller who builds their own query runner, or who wants the
 * check somewhere else entirely, does not have to reimplement it.
 *
 * @throws TypeOrmParameterRefusedError On the first offending parameter.
 */
export function assertParametersSafe(statement: string, parameters: unknown): void {
  const found = findUnsafeParameter(parameters);
  if (found !== undefined) {
    throw new TypeOrmParameterRefusedError(found.path, found.kind, truncateStatement(statement));
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
