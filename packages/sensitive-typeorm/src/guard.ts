import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { TypeOrmParameterRefusedError } from './errors.js';
import { containsRedactionMarker } from './marker.js';

/**
 * Marks a query runner this package has already wrapped.
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
 */
interface QueryRunnerLike {
  query(query: string, parameters?: unknown[], ...rest: never[]): unknown;
  stream?: (query: string, parameters?: unknown[], ...rest: never[]) => unknown;
  [WRAPPED]?: true;
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
 * Find the first parameter that must not reach the driver.
 *
 * Walks arrays and plain objects, because a JSON column's parameter is an
 * object and an `IN (...)` binding is an array, and stops at anything else: a
 * `Date`, a `Buffer` or a driver's own wrapper holds no `SensitiveString`, and
 * walking a Buffer's indices would cost more than the statement does.
 */
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

  if (Array.isArray(value)) {
    seen.add(value);
    for (const [index, item] of value.entries()) {
      const found = findOffender(item, `${path}[${index}]`, seen);
      if (found !== undefined) return found;
    }
    return undefined;
  }

  const proto: unknown = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) return undefined;

  seen.add(value);
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    const found = findOffender(item, `${path}.${key}`, seen);
    if (found !== undefined) return found;
  }
  return undefined;
}

/**
 * Check one statement's bound parameters, and refuse the ones that would
 * corrupt or leak.
 *
 * Exported so a caller who builds their own query runner, or who wants the
 * check somewhere else entirely, does not have to reimplement it.
 *
 * @throws TypeOrmParameterRefusedError On the first offending parameter.
 */
export function assertParametersSafe(statement: string, parameters: unknown): void {
  if (!Array.isArray(parameters)) return;

  for (let index = 0; index < parameters.length; index += 1) {
    const parameter: unknown = parameters[index];

    // The two shapes that account for almost every parameter are handled
    // without allocating anything. This runs once per bound parameter of every
    // statement in the process, so the path string and the cycle set are built
    // only on the branch that needs them.
    if (parameter === null || parameter === undefined) continue;
    if (parameter instanceof SensitiveString) {
      throw new TypeOrmParameterRefusedError(String(index), 'instance', truncate(statement));
    }
    if (typeof parameter !== 'object') {
      if (typeof parameter === 'string' && containsRedactionMarker(parameter)) {
        throw new TypeOrmParameterRefusedError(String(index), 'marker', truncate(statement));
      }
      continue;
    }

    const found = findOffender(parameter, String(index), new WeakSet<object>());
    if (found !== undefined) {
      throw new TypeOrmParameterRefusedError(found.path, found.kind, truncate(statement));
    }
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
 * @returns A function that removes the wrapper and restores what was there,
 *   including on the runners already handed out. That matters on the SQLite
 *   family, where every call returns the same cached runner and leaving it
 *   wrapped would outlive the uninstall.
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
  const restorers: (() => void)[] = [];

  const wrapper = (...args: unknown[]): QueryRunnerLike => {
    const runner = original(...args);
    if (runner[WRAPPED] === true) return runner;

    const queryDescriptor = Object.getOwnPropertyDescriptor(runner, 'query');
    const innerQuery = runner.query.bind(runner);
    runner.query = (query: string, parameters?: unknown[], ...rest: never[]) => {
      assertParametersSafe(query, parameters);
      return innerQuery(query, parameters, ...rest);
    };

    const streamDescriptor = Object.getOwnPropertyDescriptor(runner, 'stream');
    if (typeof runner.stream === 'function') {
      const innerStream = runner.stream.bind(runner);
      runner.stream = (query: string, parameters?: unknown[], ...rest: never[]) => {
        assertParametersSafe(query, parameters);
        return innerStream(query, parameters, ...rest);
      };
    }

    Object.defineProperty(runner, WRAPPED, {
      value: true,
      enumerable: false,
      configurable: true,
    });

    restorers.push(() => {
      restore(runner, 'query', queryDescriptor);
      restore(runner, 'stream', streamDescriptor);
      delete runner[WRAPPED];
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
    for (const undo of restorers.splice(0)) undo();
  };
}

/**
 * Put a method back the way it was: an own property is redefined, an inherited
 * one is deleted so the prototype's shows through again.
 */
function restore(
  target: object,
  key: 'query' | 'stream',
  descriptor: PropertyDescriptor | undefined
): void {
  if (descriptor === undefined) {
    delete (target as Record<string, unknown>)[key];
  } else {
    Object.defineProperty(target, key, descriptor);
  }
}
