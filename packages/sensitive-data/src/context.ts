import { createChildContext, getCurrentRevealContext } from '@platform-sec/sensitive-string-core';
import type { RevealContext, SensitivityClass } from '@platform-sec/sensitive-string-core';

/**
 * What an ORM does with a value it hands to the driver.
 *
 * Six members, and no consumer reaches all six. An entity mapper reaches every
 * one; a query builder reaches `insert`, `update` and `predicate` and has no
 * state with which to perform change detection. `unknown` is for the transformer
 * shape, which is called with one argument and is told nothing about the
 * statement: recovering the operation there would mean reading the stack, which
 * is not something a security library does in a hot path. A consumer that cannot
 * tell passes `unknown` and says so in its README rather than guessing `update`.
 */
export type WriteOperation =
  'insert' | 'update' | 'delete' | 'predicate' | 'change-detection' | 'unknown';

export interface WriteAttribution {
  /** The integration's own name: `drizzle`, `typeorm`, `prisma`. */
  readonly sink: string;
  /** Table or model, when the hook knows one. */
  readonly table?: string | undefined;
  /** Column or field. */
  readonly column?: string | undefined;
  readonly operation: WriteOperation;
  /** Class of the column being written, for a sink that filters on it. */
  readonly klass?: SensitivityClass | undefined;
  /** Used only when no ambient context supplies a name. */
  readonly name?: string | undefined;
  /** Used only when no ambient context supplies a reason. */
  readonly reason?: string | undefined;
  /** Anything else the consumer wants on the record. */
  readonly tags?: Readonly<Record<string, unknown>> | undefined;
}

/**
 * The context one column write reveals under.
 *
 * An ambient context established with `withRevealContext()` names the unit of
 * work the caller cares about, so its `name` and `reason` win: replacing them
 * with a constant would flatten a request-scoped audit trail into one bucket per
 * column. The sink, table, column and operation travel in the tags instead.
 *
 * `createChildContext` rather than a fresh object, and this is the part that is
 * easy to get wrong. A context built from scratch drops the ambient
 * `auditReveal` hook and the caller's own tags, silently, so the reveals an
 * application thought it was recording stop arriving.
 *
 * There is no fallback to refusing. A row write happens on every request, and a
 * package that turns a missing context into a failed signup gets removed; the
 * synthesised context carries more structure than most hand-written ambient
 * ones would. What does not depend on this at all is the marker refusal, which
 * is what actually prevents corruption.
 */
export function buildWriteContext(attribution: WriteAttribution): RevealContext {
  const { sink, table, column, operation, klass } = attribution;
  const path = table === undefined ? (column ?? sink) : `${table}.${column ?? '?'}`;
  const ambient = getCurrentRevealContext();

  return createChildContext({
    name: ambient?.name ?? attribution.name ?? `${sink}:${path}`,
    reason: ambient?.reason ?? attribution.reason ?? describeOperation(operation),
    tags: {
      sink,
      operation,
      ...(klass === undefined ? {} : { klass }),
      ...(table === undefined ? {} : { table }),
      ...(column === undefined ? {} : { column }),
      ...attribution.tags,
    },
  });
}

function describeOperation(operation: WriteOperation): string {
  switch (operation) {
    case 'insert':
      return 'column insert';
    case 'update':
      return 'column update';
    case 'delete':
      return 'delete predicate';
    case 'predicate':
      return 'query predicate';
    case 'change-detection':
      return 'entity change detection';
    case 'unknown':
      return 'column write or predicate';
  }
}
