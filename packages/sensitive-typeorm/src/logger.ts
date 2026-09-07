import {
  indexClassifiedPaths,
  redactParameters as redactBag,
  touchesClassifiedColumn as touches,
} from '@platform-sec/sensitive-string-data';
import type { DataSchema } from './schema.js';

/** The part of TypeORM's `Logger` this package wraps. */
export interface LoggerLike {
  logQuery(query: string, parameters?: unknown[], queryRunner?: unknown): unknown;
  logQueryError(
    error: string | Error,
    query: string,
    parameters?: unknown[],
    queryRunner?: unknown
  ): unknown;
  logQuerySlow(time: number, query: string, parameters?: unknown[], queryRunner?: unknown): unknown;
  logSchemaBuild(message: string, queryRunner?: unknown): unknown;
  logMigration(message: string, queryRunner?: unknown): unknown;
  log(level: 'log' | 'info' | 'warn', message: unknown, queryRunner?: unknown): unknown;
}

/** What a redacted parameter is replaced with. */
export const PARAMETER_CENSOR = '[REDACTED:typeorm-parameter]';

/**
 * The exact `table.column` entries of a specification, indexed by table.
 *
 * Only `fields` can be enumerated. A rule is a pattern with no list of names
 * behind it, so the rule half of a specification is answered the other way
 * round: every identifier the statement mentions is classified, and any one
 * that resolves to something other than `'plain'` counts. See
 * `touchesClassifiedColumn`.
 */
function indexFields(schema: DataSchema): Map<string, Set<string>> {
  return indexClassifiedPaths(schema.classification.fields);
}

/**
 * Whether a statement mentions anything the specification classifies.
 *
 * Deliberately generous. It answers yes when the statement names both halves of
 * a classified path anywhere in it, and yes when any identifier in it matches a
 * classification rule. Neither is proof that a classified value is among the
 * parameters, and both are cheap to be wrong about in the safe direction: a log
 * entry that loses its parameters is an inconvenience, one that keeps a
 * password is an incident.
 */
export function touchesClassifiedColumn(
  statement: string,
  schema: DataSchema,
  fieldIndex: Map<string, Set<string>>
): boolean {
  return touches(statement, {
    paths: fieldIndex,
    // The bare identifier is asked without a table, so `fields` never answers
    // it and only a rule can. Anything unmatched resolves to `undefined` rather
    // than to the specification's fallback, which is what keeps a spec with the
    // usual `fallback: 'plain'` from reporting every statement in the process.
    classify: (identifier) => schema.classification.classify(identifier, [identifier]),
  });
}

/**
 * Replace the parameters of a statement that touches a classified column.
 *
 * Strings go, everything else stays. A classified column's revealed value is
 * always a string, so the ids, the timestamps and the booleans that make a log
 * entry useful survive, and the one shape that could carry a secret does not.
 *
 * A `SensitiveString` instance and a string holding a redaction marker are
 * replaced whatever the statement looks like. An instance among the parameters
 * means the transformer never ran, which is the query builder bypass, and it
 * prints as its own marker anyway; a marker means a column is already corrupt.
 * Neither should reach a log looking ordinary.
 *
 * The named parameter map is covered as well as the array. `DataSource.query(
 * sql, { e: value })` reaches the logger as that object, so a redaction that
 * only understood arrays would print every value in it, and TypeORM's own
 * `Logger` types the argument as an array, which is why the shape is easy to
 * miss.
 */
export function redactParameters(parameters: unknown, touched: boolean): unknown {
  return redactBag(parameters, touched, PARAMETER_CENSOR);
}

/**
 * A TypeORM `Logger` that redacts the parameters of statements touching
 * classified columns.
 *
 * The query log is the surface the transformer cannot reach, and it is the
 * opposite of the marker problem rather than a variation on it: here the value
 * is correct and it is in the wrong place. `logging: ['query']` prints every
 * statement with its bound parameters, the transformer has already run by then,
 * so what is printed is the revealed plaintext. That configuration line appears
 * in most getting-started templates and survives into production more often
 * than anyone intends.
 *
 * Opt-in through the `DataSource`'s own `logger` option rather than installed
 * automatically, because a `DataSource` option cannot be reached from a
 * transformer and this package does not patch prototypes.
 *
 * @example
 * ```ts
 * new DataSource({
 *   logging: ['query', 'error'],
 *   logger: sensitiveLogger(new AdvancedConsoleLogger('all'), schema),
 * });
 * ```
 */
export function sensitiveLogger(inner: LoggerLike, schema: DataSchema): LoggerLike {
  const fieldIndex = indexFields(schema);
  // The cast restates TypeORM's own type rather than widening it. `Logger`
  // declares `parameters?: any[]`, and a named parameter map arrives here as a
  // plain object, so the redacted value goes back out under the type the inner
  // logger was written against.
  const scrub = (query: string, parameters?: unknown[]): unknown[] | undefined =>
    redactParameters(parameters, touchesClassifiedColumn(query, schema, fieldIndex)) as
      unknown[] | undefined;

  return {
    logQuery(query, parameters, queryRunner) {
      return inner.logQuery(query, scrub(query, parameters), queryRunner);
    },
    logQueryError(error, query, parameters, queryRunner) {
      return inner.logQueryError(error, query, scrub(query, parameters), queryRunner);
    },
    logQuerySlow(time, query, parameters, queryRunner) {
      return inner.logQuerySlow(time, query, scrub(query, parameters), queryRunner);
    },
    logSchemaBuild(message, queryRunner) {
      return inner.logSchemaBuild(message, queryRunner);
    },
    logMigration(message, queryRunner) {
      return inner.logMigration(message, queryRunner);
    },
    log(level, message, queryRunner) {
      return inner.log(level, message, queryRunner);
    },
  };
}
