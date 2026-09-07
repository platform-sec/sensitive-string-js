import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { containsRedactionMarker } from './marker.js';
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
 * Every identifier in a statement, lowercased.
 *
 * Quoted in three dialects and bare, because the statement TypeORM built quotes
 * its own identifiers and a statement a caller wrote by hand may not. Parsing
 * SQL properly is not on the table here and would not help: the question is
 * only whether a classified name appears at all.
 */
const IDENTIFIER = /"([^"]+)"|`([^`]+)`|\[([^\]]+)\]|([A-Za-z_][A-Za-z0-9_$]*)/g;

function identifiersIn(statement: string): Set<string> {
  const found = new Set<string>();
  for (const match of statement.matchAll(IDENTIFIER)) {
    const name = match[1] ?? match[2] ?? match[3] ?? match[4];
    if (name !== undefined) found.add(name.toLowerCase());
  }
  return found;
}

/**
 * The exact `table.column` entries of a specification, indexed by table.
 *
 * Only `fields` can be enumerated. A rule is a pattern with no list of names
 * behind it, so the rule half of a specification is answered the other way
 * round: every identifier the statement mentions is classified, and any one
 * that resolves to something other than `'plain'` counts.
 */
function indexFields(schema: DataSchema): Map<string, Set<string>> {
  const index = new Map<string, Set<string>>();
  for (const [path, klass] of schema.classification.fields) {
    if (klass === 'plain') continue;
    const at = path.lastIndexOf('.');
    if (at <= 0) continue;
    const table = path.slice(0, at).toLowerCase();
    const column = path.slice(at + 1).toLowerCase();
    const columns = index.get(table) ?? new Set<string>();
    columns.add(column);
    index.set(table, columns);
  }
  return index;
}

/**
 * Whether a statement mentions anything the specification classifies.
 *
 * Deliberately generous. It answers yes when the statement names both halves of
 * a classified path anywhere in it, and yes when any identifier in it matches a
 * classification rule. Neither is proof that a classified value is among the
 * parameters, and both are cheap to be wrong about in the safe direction: a
 * log entry that loses its parameters is an inconvenience, one that keeps a
 * password is an incident.
 */
export function touchesClassifiedColumn(
  statement: string,
  schema: DataSchema,
  fieldIndex: Map<string, Set<string>>
): boolean {
  if (typeof statement !== 'string' || statement === '') return false;
  const identifiers = identifiersIn(statement);

  for (const [table, columns] of fieldIndex) {
    // A schema-qualified key such as `public.users` is present when its last
    // segment is, since a statement writes the qualification separately.
    const tableName = table.slice(table.lastIndexOf('.') + 1);
    if (!identifiers.has(tableName)) continue;
    for (const column of columns) {
      if (identifiers.has(column)) return true;
    }
  }

  for (const identifier of identifiers) {
    const klass = schema.classification.classify(identifier, [identifier]);
    // The bare identifier is asked without a table, so `fields` never answers
    // it and only a rule can. Anything unmatched resolves to the fallback,
    // which is why 'plain' has to be excluded explicitly: without that, a
    // specification with the usual `fallback: 'plain'` would report every
    // statement in the process as touching a classified column.
    if (klass !== undefined && klass !== 'plain') return true;
  }
  return false;
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
 */
export function redactParameters(parameters: unknown, touched: boolean): unknown {
  if (typeof parameters !== 'object' || parameters === null) return parameters;

  let changed = false;
  const redactOne = (parameter: unknown): unknown => {
    if (parameter instanceof SensitiveString) {
      changed = true;
      return PARAMETER_CENSOR;
    }
    if (typeof parameter === 'string' && (touched || containsRedactionMarker(parameter))) {
      changed = true;
      return PARAMETER_CENSOR;
    }
    return parameter;
  };

  if (Array.isArray(parameters)) {
    const out: unknown[] = parameters.map(redactOne);
    return changed ? out : parameters;
  }

  // A named parameter map. `DataSource.query(sql, { e: value })` reaches the
  // logger as that object, so a redaction that only understood arrays would
  // print every value in it. TypeORM's own `Logger` types the argument as an
  // array, which is why this shape is easy to miss.
  const proto: unknown = Object.getPrototypeOf(parameters);
  if (proto !== Object.prototype && proto !== null) return parameters;

  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(parameters as Record<string, unknown>)) {
    out[key] = redactOne(value);
  }
  return changed ? out : parameters;
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
