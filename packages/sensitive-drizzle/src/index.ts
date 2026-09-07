/**
 * @platform-sec/sensitive-string-drizzle
 *
 * Drizzle ORM integration for SensitiveString.
 *
 * A classified column is declared in the schema, which is the difference that
 * matters against the other two data-layer integrations: the classification is
 * the column rather than a string key checked against it, so a select returns
 * `SensitiveString` in the type as well as the value, relations and partial
 * selects included, and a misspelled column name is a compile error rather than
 * a silently unwrapped read.
 *
 * Reads wrap and writes reveal, both through Drizzle's `customType`. That hook
 * covers more than TypeORM's transformer does, measured on 0.45.2: inserts,
 * updates, `returning()`, predicates built with `eq()` and `inArray()`,
 * `onConflictDoUpdate`, subqueries, transactions, and the relational query
 * builder's nested rows all route through it.
 *
 * Two parameter paths do not, because neither has a column behind it: a value
 * interpolated into a `sql` template, and a prepared statement whose predicate
 * is `eq(col, sql.placeholder('x'))`. `sensitiveLogger()` refuses those, and it
 * is the only seam in the ORM that sees a statement's final parameters before
 * the driver does. It is installed at construction and `checkSchema()` verifies
 * it is there.
 *
 * Two plaintext surfaces sit beside the column. `DrizzleQueryError` carries the
 * revealed parameters three times, in `params`, in `message` and in the header
 * of `stack`, which is what `sanitizeQueryError()` removes; and a configured
 * query cache stores the driver's rows before the column's read side runs,
 * which `checkSchema()` refuses.
 *
 * The column factories live in the three dialect entry points, which are the
 * only modules here that import `drizzle-orm`.
 *
 * @example
 * ```ts
 * // schema.ts
 * import { pgTable, serial, varchar } from 'drizzle-orm/pg-core';
 * import { sensitiveText, credentialText } from '@platform-sec/sensitive-string-drizzle/pg';
 *
 * export const users = pgTable('users', {
 *   id: serial('id').primaryKey(),
 *   name: varchar('name', { length: 255 }),
 *   email: sensitiveText('email', { table: 'users' }).notNull(),
 *   passwordHash: credentialText('password_hash', { table: 'users' }).notNull(),
 * });
 *
 * // db.ts
 * import { drizzle } from 'drizzle-orm/node-postgres';
 * import { checkSchema, sensitiveLogger } from '@platform-sec/sensitive-string-drizzle';
 * import * as schema from './schema.js';
 *
 * export const db = drizzle(pool, { schema, logger: sensitiveLogger() });
 * checkSchema(db, schema, { requireClassified: ['password_hash'] });
 * ```
 *
 * @packageDocumentation
 */

export {
  classificationOf,
  classifiedColumnNames,
  resetClassifiedColumnNames,
  resetPlainWriteReports,
  sensitiveMapping,
} from './column.js';
export type { SensitiveMapping } from './column.js';

export { checkSchema, classifiedColumns } from './check.js';
export type { CheckResult, ClassifiedColumn } from './check.js';

export {
  PARAMETER_CENSOR,
  SENSITIVE_LOGGER,
  assertParametersSafe,
  loggerBrand,
  redactParameters,
  sensitiveLogger,
  touchesClassifiedColumn,
} from './logger.js';

export { ERROR_PARAMETER_CENSOR, sanitizeQueryError } from './sanitize.js';

export { drizzleScrubFragment } from './scrub.js';

export { hydrateRawRows } from './raw.js';

// Recognizing a redaction marker is core's, shared with every other guard that
// refuses to hand one onward. Re-exported so a caller holding this package does
// not need a second import to write the assertion.
export {
  containsRedactionMarker,
  redactionMatchers,
  resetRedactionMarkerCache,
} from '@platform-sec/sensitive-string-core';

export type {
  CheckOptions,
  ColumnClassification,
  ColumnLike,
  DatabaseLike,
  HydrateRawOptions,
  LoggerLike,
  PlainWriteInfo,
  SensitiveColumnOptions,
  SensitiveLoggerOptions,
  SensitiveVarcharOptions,
  TableLike,
} from './types.js';

export {
  DrizzleCacheRefusedError,
  DrizzleColumnTypeError,
  DrizzleConfigError,
  DrizzleDriftError,
  DrizzleGuardMissingError,
  DrizzleMarkerReadError,
  DrizzleParameterRefusedError,
  DrizzleWriteRefusedError,
} from './errors.js';
export type { DriftFinding } from './errors.js';
