import { SensitiveStringError } from '@platform-sec/sensitive-string-core';

/**
 * A column this package refuses to build.
 *
 * Thrown by the column factories, which run at module load when the schema file
 * is imported, so an unregistered class stops the process at startup rather
 * than producing a column that quietly stores plaintext.
 */
export class DrizzleConfigError extends SensitiveStringError {
  readonly code = 'DRIZZLE_INVALID_CONFIG';

  constructor(message: string) {
    super(message);
    this.name = 'DrizzleConfigError';
  }
}

/**
 * A classified column's write side refused the value it was handed.
 *
 * Two causes, and both are a write that would have succeeded and corrupted the
 * column. A plain string under `strictWrites`, which means the property type
 * that was supposed to stop it did not; and a string already holding a
 * redaction marker, which means something upstream serialised a wrapped value
 * before it reached here.
 */
export class DrizzleWriteRefusedError extends SensitiveStringError {
  readonly code = 'DRIZZLE_WRITE_REFUSED';

  constructor(
    /** `table.column`, or just the column when the schema named no table. */
    readonly path: string,
    message: string
  ) {
    super(message);
    this.name = 'DrizzleWriteRefusedError';
  }
}

/**
 * A classified column read back a redaction marker.
 *
 * The corruption already happened, on an earlier write, and this is the first
 * moment it is visible. Raising is the inverse of the write refusal: without
 * it the marker is handed to the application as a `SensitiveString` whose
 * reveal returns `[REDACTED:...]`, and the failure surfaces as a rejected
 * credential in some other service.
 *
 * A column is not a cache, so there is no sentinel to return instead.
 */
export class DrizzleMarkerReadError extends SensitiveStringError {
  readonly code = 'DRIZZLE_MARKER_IN_COLUMN';

  constructor(
    /** `table.column`, or just the column when the schema named no table. */
    readonly path: string
  ) {
    super(
      `${path} holds a redaction marker rather than a value. The row was written by a path ` +
        `that serialised a SensitiveString instead of revealing it, most often a prepared ` +
        `statement's placeholder or a value interpolated into a sql template. The original ` +
        `value is gone; this read refuses rather than handing the marker on as if it were the ` +
        `secret.`
    );
    this.name = 'DrizzleMarkerReadError';
  }
}

/**
 * A classified column was handed something that is not text on the read path.
 *
 * Separate from {@link DrizzleMarkerReadError} because it is a different
 * failure with a different fix. A marker means an earlier write corrupted the
 * column; this means the column is not carrying text at all, which is a driver
 * answering a text column with a `Buffer`, a schema whose SQL type was
 * overridden to something else, or a direct call to `mapFromDriverValue`.
 *
 * Coercing would hide the mismatch, and wrapping a `Buffer`'s `toString()`
 * would invent a value and hand it back as if it had been read.
 */
export class DrizzleColumnTypeError extends SensitiveStringError {
  readonly code = 'DRIZZLE_UNEXPECTED_COLUMN_TYPE';

  constructor(
    /** `table.column`, or just the column when the schema named no table. */
    readonly path: string,
    /** `typeof` what arrived. Never the value. */
    readonly received: string
  ) {
    super(
      `${path} is a classified text column and read back a ${received}. Drizzle never sends null ` +
        `to a column's read side, so a nullish value here is a direct call to ` +
        `mapFromDriverValue; anything else means the column is not carrying text. Wrapping it ` +
        `would hand the application an invented value under a type that promises a ` +
        `SensitiveString.`
    );
    this.name = 'DrizzleColumnTypeError';
  }
}

/**
 * A bound parameter carried a `SensitiveString` or a redaction marker.
 *
 * This is the refusal for the paths the column never sees. A column's
 * `mapToDriverValue` runs for a value Drizzle can attribute to that column: an
 * insert, an update, a predicate built with `eq()` and friends. It does not run
 * for a value interpolated into a `sql` template, nor for a prepared
 * statement's placeholder filled through `eq(col, sql.placeholder('x'))`, which
 * is the shape Drizzle's own documentation recommends for hot queries. Both
 * reach the driver unchanged.
 *
 * What the drivers then do differs and none of it is good: `better-sqlite3`
 * throws `SQLite3 can only bind numbers, strings, bigints, buffers, and null`,
 * `pg` binds `"[REDACTED:credential]"` with the quotes `JSON.stringify` added,
 * and `mysql2` escapes the instance's own enumerable properties into the
 * statement as ``\`klass\` = 'credential', \`label\` = 'token'``. On the two
 * drivers that do not throw the statement executes and matches nothing, or
 * stores the marker.
 */
export class DrizzleParameterRefusedError extends SensitiveStringError {
  readonly code = 'DRIZZLE_SENSITIVE_PARAMETER';

  constructor(
    /**
     * Where the value was: an index into the bound parameter array, a key
     * within a parameter bag, or a path into a nested container such as
     * `0.filters[1]`. Always a string, because a numeric index cannot name a
     * position inside a container and the walk descends into one.
     */
    readonly parameter: string,
    /** What was found: an instance, or a marker. */
    readonly kind: 'instance' | 'marker',
    /** The statement, truncated. Never the parameters. */
    readonly statement: string
  ) {
    const what =
      kind === 'instance' ? `a SensitiveString instance` : `a string holding a redaction marker`;
    super(
      `Bound parameter ${String(parameter)} is ${what}, and Drizzle is about to hand it to the ` +
        `driver unchanged. A column's mapToDriverValue does not run for a value interpolated ` +
        `into a sql template, nor for a placeholder filled at execute time: neither has a ` +
        `column behind it. Use sql.param(value, table.column) for the first, and pass the value ` +
        `through the query builder rather than a placeholder for the second. ` +
        `Statement: ${statement}`
    );
    this.name = 'DrizzleParameterRefusedError';
  }
}

/** One thing {@link checkSchema} found wrong. */
export interface DriftFinding {
  /** `table.column`, as the schema names it. */
  readonly path: string;
  readonly detail: string;
}

/**
 * The schema and the deployment disagree about a classified column.
 *
 * Narrower than the equivalent check in the Prisma and TypeORM packages, and
 * deliberately so. Both of those classify by string key, so a renamed table or
 * a mistyped column name leaves an entry classifying nothing and the compiler
 * says nothing. Here the classification *is* the column: `sensitiveText('ssn')`
 * produces a column whose select type is `SensitiveString`, and a name that
 * does not exist is a compile error.
 *
 * What is left for runtime is the direction the compiler cannot see: a column
 * that should have been classified and was declared with a plain factory, and a
 * classified column carrying a literal default.
 */
export class DrizzleDriftError extends SensitiveStringError {
  readonly code = 'DRIZZLE_SCHEMA_DRIFT';

  constructor(readonly findings: readonly DriftFinding[]) {
    super(
      `The schema has ${findings.length} classification problem` +
        `${findings.length === 1 ? '' : 's'}:\n` +
        findings.map((f) => `  - ${f.path}: ${f.detail}`).join('\n')
    );
    this.name = 'DrizzleDriftError';
  }
}

/**
 * A query cache is configured on a database that has classified columns.
 *
 * Drizzle's cache stores what the driver returned, which for a select is the
 * rows before any column's `mapFromDriverValue` has run. So a cached query puts
 * the plaintext of every classified column it selected into whatever store the
 * cache is backed by: Upstash Redis in the shipped adapter, which is a second
 * copy with none of the database's grants, a TTL of the cache's choosing, and a
 * name no schema review recognises as holding user data.
 *
 * The cache key is a SHA-256 of the statement and its parameters, so the
 * predicate values are not in the key. The rows are the exposure.
 *
 * A refusal rather than a warning because the copy outlives the request.
 */
export class DrizzleCacheRefusedError extends SensitiveStringError {
  readonly code = 'DRIZZLE_QUERY_CACHE';

  constructor(
    readonly classifiedColumns: readonly string[],
    /** The cache's own entity kind, as Drizzle names it. */
    readonly cacheKind: string
  ) {
    const sample = classifiedColumns.slice(0, 3).join(', ');
    const more = classifiedColumns.length > 3 ? ` and ${classifiedColumns.length - 3} more` : '';
    super(
      `The database was constructed with a query cache (${cacheKind}) and the schema has ` +
        `${classifiedColumns.length} classified column${classifiedColumns.length === 1 ? '' : 's'} ` +
        `(${sample}${more}). The cache stores the driver's rows, which for a select are the rows ` +
        `before the column's read side runs, so the classified values land as plaintext in the ` +
        `cache store. Drop the cache option, or pass { allowCachedPlaintext: true } to ` +
        `checkSchema() and accept it in writing.`
    );
    this.name = 'DrizzleCacheRefusedError';
  }
}

/**
 * The database was constructed without this package's logger.
 *
 * In this package the logger is a security control rather than a diagnostic.
 * It is the only seam Drizzle offers that sees a statement's final bound
 * parameters, after a prepared statement's placeholders have been filled and
 * before the driver is called, and it sees them on every session including the
 * ones a transaction creates for itself. Without it the two paths a column
 * cannot see are unguarded. See {@link DrizzleParameterRefusedError}.
 */
export class DrizzleGuardMissingError extends SensitiveStringError {
  readonly code = 'DRIZZLE_GUARD_MISSING';

  constructor(readonly classifiedColumns: readonly string[]) {
    super(
      `The database has ${classifiedColumns.length} classified ` +
        `column${classifiedColumns.length === 1 ? '' : 's'} and was constructed without ` +
        `sensitiveLogger(). In this package the logger is the parameter guard: it is the only ` +
        `place that sees a statement's bound parameters after a prepared statement's ` +
        `placeholders are filled and before the driver runs. Construct the database as ` +
        `drizzle(client, { schema, logger: sensitiveLogger() }), or pass ` +
        `{ allowUnguarded: true } to checkSchema() and accept it in writing.`
    );
    this.name = 'DrizzleGuardMissingError';
  }
}
