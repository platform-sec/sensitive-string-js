import { SensitiveStringError } from '@platform-sec/sensitive-string-core';

/**
 * A specification this package refuses to build a schema or a transformer from.
 *
 * Thrown by `defineSchema()` and `schema.column()`, which run at module load,
 * so an unregistered class or a path the spec does not classify stops the
 * process at startup rather than producing a column that quietly stores
 * plaintext.
 */
export class TypeOrmConfigError extends SensitiveStringError {
  readonly code = 'TYPEORM_INVALID_CONFIG';

  constructor(message: string) {
    super(message);
    this.name = 'TypeOrmConfigError';
  }
}

/**
 * The write transformer refused the value it was handed.
 *
 * Two causes, and both are a write that would have succeeded and corrupted the
 * column. A plain string under `strictWrites`, which means the property type
 * that was supposed to stop it did not; and a string already holding a
 * redaction marker, which means something upstream serialised a wrapped value
 * before it reached here.
 */
export class TypeOrmWriteRefusedError extends SensitiveStringError {
  readonly code = 'TYPEORM_WRITE_REFUSED';

  constructor(
    /** `table.column` the transformer is bound to. */
    readonly path: string,
    message: string
  ) {
    super(message);
    this.name = 'TypeOrmWriteRefusedError';
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
export class TypeOrmMarkerReadError extends SensitiveStringError {
  readonly code = 'TYPEORM_MARKER_IN_COLUMN';

  constructor(
    /** `table.column` the marker was read from. */
    readonly path: string
  ) {
    super(
      `${path} holds a redaction marker rather than a value. The row was written by a path ` +
        `that serialised a SensitiveString instead of revealing it, most often a query builder ` +
        `parameter (see guardParameters) or a raw statement. The original value is gone; this ` +
        `read refuses rather than handing the marker on as if it were the secret.`
    );
    this.name = 'TypeOrmMarkerReadError';
  }
}

/**
 * A bound parameter carried a `SensitiveString` or a redaction marker.
 *
 * This is the refusal for the path the transformer never sees. TypeORM binds a
 * query builder's named parameters straight to the driver, with no column
 * metadata in reach, so `to()` is not called and nothing else in this package
 * is either. What the drivers then do differs and none of it is good:
 * `better-sqlite3` throws, `pg` binds `"[REDACTED:sensitive]"` with the quotes
 * `JSON.stringify` added, and `mysql2` stringifies the instance's own
 * enumerable properties into the statement.
 */
export class TypeOrmParameterRefusedError extends SensitiveStringError {
  readonly code = 'TYPEORM_SENSITIVE_PARAMETER';

  constructor(
    /** Index into the bound parameter array, or a path within one. */
    readonly parameter: string,
    /** What was found: an instance, or a marker. */
    readonly kind: 'instance' | 'marker',
    /** The statement, truncated. Never the parameters. */
    readonly statement: string
  ) {
    const what =
      kind === 'instance' ? `a SensitiveString instance` : `a string holding a redaction marker`;
    super(
      `Bound parameter ${parameter} is ${what}, and TypeORM is about to hand it to the driver ` +
        `unchanged. A column transformer does not run for a query builder parameter: ` +
        `'u.email = :e' is a SQL fragment and ':e' is a name, so there is no column metadata to ` +
        `consult. Reveal the value at the call site, or use the find-options form ` +
        `(.where({ email: value })), which does run the transformer. Statement: ${statement}`
    );
    this.name = 'TypeOrmParameterRefusedError';
  }
}

/** One thing `schema.check()` found wrong. */
export interface DriftFinding {
  /** `table.column`, as this package names it. */
  readonly path: string;
  readonly detail: string;
}

/**
 * The entity metadata and the specification disagree.
 *
 * Both directions are checked and both are silent without this. A classified
 * column with no transformer stores plaintext and hands the application a
 * string where its own property type promises a `SensitiveString`; a
 * transformed column the spec no longer classifies is a stale annotation that
 * nothing else reports.
 *
 * This is as close as a `ValueTransformer` gets to the compile-time guarantee
 * a Drizzle `customType` makes. TypeORM types a property by the author's own
 * annotation on the class field, and no transformer can make the compiler check
 * that the annotation matches the spec.
 */
export class TypeOrmDriftError extends SensitiveStringError {
  readonly code = 'TYPEORM_SCHEMA_DRIFT';

  constructor(readonly findings: readonly DriftFinding[]) {
    super(
      `The classification specification and the entity metadata disagree in ` +
        `${findings.length} place${findings.length === 1 ? '' : 's'}:\n` +
        findings.map((f) => `  - ${f.path}: ${f.detail}`).join('\n')
    );
    this.name = 'TypeOrmDriftError';
  }
}

/**
 * The query result cache is enabled on a `DataSource` that has classified
 * columns.
 *
 * TypeORM's cache stores the raw driver rows, before `from()` runs, and it
 * stores the statement with its bound parameters as the cache key. So a cached
 * query puts the plaintext of every classified column it selected, and of every
 * classified value it filtered on, into a second table: one with none of the
 * first table's grants, no TTL beyond the per-query duration, and a name no
 * schema review recognises as holding user data. Backed by Redis it lands
 * somewhere with no access control at all.
 *
 * A refusal rather than a warning because the copy outlives the request. A
 * boot-time warning is a line nobody reads in a log nobody keeps.
 */
export class TypeOrmCacheRefusedError extends SensitiveStringError {
  readonly code = 'TYPEORM_QUERY_CACHE';

  constructor(readonly classifiedColumns: readonly string[]) {
    const sample = classifiedColumns.slice(0, 3).join(', ');
    const more = classifiedColumns.length > 3 ? ` and ${classifiedColumns.length - 3} more` : '';
    super(
      `The DataSource has the query result cache enabled and ${classifiedColumns.length} ` +
        `classified column${classifiedColumns.length === 1 ? '' : 's'} (${sample}${more}). ` +
        `The cache stores the driver's rows before the read transformer runs, and stores the ` +
        `statement's bound parameters as part of the cache key, so both the selected values and ` +
        `the filtered ones land as plaintext in 'query-result-cache'. Turn the cache off, or ` +
        `pass { allowCachedPlaintext: true } to schema.check() and accept it in writing.`
    );
    this.name = 'TypeOrmCacheRefusedError';
  }
}
