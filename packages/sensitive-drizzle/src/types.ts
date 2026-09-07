import type { SensitivityClass } from '@platform-sec/sensitive-string-core';

/**
 * Drizzle's `Logger`, restated structurally.
 *
 * Declared here rather than imported so the guard carries no import of
 * `drizzle-orm` at all: the root entry point of this package is usable in a
 * process that has only one of the three dialect modules installed, and in one
 * that has two copies of the ORM in its dependency graph.
 *
 * The interface is one method and has not changed since 0.29.
 */
export interface LoggerLike {
  logQuery(query: string, params: unknown[]): void;
}

/** The two things a session carries that this package asks about. */
export interface SessionLike {
  readonly logger?: unknown;
  readonly cache?: unknown;
}

/**
 * The part of a Drizzle database this package reads.
 *
 * Structural for the same reason as {@link LoggerLike}, and narrower than it
 * looks: the session is the only thing on a `PgDatabase`, `MySqlDatabase` or
 * `BaseSQLiteDatabase` that {@link checkSchema} needs, and the two properties
 * read off it are the ones every dialect's session sets in its constructor.
 *
 * Both places the session might be are declared, and neither is guaranteed.
 * Drizzle declares `session` on the class as `@internal`, so it exists at
 * runtime and not in the published type; it declares `_.session` in the
 * published type, and on 0.45.2 the constructor does not put it there, so it
 * exists in the type and not at runtime. `_` is what makes this interface match
 * a real database rather than being rejected as a weak type with nothing in
 * common, and the instance property is what is actually read.
 */
export interface DatabaseLike {
  readonly _?: unknown;
  readonly session?: SessionLike;
}

/**
 * The part of a Drizzle `Column` this package reads.
 *
 * `mapFromDriverValue` is how a classified column is recognised, and it is
 * public API on `Column` in every dialect. See {@link classificationOf}.
 */
export interface ColumnLike {
  readonly name: string;
  readonly notNull?: boolean;
  readonly hasDefault?: boolean;
  readonly default?: unknown;
  getSQLType(): string;
  mapFromDriverValue(value: unknown): unknown;
  mapToDriverValue(value: unknown): unknown;
}

/** The part of a Drizzle `Table` this package reads. */
export type TableLike = Record<string | symbol, unknown>;

/** What a classified column says about itself when probed. */
export interface ColumnClassification {
  readonly klass: SensitivityClass;
  readonly label: string | undefined;
}

/** What was passed to a column's write side when it refused or reported. */
export interface PlainWriteInfo {
  /** `table.column`, or just the column when the schema named no table. */
  readonly path: string;
  readonly klass: SensitivityClass;
  /** `typeof` the value. Never the value. */
  readonly received: string;
}

/** How one classified column behaves. */
export interface SensitiveColumnOptions {
  /**
   * Database table, used in audit tags and in every message.
   *
   * Drizzle builds the column before the table exists, so a column cannot ask
   * which table it ended up in. Passing it is what puts the table in the audit
   * record; leaving it out costs a tag, not a guarantee.
   */
  readonly table?: string;
  /** Audit label for values read back. Defaults to the column name. */
  readonly label?: string;
  /**
   * Refuse a plain string on the write path instead of passing it through.
   *
   * Off by default, and that is measured rather than preferred:
   * `where(eq(users.email, 'a@example.com'))` with a literal hands the write
   * side a plain string, and it is an ordinary query. What the default does
   * instead is report it once per path when development mode is on.
   *
   * A service whose property types are all `SensitiveString` and whose
   * predicates all pass instances can turn this on and have the ORM enforce it.
   */
  readonly strictWrites?: boolean;
  /**
   * Require an ambient reveal context on the write path.
   *
   * Off by default. A row write happens on every request, so refusing one for
   * want of a context turns a security library into an availability incident.
   * A service that has already wired `withRevealContext()` at its request
   * boundary can turn it on and find the paths that escaped.
   */
  readonly strictContext?: boolean;
  /** Context name used when no ambient context supplies one. */
  readonly name?: string;
  /** Context reason used when no ambient context supplies one. */
  readonly reason?: string;
  /**
   * Called the first time a path is handed a plain string, when
   * `strictWrites` is off.
   *
   * Defaults to one `console.warn` per path, emitted only when core's
   * development mode is on. Production pays one property read for it.
   */
  readonly onPlainWrite?: (info: PlainWriteInfo) => void;
}

/** {@link SensitiveColumnOptions} plus the length a `varchar` needs. */
export interface SensitiveVarcharOptions extends SensitiveColumnOptions {
  /** `varchar(n)`. Omitted, the column is a bare `varchar`. */
  readonly length?: number;
}

/** Options for {@link sensitiveLogger}. */
export interface SensitiveLoggerOptions {
  /**
   * Where a redacted log line goes.
   *
   * Omitted, nothing is printed and the logger is only the guard. That is the
   * common case: Drizzle logs nothing by default, and this option exists so a
   * deployment that wants query logging can have it without also getting the
   * plaintext.
   */
  readonly inner?: LoggerLike;
  /**
   * Refuse a statement whose parameters still hold a `SensitiveString`, or a
   * string that is a redaction marker.
   *
   * On by default, and turning it off is the whole reason this package tells
   * you to install the logger. See {@link sensitiveLogger}.
   */
  readonly refuse?: boolean;
  /**
   * Censor every string parameter, not only those of a statement that mentions
   * a classified column name.
   *
   * Off by default. Turn it on for a deployment where the log is shipped
   * somewhere with a wider audience than the database.
   */
  readonly redactAllParameters?: boolean;
  /**
   * Extra column names to treat as classified when deciding whether a
   * statement's parameters are censored.
   *
   * The names of every column built by this package's factories are registered
   * automatically, so this is for a column classified some other way: a view, a
   * generated column, or a table in another service whose statements pass
   * through this connection.
   */
  readonly alsoClassified?: readonly string[];
}

/** Options for {@link checkSchema}. */
export interface CheckOptions {
  /**
   * Proceed with a query cache configured.
   *
   * Deliberately awkward to type. It means the deployment accepts that every
   * cached select writes the driver's rows, classified columns included, into
   * whatever store the cache is backed by, before the read side of the column
   * has run.
   */
  readonly allowCachedPlaintext?: boolean;
  /**
   * Proceed without this package's logger installed.
   *
   * It means the deployment accepts that a `SensitiveString` reaching a bound
   * parameter through one of the paths a column cannot see is handed to the
   * driver unchanged. See {@link sensitiveLogger} for what each driver then
   * does with it.
   */
  readonly allowUnguarded?: boolean;
  /**
   * Accept a classified column that carries a column default.
   *
   * A literal default on a classified column is a secret in the schema file and
   * in every migration generated from it. Turn this on only for a default that
   * is not a secret, such as an empty string.
   */
  readonly allowColumnDefaults?: boolean;
  /**
   * Column names that must be classified wherever they appear.
   *
   * The one drift this package can check that the compiler cannot: a column
   * added to a table with `text('ssn')` instead of `sensitiveText('ssn')` is
   * well typed, compiles, and stores plaintext. Listing the name here turns
   * that into a boot-time failure.
   */
  readonly requireClassified?: readonly string[];
}

/** Options for {@link hydrateRawRows}. */
export interface HydrateRawOptions {
  /**
   * Property key each raw row is keyed by, when it differs from the column's
   * database name.
   *
   * A `db.select({ e: sql`${users.email}` })` names the result `e`, and a
   * driver-level `db.execute()` names it `email`. Both are handled: the
   * database name is tried first, then the schema key. Anything else needs a
   * mapping here, from the key in the row to the schema key of the column.
   */
  readonly keys?: Readonly<Record<string, string>>;
  /**
   * Leave a row key that matches no column alone.
   *
   * On by default. Turned off, an unmatched key is an error, which is what a
   * caller who believes the row is exactly one table's columns wants.
   */
  readonly allowUnknownKeys?: boolean;
}
