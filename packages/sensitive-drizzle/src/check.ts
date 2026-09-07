import { classificationOf } from './column.js';
import { DrizzleCacheRefusedError, DrizzleDriftError, DrizzleGuardMissingError } from './errors.js';
import type { DriftFinding } from './errors.js';
import { loggerBrand } from './logger.js';
import type { CheckOptions, ColumnLike, DatabaseLike, SessionLike, TableLike } from './types.js';

/**
 * Drizzle's global registry symbol for the class tag it puts on its own
 * entities.
 *
 * `Symbol.for` rather than an import, so the root entry point still imports no
 * `drizzle-orm`. The symbol is part of how Drizzle's own `is()` works across
 * duplicate copies of the package, so reading it is the same contract `is()`
 * relies on.
 */
const ENTITY_KIND = Symbol.for('drizzle:entityKind');

/** Drizzle's symbol for a table's column map. */
const TABLE_COLUMNS = Symbol.for('drizzle:Columns');
/** Drizzle's symbol for a table's database name. */
const TABLE_NAME = Symbol.for('drizzle:Name');

/**
 * The session a database is actually using.
 *
 * `db.session` is where every dialect puts it. `db._.session` is where the
 * published type says it is, and 0.45.2 does not populate it; it is read second
 * so a release that starts to costs nothing to follow.
 */
function sessionOf(db: DatabaseLike): SessionLike | undefined {
  if (db.session !== undefined) return db.session;
  const underscore: unknown = db._;
  if (typeof underscore !== 'object' || underscore === null) return undefined;
  const { session } = underscore as { session?: SessionLike };
  if (typeof session !== 'object' || session === null) return undefined;
  return session;
}

function entityKindOf(value: unknown): string | undefined {
  if (typeof value !== 'object' || value === null) return undefined;
  const ctor: unknown = (value as { constructor?: unknown }).constructor;
  if (typeof ctor !== 'function') return undefined;
  const kind: unknown = (ctor as unknown as Record<symbol, unknown>)[ENTITY_KIND];
  return typeof kind === 'string' ? kind : undefined;
}

/**
 * The columns of a Drizzle table, by schema key.
 *
 * Read through Drizzle's own registry symbols rather than by enumerating the
 * table's own properties, because a table is a `Proxy` whose keys include the
 * relation helpers and whose column objects are also reachable as ordinary
 * properties. `getTableColumns()` in `drizzle-orm` does exactly this, and this
 * package cannot import it without pulling the ORM into a root entry point that
 * is meant to work with any one of the three dialect modules installed.
 */
function columnsOf(table: unknown): Record<string, ColumnLike> | undefined {
  if (typeof table !== 'object' || table === null) return undefined;
  const columns: unknown = (table as Record<symbol, unknown>)[TABLE_COLUMNS];
  if (typeof columns !== 'object' || columns === null) return undefined;
  return columns as Record<string, ColumnLike>;
}

function tableNameOf(table: unknown, fallback: string): string {
  if (typeof table !== 'object' || table === null) return fallback;
  const name: unknown = (table as Record<symbol, unknown>)[TABLE_NAME];
  return typeof name === 'string' && name !== '' ? name : fallback;
}

/** One classified column {@link checkSchema} found. */
export interface ClassifiedColumn {
  /** `table.column`, using the database names. */
  readonly path: string;
  readonly klass: string;
  readonly label: string | undefined;
  readonly sqlType: string;
}

/** What {@link checkSchema} found, when it did not throw. */
export interface CheckResult {
  readonly classified: readonly ClassifiedColumn[];
  /** Tables in the schema object that had no columns to inspect. */
  readonly skipped: readonly string[];
}

/**
 * Verify at boot that the deployment matches what the schema promises.
 *
 * Three questions, and each of them is silent without an answer:
 *
 * 1. **Is the guard installed?** The database has to have been constructed with
 *    `sensitiveLogger()`. Without it, a `SensitiveString` reaching a bound
 *    parameter through a `sql` template or a prepared statement's placeholder
 *    is handed to the driver, which on `pg` binds a redaction marker and
 *    reports success.
 * 2. **Is a query cache configured?** Drizzle's cache stores the driver's rows,
 *    which for a select are the rows before the column's read side runs.
 * 3. **Does any column that should be classified fail to be?** This is the one
 *    drift a Drizzle schema can still have. A misspelled column name is a
 *    compile error here, unlike in the Prisma and TypeORM integrations where
 *    classification is a string key, but `text('ssn')` where `sensitiveText`
 *    was meant compiles perfectly and stores plaintext. `requireClassified`
 *    names the columns that must never be declared that way.
 *
 * It also reports a classified column carrying a column default, because a
 * literal default on a classified column is a secret in the schema file and in
 * every migration generated from it.
 *
 * Run it behind an explicit call rather than at boot automatically: this
 * package has no seam that runs when a database is constructed, and inventing
 * one would mean patching something.
 *
 * @param db - The database handle, for the logger and cache questions.
 * @param tables - The schema object, the same one passed to `drizzle()`.
 *
 * @throws DrizzleGuardMissingError If the logger is absent or does not refuse.
 * @throws DrizzleCacheRefusedError If a query cache is configured.
 * @throws DrizzleDriftError If a column that must be classified is not.
 *
 * @example
 * ```ts
 * const db = drizzle(pool, { schema, logger: sensitiveLogger() });
 * checkSchema(db, schema, { requireClassified: ['password_hash', 'ssn'] });
 * ```
 */
export function checkSchema(
  db: DatabaseLike,
  tables: Readonly<Record<string, unknown>>,
  options: CheckOptions = {}
): CheckResult {
  const classified: ClassifiedColumn[] = [];
  const skipped: string[] = [];
  const findings: DriftFinding[] = [];
  const required = new Set((options.requireClassified ?? []).map((name) => name.toLowerCase()));

  for (const [key, table] of Object.entries(tables)) {
    const columns = columnsOf(table);
    if (columns === undefined) {
      // A `relations()` object, an enum, a sequence, or anything else a schema
      // module exports beside its tables.
      skipped.push(key);
      continue;
    }
    const tableName = tableNameOf(table, key);
    for (const [schemaKey, column] of Object.entries(columns)) {
      if (typeof column !== 'object' || column === null) continue;
      const dbName =
        typeof column.name === 'string' && column.name !== '' ? column.name : schemaKey;
      const path = `${tableName}.${dbName}`;
      const classification = classificationOf(column);

      if (classification === undefined) {
        if (required.has(dbName.toLowerCase()) || required.has(schemaKey.toLowerCase())) {
          findings.push({
            path,
            detail:
              `listed in requireClassified but declared with a plain column factory, so it ` +
              `stores and returns an unwrapped string`,
          });
        }
        continue;
      }

      classified.push({
        path,
        klass: classification.klass,
        label: classification.label,
        sqlType: typeof column.getSQLType === 'function' ? column.getSQLType() : '(unknown)',
      });

      if (column.hasDefault === true && options.allowColumnDefaults !== true) {
        findings.push({
          path,
          detail:
            `classified '${classification.klass}' and carries a column default. A literal ` +
            `default on a classified column is a secret in the schema file and in every ` +
            `migration generated from it. Pass { allowColumnDefaults: true } if the default is ` +
            `not one`,
        });
      }
    }
  }

  if (classified.length > 0) {
    const session = sessionOf(db);
    const brand = loggerBrand(session?.logger);
    if (brand === undefined || !brand.refuse) {
      if (options.allowUnguarded !== true) {
        throw new DrizzleGuardMissingError(classified.map((c) => c.path));
      }
    }

    const cacheKind = entityKindOf(session?.cache);
    if (cacheKind !== undefined && cacheKind !== 'NoopCache') {
      if (options.allowCachedPlaintext !== true) {
        throw new DrizzleCacheRefusedError(
          classified.map((c) => c.path),
          cacheKind
        );
      }
    }
  }

  if (findings.length > 0) throw new DrizzleDriftError(findings);

  return { classified, skipped };
}

/**
 * The classified columns of a schema, without any of the refusals.
 *
 * For a report, a test, or a startup log line. {@link checkSchema} is the one
 * that enforces.
 */
export function classifiedColumns(
  tables: Readonly<Record<string, unknown>>
): readonly ClassifiedColumn[] {
  const found: ClassifiedColumn[] = [];
  for (const [key, table] of Object.entries(tables)) {
    const columns = columnsOf(table);
    if (columns === undefined) continue;
    const tableName = tableNameOf(table, key);
    for (const [schemaKey, column] of Object.entries(columns)) {
      const classification = classificationOf(column);
      if (classification === undefined) continue;
      const dbName =
        typeof column.name === 'string' && column.name !== '' ? column.name : schemaKey;
      found.push({
        path: `${tableName}.${dbName}`,
        klass: classification.klass,
        label: classification.label,
        sqlType: typeof column.getSQLType === 'function' ? column.getSQLType() : '(unknown)',
      });
    }
  }
  return found;
}

export type { TableLike };
