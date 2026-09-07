import { compileClassification, hasPolicy } from '@platform-sec/sensitive-string-core';
import type { CompiledClassification, FieldClass } from '@platform-sec/sensitive-string-core';
import { TypeOrmCacheRefusedError, TypeOrmConfigError, TypeOrmDriftError } from './errors.js';
import type { DriftFinding } from './errors.js';
import { hydrateRawRows } from './raw.js';
import { brandOf, sensitiveColumn } from './transformer.js';
import type {
  CheckOptions,
  DataSchemaSpec,
  HydrateRawOptions,
  SensitiveColumnOptions,
  SensitiveTransformer,
  TransformerBrand,
} from './types.js';

/**
 * The part of TypeORM's `ColumnMetadata` this package reads.
 *
 * Structural, so nothing here imports the ORM. `databaseName` is the column as
 * the database spells it and `propertyName` is the entity's field;
 * `@Column({ name })` and an `EntitySchema` column both let the two differ,
 * which is why the specification is keyed on the database name and the property
 * name is only offered as an alias.
 */
export interface ColumnMetadataLike {
  readonly propertyName: string;
  readonly databaseName: string;
  readonly transformer?: unknown;
}

/** The part of TypeORM's `EntityMetadata` this package reads. */
export interface EntityMetadataLike {
  readonly name: string;
  readonly tableName: string;
  readonly columns: readonly ColumnMetadataLike[];
}

/** The part of TypeORM's `DataSource` `schema.check()` reads. */
export interface DataSourceLike {
  readonly entityMetadatas: readonly EntityMetadataLike[];
  readonly options: { readonly cache?: unknown };
}

/** A specification, compiled, with the four things built on top of it. */
export interface DataSchema {
  /** The compiled classification, shared with the logger and the guard. */
  readonly classification: CompiledClassification;
  /** The specification as given. */
  readonly spec: DataSchemaSpec;

  /**
   * The class the specification gives one `table.column` path.
   *
   * Never `undefined`: the fallback is required, so every path resolves.
   */
  classify(path: string): FieldClass;

  /**
   * A transformer for one column, with the class resolved from the
   * specification rather than passed again at the call site.
   *
   * @throws TypeOrmConfigError If the path resolves to `'plain'`. A
   *   pass-through transformer is worse than none: it looks like coverage.
   */
  column(path: string, options?: SensitiveColumnOptions): SensitiveTransformer;

  /**
   * Check a live `DataSource` against the specification.
   *
   * Four failures, every one of them silent without this. A column the
   * specification classifies with no transformer on it stores plaintext while
   * the entity's property type says otherwise. A column carrying one of this
   * package's transformers that the specification no longer classifies is a
   * stale annotation. A transformer built for a different path than the column
   * it sits on works, and audits every reveal under the wrong column, which is
   * what a copied line produces. And an exact `fields` entry that no column
   * matches is dead configuration: it is the quietest failure of the four,
   * because nothing is wrapped and nothing says so.
   *
   * Also refuses the query result cache. See `TypeOrmCacheRefusedError`.
   *
   * @throws TypeOrmDriftError With every finding at once, so one run fixes
   *   them all. Drift is reported before the cache is examined, so a
   *   `DataSource` with both problems reports the drift first.
   * @throws TypeOrmCacheRefusedError If the cache is on and anything is
   *   classified.
   */
  check(dataSource: DataSourceLike, options?: CheckOptions): void;

  /**
   * Wrap the classified columns of rows that came back from a raw query.
   *
   * The explicit opt-in for `ds.query()` and `getRawMany()`, which return
   * plaintext because neither has entity metadata for the transformer to
   * consult. An audited bypass is better than a silent one, and this is what
   * makes the limitation something a caller can act on.
   */
  hydrateRaw<Row extends Record<string, unknown>>(
    table: string,
    rows: readonly Row[],
    options?: HydrateRawOptions
  ): Record<string, unknown>[];
}

function splitPath(path: string): { table: string | undefined; column: string } {
  const at = path.lastIndexOf('.');
  if (at <= 0 || at === path.length - 1) return { table: undefined, column: path };
  return { table: path.slice(0, at), column: path.slice(at + 1) };
}

function assertSpec(spec: DataSchemaSpec): void {
  if (typeof spec !== 'object' || spec === null) {
    throw new TypeOrmConfigError(
      `defineSchema() expects a specification object with 'fields', 'rules' and 'fallback'.`
    );
  }
  if (spec.fallback === undefined) {
    throw new TypeOrmConfigError(
      `defineSchema() requires 'fallback'. It is normally 'plain': a column nothing classifies ` +
        `must stay an ordinary string, because wrapping one puts an object where the ` +
        `application compares a string and the comparison becomes permanently false.`
    );
  }
  for (const [path, klass] of Object.entries(spec.fields ?? {})) {
    if (path === '') {
      throw new TypeOrmConfigError(`A field is classified under an empty path.`);
    }
    if (klass !== 'plain' && !hasPolicy(klass)) {
      throw new TypeOrmConfigError(
        `'${path}' names sensitivity class '${String(klass)}', which is not registered. ` +
          `Register it with registerPolicy() before defining the schema, or correct the spelling.`
      );
    }
  }
  for (const rule of spec.rules ?? []) {
    if (rule.klass !== 'plain' && !hasPolicy(rule.klass)) {
      throw new TypeOrmConfigError(
        `A classification rule names sensitivity class '${String(rule.klass)}', which is not ` +
          `registered.`
      );
    }
  }
}

/**
 * Compile a specification into the schema the rest of the package hangs off.
 *
 * The class of a column is named here, once, rather than repeated at each
 * `@Column`. That is what makes the drift check possible and what lets the same
 * specification be handed to a shared data layer later without rewriting it.
 *
 * @param spec - Exact `table.column` matches, then rules in order, then the
 *   required fallback.
 * @param defaults - Options every column built from this schema starts with.
 *   A per-column `options` argument still wins.
 *
 * @throws TypeOrmConfigError If the shape is wrong or a class is unregistered.
 *
 * @example
 * ```ts
 * const schema = defineSchema({
 *   fields: { 'users.password_hash': 'credential', 'users.email': 'sensitive' },
 *   rules: [{ pattern: /(^|[._])(token|secret)([._]|$)/i, klass: 'credential' }],
 *   fallback: 'plain',
 * });
 * ```
 */
export function defineSchema(
  spec: DataSchemaSpec,
  defaults: Omit<SensitiveColumnOptions, 'table' | 'column' | 'label'> = {}
): DataSchema {
  assertSpec(spec);
  const classification = compileClassification(spec);

  const classify = (path: string): FieldClass => {
    const { column } = splitPath(path);
    // The bare column name is offered as an alias so a rule written /password/
    // matches users.password_hash without anticipating the table.
    return classification.classify(path, [column]) ?? spec.fallback;
  };

  const schema: DataSchema = {
    classification,
    spec,
    classify,

    column(path: string, options: SensitiveColumnOptions = {}): SensitiveTransformer {
      const klass = classify(path);
      if (klass === 'plain') {
        throw new TypeOrmConfigError(
          `schema.column('${path}') resolves to 'plain', so there is nothing to build. A ` +
            `pass-through transformer is worse than no transformer: it reads as coverage in a ` +
            `review and protects nothing. Classify the path in the specification, or drop the ` +
            `transformer from the column.`
        );
      }
      const { table, column } = splitPath(path);
      return sensitiveColumn(klass, {
        ...defaults,
        ...(table === undefined ? {} : { table }),
        column,
        ...options,
      });
    },

    check(dataSource: DataSourceLike, options: CheckOptions = {}): void {
      const findings: DriftFinding[] = [];
      const classified: string[] = [];
      const usedFields = new Set<string>();

      for (const entity of dataSource.entityMetadatas) {
        for (const col of entity.columns) {
          const path = `${entity.tableName}.${col.databaseName}`;
          const expected = classification.classify(path, [col.databaseName, col.propertyName]);
          const klass = expected ?? spec.fallback;
          const brands = transformerBrands(col.transformer);

          // Which exact entries a real column could have been answered by. A
          // rule cannot be tracked this way, because it is a pattern with no
          // names behind it, but an exact entry that nothing matched is dead
          // configuration and is reported below.
          for (const candidate of [path, col.databaseName, col.propertyName]) {
            if (classification.fields.has(candidate)) usedFields.add(candidate);
          }

          if (klass !== 'plain') {
            classified.push(path);
            if (brands.length === 0) {
              findings.push({
                path,
                detail:
                  `classified '${klass}' but carries no transformer from this package, so it ` +
                  `stores plaintext and reads back a plain string. Add ` +
                  `transformer: schema.column('${path}') to ${entity.name}.${col.propertyName}.`,
              });
              continue;
            }
          } else if (brands.length > 0) {
            findings.push({
              path,
              detail:
                `carries a transformer from this package but the specification classifies it ` +
                `'plain'. Either the specification lost an entry or the annotation is stale; ` +
                `one of the two is wrong and both are silent.`,
            });
            continue;
          }

          for (const brand of brands) {
            if (brand.table !== undefined && brand.path !== path) {
              findings.push({
                path,
                detail:
                  `carries a transformer built for '${brand.path}'. It works, and it audits ` +
                  `every reveal under the wrong column. This is what a copied schema.column() ` +
                  `line looks like.`,
              });
            }
            if (klass !== 'plain' && brand.klass !== klass) {
              findings.push({
                path,
                detail:
                  `is classified '${klass}' but its transformer wraps values as ` +
                  `'${brand.klass}'. The column would read back under a policy the ` +
                  `specification did not choose.`,
              });
            }
          }
        }
      }

      // A specification entry no column answered. This is the failure that
      // looks most like success: the entry classifies nothing, no column is
      // wrapped, every read returns a plain string where the property type
      // promises an instance, and nothing else in the package is in a position
      // to notice. One renamed table or one mistyped column turns the whole
      // guarantee off silently, which is exactly what the drift check exists
      // to prevent.
      if (options.allowUnmatchedFields !== true) {
        for (const [key, klass] of classification.fields) {
          if (klass === 'plain' || usedFields.has(key)) continue;
          findings.push({
            path: key,
            detail:
              `is classified '${klass}' in the specification, but no column of any entity on ` +
              `this DataSource is named by it. The entry protects nothing: whatever column it ` +
              `was meant for is storing and returning plaintext. Check the table and column ` +
              `names as the database spells them, or pass { allowUnmatchedFields: true } if ` +
              `this specification deliberately covers more than one DataSource.`,
          });
        }
      }

      if (findings.length > 0) throw new TypeOrmDriftError(findings);

      if (
        options.allowCachedPlaintext !== true &&
        dataSource.options.cache !== undefined &&
        dataSource.options.cache !== false &&
        classified.length > 0
      ) {
        throw new TypeOrmCacheRefusedError(classified);
      }
    },

    hydrateRaw<Row extends Record<string, unknown>>(
      table: string,
      rows: readonly Row[],
      hydrateOptions: HydrateRawOptions = {}
    ): Record<string, unknown>[] {
      return hydrateRawRows(schema, table, rows, hydrateOptions);
    },
  };

  return schema;
}

/**
 * The brands on a column's transformer, which may be one or an array.
 *
 * TypeORM applies an array left to right on the way to the database and right
 * to left on the way back, so this package's transformer composes with an
 * encryption one underneath it. The drift check has to look inside the array
 * or it would report every composed column as unprotected.
 */
function transformerBrands(transformer: unknown): TransformerBrand[] {
  const candidates: unknown[] = Array.isArray(transformer) ? transformer : [transformer];
  const brands: TransformerBrand[] = [];
  for (const candidate of candidates) {
    const brand = brandOf(candidate);
    if (brand !== undefined) brands.push(brand);
  }
  return brands;
}
