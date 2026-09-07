import {
  SensitiveString,
  containsRedactionMarker,
  getCurrentRevealContext,
  getDevModeConfig,
  hasPolicy,
} from '@platform-sec/sensitive-string-core';
import { buildWriteContext } from '@platform-sec/sensitive-string-data';
import type { RevealContext, SensitivityClass } from '@platform-sec/sensitive-string-core';
import { TypeOrmConfigError, TypeOrmMarkerReadError, TypeOrmWriteRefusedError } from './errors.js';
import { SENSITIVE_TRANSFORMER } from './types.js';
import type {
  PlainWriteInfo,
  SensitiveColumnOptions,
  SensitiveTransformer,
  TransformerBrand,
} from './types.js';

/**
 * Paths already reported through `onPlainWrite`, so a hot endpoint reports
 * once rather than once per row.
 *
 * Module-level, and therefore shared by every transformer in the process. That
 * is the intent: the report names a path, and the same path built twice is the
 * same mistake twice.
 */
const reportedPlainWrites = new Set<string>();

/** Reset the once-per-path report. Exported for tests. */
export function resetPlainWriteReports(): void {
  reportedPlainWrites.clear();
}

function defaultOnPlainWrite(info: PlainWriteInfo): void {
  // The guard is one property read, which is what production pays for the
  // feature. Everything past it only runs for a developer who asked.
  if (!getDevModeConfig().enabled) return;
  // eslint-disable-next-line no-console
  console.warn(
    `[sensitive-typeorm] ${info.path} is classified '${info.klass}' but was handed a plain ` +
      `${info.received}. That is legitimate for a literal in a where clause and a mistake in a ` +
      `write: the write stores the string unprotected. Set strictWrites: true to refuse it.`
  );
}

function describe(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  return typeof value;
}

/**
 * Build the context one column write reveals under.
 *
 * `sensitive-data`'s, so that an audit sink reads the same tag names from every
 * ORM package in this family. What is TypeORM's own is the two arguments below.
 *
 * `operation` is always `'unknown'`, and it cannot be anything else. A
 * `ValueTransformer` is called with one argument. It is not told whether this
 * value is being inserted, updated, compared against for change detection, or
 * used as a predicate, and the only way to recover that is to read the stack,
 * which is not something a security library does in a hot path. The reason text
 * names all four rather than letting the shared default name two, because on
 * this hook all four really do arrive here.
 */
function writeContext(brand: TransformerBrand, options: SensitiveColumnOptions): RevealContext {
  return buildWriteContext({
    sink: 'typeorm',
    operation: 'unknown',
    klass: brand.klass,
    table: brand.table,
    column: brand.column,
    name: options.name ?? `typeorm:${brand.path}`,
    reason: options.reason ?? 'column write, predicate or change detection',
  });
}

/**
 * Reveal one value under a context that names the column it is going to.
 *
 * Core hands the same context to the policy's `checkRevealAllowed` and to
 * `auditReveal` as its third argument, so passing it is the whole of it: a sink
 * reads the table and the column from what it is given.
 *
 * This used to install the context ambiently as well, one AsyncLocalStorage
 * entry per column write, because the hook was told the value and the operation
 * and nothing else. Core's hook now carries the context, and the entry went
 * with the workaround.
 */
function revealFor(value: SensitiveString<SensitivityClass>, ctx: RevealContext): string {
  return value.reveal(ctx);
}

/**
 * A `ValueTransformer` for one classified column.
 *
 * Reads wrap, writes reveal, and both directions return `null` for `null` and
 * `undefined` for `undefined`. That last guard is not defensive coding: TypeORM
 * passes `undefined` to `to()` on two ordinary paths, `IsNull()` on a nullable
 * classified column and an `upsert` whose row object omits the column, and a
 * transformer that only guards `null` throws a `TypeError` from inside the ORM
 * on both.
 *
 * What this does not cover, because the hook is never called for it: a query
 * builder's named parameters. See `guardParameters()`, which is the only place
 * that sees those before the driver does.
 *
 * @param klass - Sensitivity class; must be registered with core's policy
 *   registry.
 * @param options - Table and column for the audit tags and the messages, plus
 *   the two strict modes.
 *
 * @throws TypeOrmConfigError If the class is not registered.
 *
 * @example
 * ```ts
 * @Column({ type: 'text', transformer: sensitiveColumn('sensitive', { table: 'users', column: 'email' }) })
 * email!: SensitiveString<'sensitive'>;
 * ```
 */
export function sensitiveColumn(
  klass: SensitivityClass,
  options: SensitiveColumnOptions = {}
): SensitiveTransformer {
  if (typeof klass !== 'string' || !hasPolicy(klass)) {
    throw new TypeOrmConfigError(
      `sensitiveColumn() was given sensitivity class '${String(klass)}', which is not ` +
        `registered. Register it with registerPolicy() before the entity is defined, or correct ` +
        `the spelling. A transformer built on an unregistered class would wrap values with no ` +
        `policy behind them.`
    );
  }

  const { table, column } = options;
  const path = table === undefined ? (column ?? '(unnamed column)') : `${table}.${column ?? '?'}`;
  const label = options.label ?? column;
  const brand: TransformerBrand = { klass, label, path, table, column };
  const onPlainWrite = options.onPlainWrite ?? defaultOnPlainWrite;

  const transformer: SensitiveTransformer = {
    [SENSITIVE_TRANSFORMER]: brand,

    to(value: unknown): unknown {
      // Both, and measured twice. `IsNull()` routes through `transformValue`
      // with no operand, and `upsert` passes `undefined` for a column the row
      // object omits.
      if (value == null) return value;

      if (value instanceof SensitiveString) {
        // Before the context is built, so a refusal costs nothing and so the
        // refusal is unambiguously about the absence rather than about
        // something the synthesised context did.
        if (options.strictContext === true && getCurrentRevealContext() == null) {
          throw new TypeOrmWriteRefusedError(
            path,
            `${path} is configured with strictContext and there is no ambient reveal context. ` +
              `Wrap the unit of work in withRevealContext() so the reveal this write performs is ` +
              `attributable.`
          );
        }
        const ctx = writeContext(brand, options);
        const revealed = revealFor(value as SensitiveString<SensitivityClass>, ctx);
        // A revealed value that is itself a marker means the instance was built
        // from one: something upstream serialised a wrapped value and wrapped
        // the result. Writing it destroys the column.
        if (containsRedactionMarker(revealed)) {
          throw new TypeOrmWriteRefusedError(
            path,
            `${path} was handed a SensitiveString whose value is a redaction marker. The ` +
              `instance was built from an already-redacted string, so the original value is ` +
              `gone and this write would store the marker.`
          );
        }
        return revealed;
      }

      if (typeof value === 'string') {
        if (containsRedactionMarker(value)) {
          throw new TypeOrmWriteRefusedError(
            path,
            `${path} was handed a plain string holding a redaction marker. Something upstream ` +
              `serialised a SensitiveString rather than revealing it; the value is already gone ` +
              `and this write would store the marker.`
          );
        }
        if (options.strictWrites === true) {
          throw new TypeOrmWriteRefusedError(
            path,
            `${path} is classified '${klass}' and was handed a plain string under strictWrites. ` +
              `Pass a SensitiveString, so the write is an audited reveal. A literal in a where ` +
              `clause is the one legitimate case; turn strictWrites off for this column if that ` +
              `is what this is.`
          );
        }
        if (!reportedPlainWrites.has(path)) {
          reportedPlainWrites.add(path);
          onPlainWrite({ path, klass, received: 'string' });
        }
        return value;
      }

      // A number, a Date, a Buffer: not this package's business. TypeORM has
      // its own column-type handling underneath, and refusing here would break
      // a spec applied to a column that is not text.
      if (options.strictWrites === true) {
        throw new TypeOrmWriteRefusedError(
          path,
          `${path} is classified '${klass}' and was handed a ${describe(value)} under ` +
            `strictWrites. Only a SensitiveString may be written to a classified column.`
        );
      }
      return value;
    },

    from(value: unknown): unknown {
      if (value == null) return value;
      // A spec applied to a non-text column, or a driver that returns a Buffer.
      // Wrapping would put an object where the application's own property type
      // says a string was, which is the failure the 'plain' fallback exists to
      // prevent, so leave it.
      if (typeof value !== 'string') return value;
      if (containsRedactionMarker(value)) throw new TypeOrmMarkerReadError(path);
      return new SensitiveString(value, klass, label);
    },
  };

  // Non-enumerable so the brand does not appear in an inspection of the entity
  // metadata, and so a caller spreading the transformer into an array does not
  // carry it somewhere it means nothing.
  Object.defineProperty(transformer, SENSITIVE_TRANSFORMER, {
    value: brand,
    enumerable: false,
    writable: false,
    configurable: false,
  });

  return transformer;
}

/** The brand a transformer of this package's carries, or `undefined`. */
export function brandOf(transformer: unknown): TransformerBrand | undefined {
  if (typeof transformer !== 'object' || transformer === null) return undefined;
  const brand = (transformer as Partial<SensitiveTransformer>)[SENSITIVE_TRANSFORMER];
  return brand ?? undefined;
}
