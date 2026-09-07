import {
  SensitiveString,
  createChildContext,
  getCurrentRevealContext,
  getDevModeConfig,
  hasPolicy,
} from '@platform-sec/sensitive-string-core';
import type { RevealContext, SensitivityClass } from '@platform-sec/sensitive-string-core';
import {
  DrizzleColumnTypeError,
  DrizzleConfigError,
  DrizzleMarkerReadError,
  DrizzleWriteRefusedError,
} from './errors.js';
import { containsRedactionMarker } from './marker.js';
import type {
  ColumnClassification,
  ColumnLike,
  PlainWriteInfo,
  SensitiveColumnOptions,
} from './types.js';

/**
 * The two halves Drizzle's `customType` needs from us, plus the SQL type.
 *
 * `customType` is dialect-specific and is the only thing this package imports
 * from `drizzle-orm`, so it stays in the three dialect entry points and this
 * module hands them a pair of functions. The behaviour is identical across
 * dialects because a `customType` column is: the mapping runs in Drizzle's
 * dialect-independent SQL builder and result mapper.
 */
export interface SensitiveMapping<C extends SensitivityClass> {
  readonly dataType: () => string;
  readonly toDriver: (value: SensitiveString<C> | string | null | undefined) => string | null;
  readonly fromDriver: (value: unknown) => SensitiveString<C>;
}

/**
 * Every database column name this package has classified, lowercased.
 *
 * Names only. It exists so {@link sensitiveLogger} can decide whether a
 * statement's parameters might carry a classified value without being handed
 * the schema, which keeps the logger a one-argument install at the point where
 * the database is constructed.
 *
 * Module-level and never pruned. A column is declared once at module load and
 * lives for the process, and a name that stops being classified would only make
 * the logger censor more than it needs to.
 */
const classifiedNames = new Set<string>();

/** The lowercased database names of every column this package has built. */
export function classifiedColumnNames(): ReadonlySet<string> {
  return classifiedNames;
}

/** Forget the registered names. Exported for tests. */
export function resetClassifiedColumnNames(): void {
  classifiedNames.clear();
}

/**
 * Paths already reported through `onPlainWrite`, so a hot endpoint reports
 * once rather than once per row.
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
    `[sensitive-drizzle] ${info.path} is classified '${info.klass}' but was handed a plain ` +
      `${info.received}. That is legitimate for a literal in a predicate and a mistake in a ` +
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
 * An ambient context established with `withRevealContext()` names the unit of
 * work the caller cares about, so its `name` and `reason` win: replacing them
 * with a constant would flatten a request-scoped audit trail into one bucket
 * per column. The table, the column and the sink travel in the tags instead,
 * and `createChildContext` is what keeps the ambient `auditReveal` hook and the
 * caller's own tags attached.
 *
 * The ambient context does reach here, on every path, and that is measured
 * rather than assumed. Drizzle builds a statement's parameters lazily, at the
 * moment the query is executed rather than the moment it is described, so the
 * reveal happens inside whatever context the caller awaited the query in,
 * including inside `db.transaction()`. The design document proposed a second
 * `AsyncLocalStorage` for write context on the assumption that it did not; that
 * store would have competed with core's and dropped the ambient audit hook.
 *
 * `operation` is always `'unknown'`, and it cannot be anything else.
 * `mapToDriverValue` is called with one argument. It is not told whether the
 * value is being inserted, updated, or used as a predicate, and the only way to
 * recover that is to read the stack, which is not something a security library
 * does in a hot path.
 */
function writeContext(
  path: string,
  klass: SensitivityClass,
  table: string | undefined,
  column: string,
  options: SensitiveColumnOptions
): RevealContext {
  const ambient = getCurrentRevealContext();
  return createChildContext({
    name: ambient?.name ?? options.name ?? `drizzle:${path}`,
    reason: ambient?.reason ?? options.reason ?? 'column write or predicate',
    tags: {
      sink: 'drizzle',
      operation: 'unknown',
      klass,
      ...(table === undefined ? {} : { table }),
      column,
    },
  });
}

/**
 * The read and write halves of one classified column.
 *
 * Reads wrap and writes reveal, both through Drizzle's `customType`.
 *
 * Both directions pass `null` through, and the write side has to. Drizzle skips
 * the mapping for `null` almost everywhere, in the result mapper and for an
 * insert, an update, an `onConflictDoUpdate` and every predicate builder, so
 * the guard reads as defensive. It is not. A prepared statement whose
 * `values()` used `sql.placeholder` calls `mapToDriverValue` at fill time with
 * whatever `execute()` was given, `null` included, and a mapping that refused
 * one would turn writing NULL to a nullable classified column into an error on
 * exactly that path. Measured on 0.45.2.
 *
 * What this does not cover, because Drizzle does not route it through a column:
 * a value interpolated into a `sql` template, and a prepared statement's
 * placeholder. See `sensitiveLogger()`, which is the only place that sees
 * those before the driver does.
 *
 * @throws DrizzleConfigError If the class is not registered.
 */
export function sensitiveMapping<C extends SensitivityClass>(
  klass: C,
  sqlType: string,
  column: string,
  options: SensitiveColumnOptions = {}
): SensitiveMapping<C> {
  if (typeof klass !== 'string' || !hasPolicy(klass)) {
    throw new DrizzleConfigError(
      `A sensitive column was declared with sensitivity class '${String(klass)}', which is not ` +
        `registered. Register it with registerPolicy() before the schema module is imported, or ` +
        `correct the spelling. A column built on an unregistered class would wrap values with ` +
        `no policy behind them.`
    );
  }
  if (typeof column !== 'string' || column === '') {
    throw new DrizzleConfigError(
      `A sensitive column was declared with no database column name. Drizzle allows a nameless ` +
        `column and derives the name from the schema key, but this package puts the name in ` +
        `every audit record and in the logger's decision about which statements carry ` +
        `classified parameters, so it has to be given: sensitiveText('email').`
    );
  }

  const path = options.table === undefined ? column : `${options.table}.${column}`;
  const label = options.label ?? column;
  const onPlainWrite = options.onPlainWrite ?? defaultOnPlainWrite;
  classifiedNames.add(column.toLowerCase());

  return {
    dataType: () => sqlType,

    toDriver(value: SensitiveString<C> | string | null | undefined): string | null {
      // `null` only, and `undefined` deliberately not. Both arrive by the same
      // route, a prepared statement's placeholder fill, and they mean different
      // things: `null` is a caller writing NULL to a nullable column, while
      // `undefined` is a caller who thought they were passing a value. A
      // missing key throws inside Drizzle, so an `undefined` here is explicit,
      // and treating it as NULL would overwrite a stored credential on the
      // quietest possible path. It falls through to the refusal below.
      if (value === null) return null;

      if (value instanceof SensitiveString) {
        // Before the context is built, so a refusal costs nothing and so the
        // refusal is unambiguously about the absence rather than about
        // something the synthesised context did.
        if (options.strictContext === true && getCurrentRevealContext() == null) {
          throw new DrizzleWriteRefusedError(
            path,
            `${path} is configured with strictContext and there is no ambient reveal context. ` +
              `Wrap the unit of work in withRevealContext() so the reveal this write performs ` +
              `is attributable.`
          );
        }
        const revealed = value.reveal(writeContext(path, klass, options.table, column, options));
        // A revealed value that is itself a marker means the instance was built
        // from one: something upstream serialised a wrapped value and wrapped
        // the result. Writing it destroys the column.
        if (containsRedactionMarker(revealed)) {
          throw new DrizzleWriteRefusedError(
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
          throw new DrizzleWriteRefusedError(
            path,
            `${path} was handed a plain string holding a redaction marker. Something upstream ` +
              `serialised a SensitiveString rather than revealing it; the value is already gone ` +
              `and this write would store the marker.`
          );
        }
        if (options.strictWrites === true) {
          throw new DrizzleWriteRefusedError(
            path,
            `${path} is classified '${klass}' and was handed a plain string under ` +
              `strictWrites. Pass a SensitiveString, so the write is an audited reveal. A ` +
              `literal in a predicate is the one legitimate case; turn strictWrites off for ` +
              `this column if that is what this is.`
          );
        }
        if (!reportedPlainWrites.has(path)) {
          reportedPlainWrites.add(path);
          onPlainWrite({ path, klass, received: 'string' });
        }
        return value;
      }

      // A number, a Date, a Buffer. The column's declared type is text and its
      // data type is a SensitiveString, so nothing well typed arrives here;
      // what does is a placeholder filled from an `any`, and passing it through
      // would store a value the property type says cannot exist.
      throw new DrizzleWriteRefusedError(
        path,
        `${path} is classified '${klass}' and was handed a ${describe(value)}. A classified ` +
          `column stores text: pass a SensitiveString, or a plain string for a literal ` +
          `predicate. A value of another type reaching here came from a prepared statement's ` +
          `placeholder or from a direct call to the column's mapToDriverValue.`
      );
    },

    fromDriver(value: unknown): SensitiveString<C> {
      if (typeof value !== 'string') {
        // A driver that answers a text column with a Buffer, or a schema whose
        // SQL type was overridden to something that is not text. Coercing hides
        // the mismatch, and wrapping a Buffer's `toString()` invents a value.
        // Drizzle never sends `null` here, so a nullish value is a direct call.
        throw new DrizzleColumnTypeError(path, describe(value));
      }
      if (containsRedactionMarker(value)) throw new DrizzleMarkerReadError(path);
      return new SensitiveString(value, klass, label);
    },
  };
}

/**
 * The sentinel a column is probed with to find out whether it is classified.
 *
 * Chosen so that a column which passes its input through unchanged is
 * recognisable in a message, and so that it is not a redaction marker: a
 * classified column refuses to read one back, and the probe would then look
 * like a broken column rather than a working one.
 */
const PROBE = '__sensitive_string_probe__';

/**
 * What a column classifies its values as, or `undefined` for a plain column.
 *
 * Asked by running the column's own read side over a sentinel and looking at
 * what comes back. That is entirely public API: `mapFromDriverValue` is
 * declared on Drizzle's `Column` base class in every dialect and is what the
 * result mapper itself calls. Reading the `customType` parameters off the
 * column instead would mean reaching for fields Drizzle declares private, which
 * is the kind of thing that works until a patch release.
 *
 * The cost is one `SensitiveString` allocation per column, at the moment
 * {@link checkSchema} runs, which is boot.
 */
export function classificationOf(column: unknown): ColumnClassification | undefined {
  if (typeof column !== 'object' || column === null) return undefined;
  const mapFrom = (column as Partial<ColumnLike>).mapFromDriverValue;
  if (typeof mapFrom !== 'function') return undefined;
  let probed: unknown;
  try {
    probed = mapFrom.call(column, PROBE);
  } catch {
    // A column whose read side throws on a string is not one of ours, and it is
    // not this function's business to say what it is.
    return undefined;
  }
  if (!(probed instanceof SensitiveString)) return undefined;
  // `instanceof` against a generic class narrows to `SensitiveString<any>`,
  // and the class argument is not recoverable from the check. The cast puts
  // the union back; `klass` carries the answer at runtime either way.
  const wrapped = probed as SensitiveString<SensitivityClass>;
  return { klass: wrapped.klass, label: wrapped.label };
}
