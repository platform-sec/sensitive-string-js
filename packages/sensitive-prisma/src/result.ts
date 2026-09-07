import { SensitiveString } from '@platform-sec/sensitive-string-core';
import type { SensitivityClass } from '@platform-sec/sensitive-string-core';
import type { NormalizedConfig, NormalizedField } from './config.js';
import { describeValue } from './describe.js';
import { PrismaFieldTypeError } from './errors.js';
import { isSensitiveString } from './guard.js';

/** One computed field as Prisma's `result` extension component describes it. */
export interface ComputedField {
  readonly needs: Readonly<Record<string, boolean>>;
  /**
   * Declared as a function property rather than a method, which it is: it
   * closes over its field's configuration and never reads `this`, and Prisma
   * calls it with the row alone.
   */
  readonly compute: (row: Readonly<Record<string, unknown>>) => unknown;
}

/** The `result` argument of a Prisma client extension. */
export type ResultComponentValue = Readonly<
  Record<string, Readonly<Record<string, ComputedField>>>
>;

/**
 * Build the `compute` for one classified field.
 *
 * The runtime follows the shape of the value, not the shape the configuration
 * declared: `null` and `undefined` pass through, an array is wrapped element by
 * element, and a string is wrapped. `nullable` and `list` in the configuration
 * decide only the published type, so a mismatch between them and the schema
 * produces a wrong type rather than a failed read or an unwrapped value.
 *
 * Anything else is a column this package cannot wrap, and the refusal names the
 * model and field and the JavaScript type that arrived. It never carries the
 * value: a `PrismaFieldTypeError` is raised inside a query and travels the same
 * paths a leak would.
 */
function buildCompute(
  model: string,
  field: string,
  { klass, label }: NormalizedField
): (row: Readonly<Record<string, unknown>>) => unknown {
  const wrapOne = (value: unknown): SensitiveString<SensitivityClass> => {
    // Already wrapped: another result extension classified the same field
    // first, or this extension was applied twice. Wrapping again would bury
    // the value a level deeper, where `reveal()` returns the inner instance's
    // marker rather than the string.
    if (isSensitiveString(value)) {
      return value;
    }
    if (typeof value !== 'string') {
      throw new PrismaFieldTypeError(model, field, describeValue(value));
    }
    return new SensitiveString(value, klass, label);
  };

  return (row) => {
    const value = row[field];

    // A `null` column stays `null`, and an absent one stays absent. The empty
    // string is a value and is wrapped: a required column typed
    // `SensitiveString<C>` must not become nullable because a row holds ''.
    if (value === null || value === undefined) {
      return value;
    }

    if (Array.isArray(value)) {
      return value.map((item) => wrapOne(item));
    }

    return wrapOne(value);
  };
}

/**
 * Turn a validated configuration into Prisma's `result` extension component.
 *
 * One `needs`/`compute` entry per configured field, keyed by the client
 * property name. Prisma applies a result extension per model wherever that
 * model appears in a result, so relations loaded through `include` or `select`
 * are covered by the same entry and this package never walks a result tree.
 *
 * Only configured models appear, so a model absent from the configuration is
 * returned exactly as Prisma produced it.
 */
export function buildResultComponent(config: NormalizedConfig): ResultComponentValue {
  const result: Record<string, Record<string, ComputedField>> = {};

  for (const [key, model] of config.models) {
    const entry: Record<string, ComputedField> = {};
    for (const [field, spec] of model.fields) {
      entry[field] = {
        needs: { [field]: true },
        compute: buildCompute(model.name, field, spec),
      };
    }
    result[key] = entry;
  }

  return result;
}
