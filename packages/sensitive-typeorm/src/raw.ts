import { SensitiveString } from '@platform-sec/sensitive-string-core';
import type { SensitivityClass } from '@platform-sec/sensitive-string-core';
import { TypeOrmMarkerReadError } from './errors.js';
import { containsRedactionMarker } from './marker.js';
import type { HydrateRawOptions } from './types.js';

/** The part of a `DataSchema` this module needs, so the two do not import each other. */
interface ClassifyingSchema {
  classify(path: string): string;
}

/**
 * Wrap the classified columns of raw rows.
 *
 * `ds.query()` and `getRawMany()` return plaintext and always will: neither has
 * entity metadata, so there is no column for a `ValueTransformer` to be
 * attached to. This is the opt-in that closes the gap for a caller who knows
 * which table the rows came from, and it produces the same instances the read
 * transformer would have.
 *
 * Rows are copied rather than mutated, and a key the specification does not
 * classify is carried across by identity.
 *
 * @throws TypeOrmMarkerReadError If a classified column holds a redaction
 *   marker, on the same reasoning as the read transformer: the value is
 *   already gone and handing the marker on hides that.
 */
export function hydrateRawRows<Row extends Record<string, unknown>>(
  schema: ClassifyingSchema,
  table: string,
  rows: readonly Row[],
  options: HydrateRawOptions = {}
): Record<string, unknown>[] {
  const prefix = options.aliasPrefix === undefined ? undefined : `${options.aliasPrefix}_`;

  return rows.map((row) => {
    const out: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(row)) {
      const column =
        prefix !== undefined && key.startsWith(prefix) ? key.slice(prefix.length) : key;
      const klass = schema.classify(`${table}.${column}`);
      if (klass === 'plain' || value == null || typeof value !== 'string') {
        out[key] = value;
        continue;
      }
      if (containsRedactionMarker(value)) throw new TypeOrmMarkerReadError(`${table}.${column}`);
      out[key] = new SensitiveString(value, klass as SensitivityClass, column);
    }
    return out;
  });
}
