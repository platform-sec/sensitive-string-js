import { classificationOf } from './column.js';
import { DrizzleConfigError } from './errors.js';
import type { ColumnLike, HydrateRawOptions } from './types.js';

/** Drizzle's symbol for a table's column map. */
const TABLE_COLUMNS = Symbol.for('drizzle:Columns');

function columnsOf(table: unknown): Record<string, ColumnLike> {
  if (typeof table !== 'object' || table === null) {
    throw new DrizzleConfigError(
      `hydrateRawRows() was given something that is not a Drizzle table. Pass the table object ` +
        `from the schema module, not its name.`
    );
  }
  const columns: unknown = (table as Record<symbol, unknown>)[TABLE_COLUMNS];
  if (typeof columns !== 'object' || columns === null) {
    throw new DrizzleConfigError(
      `hydrateRawRows() was given an object with no Drizzle columns on it. Pass the table ` +
        `object from the schema module.`
    );
  }
  return columns as Record<string, ColumnLike>;
}

/**
 * Wrap the classified columns of rows a raw path returned.
 *
 * Drizzle maps a result through a column only when it knows which column the
 * value came from. Three ordinary paths do not give it that, and all three
 * return the plaintext:
 *
 * - `db.select({ e: sql`${users.email}` })`, where the selection is an
 *   expression and the decoder is `sql`'s own rather than the column's;
 * - `.values()` on a select, which returns the driver's arrays untouched;
 * - `db.execute(sql`...`)` and the dialect-specific raw runners, which return
 *   whatever the driver gave.
 *
 * This is the audited bypass for those. Give it the table the row came from and
 * it wraps the keys that match a classified column, leaving everything else
 * alone. It is not a substitute for the column: nothing about a raw path made
 * the value safe on its way out of the database, and the wrapping here happens
 * after it has already been an ordinary string in the process.
 *
 * @param rows - Plain objects, keyed by database column name or by schema key.
 * @param table - The Drizzle table the row came from.
 *
 * @example
 * ```ts
 * const rows = await db.execute(sql`select id, email from users`);
 * const users = hydrateRawRows(rows, usersTable);
 * users[0].email; // SensitiveString<'sensitive'>
 * ```
 */
export function hydrateRawRows<T extends Record<string, unknown>>(
  rows: readonly T[],
  table: unknown,
  options: HydrateRawOptions = {}
): Record<string, unknown>[] {
  const columns = columnsOf(table);
  const allowUnknown = options.allowUnknownKeys ?? true;
  const remap = options.keys ?? {};

  // Both the database name and the schema key resolve to the same column, so a
  // row from `db.execute()` (database names) and one from a `sql` selection
  // (whatever the caller named it) are both handled without being told which.
  const byName = new Map<string, ColumnLike>();
  for (const [schemaKey, column] of Object.entries(columns)) {
    byName.set(schemaKey, column);
    if (typeof column.name === 'string' && column.name !== '') byName.set(column.name, column);
  }

  return rows.map((row) => {
    if (typeof row !== 'object' || row === null) {
      throw new DrizzleConfigError(
        `hydrateRawRows() was given a row that is not an object. A .values() result is an array ` +
          `of arrays and has no keys to match against a column; select into named keys instead.`
      );
    }
    const out: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(row)) {
      const columnKey = remap[key] ?? key;
      const column = byName.get(columnKey);
      if (column === undefined) {
        if (!allowUnknown) {
          throw new DrizzleConfigError(
            `hydrateRawRows() found the key '${key}' in a row and no column of that name on the ` +
              `table. Map it with the keys option, or pass allowUnknownKeys: true.`
          );
        }
        out[key] = value;
        continue;
      }
      if (value === null || value === undefined) {
        out[key] = value;
        continue;
      }
      if (classificationOf(column) === undefined) {
        out[key] = value;
        continue;
      }
      // The column's own read side, so a marker in the column is refused here
      // exactly as it would be on an ordinary select.
      out[key] = column.mapFromDriverValue(value);
    }
    return out;
  });
}
