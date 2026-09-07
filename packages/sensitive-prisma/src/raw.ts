import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { normalizeModelFields } from './config.js';
import { isSensitiveString } from './guard.js';
import type { ModelFieldConfig } from './config.js';
import { PrismaFieldTypeError } from './errors.js';
import { describeValue } from './describe.js';
import type { WrapRow } from './types.js';

/**
 * Wrap the configured columns of raw query rows.
 *
 * Raw results are the one read path the extension cannot cover on its own. A
 * type argument such as `$queryRaw<User[]>` is erased before the query hook
 * runs, and the hook is handed `model: undefined` for every raw operation, so
 * nothing at runtime can say which model a column belongs to. Rows therefore
 * come back as plain strings and this is the explicit step that classifies
 * them.
 *
 * Column names are matched exactly, so a statement that renames a column must
 * alias it back to the configured field name
 * (`SELECT password_hash AS "passwordHash"`). Columns the configuration does
 * not name are copied through untouched, and a configured field the row does
 * not contain adds no key.
 *
 * Bound parameters need no equivalent: the extension's query hook unwraps a
 * `SensitiveString` interpolated into `$queryRaw` or `$executeRaw` before the
 * statement reaches the driver.
 *
 * @param rows - Rows as Prisma returned them.
 * @param fields - The same per-model field configuration the extension takes.
 * @param model - Name used in refusals, for the case where the spec is wrong.
 * @returns New row objects; the input rows are not modified.
 * @throws PrismaConfigError If a spec names an unregistered class or is malformed.
 * @throws PrismaFieldTypeError If a named column is present but is not a string.
 *
 * @example
 * ```ts
 * const rows = await prisma.$queryRaw<{ id: number; email: string }[]>`
 *   SELECT id, email FROM users WHERE id = ${id}
 * `;
 * const users = wrapRows(rows, { email: 'sensitive' });
 * users[0]?.email.reveal({ name: 'report', reason: 'export' });
 * ```
 */
export function wrapRows<Row extends object, const Fields extends ModelFieldConfig>(
  rows: readonly Row[],
  fields: Fields,
  model = 'wrapRows'
): WrapRow<Row, Fields>[] {
  const specs = normalizeModelFields(model, fields);

  return rows.map((row) => {
    const wrapped: Record<string, unknown> = { ...(row as Record<string, unknown>) };

    for (const [field, { klass, label }] of specs.fields) {
      if (!Object.hasOwn(wrapped, field)) continue;

      const value = wrapped[field];
      if (value === null || value === undefined) continue;

      // Already an instance: a row that has been through this helper once, or
      // a hand-assembled row. Wrapping again would bury the value one level
      // deeper and reveal the inner instance instead of the string.
      if (isSensitiveString(value)) continue;

      if (Array.isArray(value)) {
        wrapped[field] = value.map((item) => {
          if (isSensitiveString(item)) return item;
          if (typeof item !== 'string') {
            throw new PrismaFieldTypeError(model, field, describeValue(item));
          }
          return new SensitiveString(item, klass, label);
        });
        continue;
      }

      if (typeof value !== 'string') {
        throw new PrismaFieldTypeError(model, field, describeValue(value));
      }

      wrapped[field] = new SensitiveString(value, klass, label);
    }

    return wrapped as WrapRow<Row, Fields>;
  });
}
