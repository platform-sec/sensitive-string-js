/**
 * SQLite column factories.
 *
 * `text` only. SQLite has no `varchar`: its type affinity rules treat
 * `varchar(11)` as `TEXT` with the length ignored, so a `sensitiveVarchar` here
 * would promise a constraint the database does not apply. Use
 * {@link sensitiveText} and put the length check where it can be enforced.
 *
 * @packageDocumentation
 */
import type { SensitiveString, SensitivityClass } from '@platform-sec/sensitive-string-core';
import { customType } from 'drizzle-orm/sqlite-core';
import type { ConvertCustomConfig, SQLiteCustomColumnBuilder } from 'drizzle-orm/sqlite-core';
import { sensitiveMapping } from './column.js';
import { splitArgs } from './factory.js';
import type { SensitiveColumnOptions } from './types.js';

/**
 * What a classified SQLite column builder is, spelled out.
 *
 * Named rather than inferred because the factories are overloaded, and an
 * overload signature has to declare its return type. It is exactly what
 * `customType<{ data: SensitiveString<C>; driverData: string }>(...)(name)`
 * produces, so `.notNull()`, `.default()`, `.primaryKey()`, `.unique()`,
 * `.$type()` and the rest of Drizzle's builder chain all compose as usual.
 */
export type SensitiveSqliteColumn<
  C extends SensitivityClass,
  TName extends string,
> = SQLiteCustomColumnBuilder<
  ConvertCustomConfig<TName, { data: SensitiveString<C>; driverData: string }>
>;

function build<C extends SensitivityClass, TName extends string>(
  klass: C,
  sqlType: string,
  name: TName,
  options: SensitiveColumnOptions
): SensitiveSqliteColumn<C, TName> {
  return customType<{ data: SensitiveString<C>; driverData: string }>(
    sensitiveMapping(klass, sqlType, name, options)
  )(name, undefined);
}

/**
 * A `text` column whose values are `SensitiveString` in TypeScript and plain
 * text in Postgres.
 *
 * Reads wrap and writes reveal, so the column's select type and its insert type
 * are both `SensitiveString<C>`. That is not an oversight: Drizzle's
 * `customType` has one `data` type serving both directions, and widening it to
 * `SensitiveString<C> | string` so a plain string could be inserted would widen
 * what a select returns by the same amount, which is the type lie this package
 * exists to remove. A plain string still works at runtime, because
 * `where(eq(users.email, 'literal'))` is an ordinary query and the predicate
 * goes through the same mapping.
 *
 * The migration is unaffected: `drizzle-kit` reads `text` from the column and
 * writes `text` in the SQL.
 *
 * @example
 * ```ts
 * export const users = sqliteTable('users', {
 *   id: integer('id').primaryKey({ autoIncrement: true }),
 *   email: sensitiveText('email', { table: 'users' }).notNull(),
 *   passwordHash: sensitiveText('password_hash', 'credential').notNull(),
 * });
 * ```
 */
export function sensitiveText<TName extends string>(
  name: TName,
  options?: SensitiveColumnOptions
): SensitiveSqliteColumn<'sensitive', TName>;
export function sensitiveText<C extends SensitivityClass, TName extends string>(
  name: TName,
  klass: C,
  options?: SensitiveColumnOptions
): SensitiveSqliteColumn<C, TName>;
export function sensitiveText<C extends SensitivityClass, TName extends string>(
  name: TName,
  klassOrOptions?: C | SensitiveColumnOptions,
  maybeOptions?: SensitiveColumnOptions
): SensitiveSqliteColumn<C, TName> {
  // The implementation signature carries the same type parameters as the wider
  // overload, so both overloads stay compatible with it. `klass` is narrowed by
  // the overloads rather than by anything visible here, which is what the cast
  // records.
  const { klass, options } = splitArgs('sensitive' as C, klassOrOptions, maybeOptions);
  return build(klass, 'text', name, options);
}

/** {@link sensitiveText} fixed to the `credential` class. */
export function credentialText<TName extends string>(
  name: TName,
  options: SensitiveColumnOptions = {}
): SensitiveSqliteColumn<'credential', TName> {
  return build('credential', 'text', name, options);
}
