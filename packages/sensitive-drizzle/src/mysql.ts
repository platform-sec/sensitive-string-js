/**
 * MySQL column factories.
 *
 * @packageDocumentation
 */
import type { SensitiveString, SensitivityClass } from '@platform-sec/sensitive-string-core';
import { customType } from 'drizzle-orm/mysql-core';
import type { ConvertCustomConfig, MySqlCustomColumnBuilder } from 'drizzle-orm/mysql-core';
import { sensitiveMapping } from './column.js';
import { splitArgs, varcharType } from './factory.js';
import type { SensitiveColumnOptions, SensitiveVarcharOptions } from './types.js';

/**
 * What a classified MySQL column builder is, spelled out.
 *
 * Named rather than inferred because the factories are overloaded, and an
 * overload signature has to declare its return type. It is exactly what
 * `customType<{ data: SensitiveString<C>; driverData: string }>(...)(name)`
 * produces, so `.notNull()`, `.default()`, `.primaryKey()`, `.unique()`,
 * `.$type()` and the rest of Drizzle's builder chain all compose as usual.
 *
 * `driverData` is `string | null` rather than `string` because the write side
 * passes a `null` through, which it has to: a prepared statement's placeholder
 * fill is one path that sends one. It is the driver-facing type only, and does
 * not reach `$inferSelect` or `$inferInsert`, both of which come from `data`.
 */
export type SensitiveMySqlColumn<
  C extends SensitivityClass,
  TName extends string,
> = MySqlCustomColumnBuilder<
  ConvertCustomConfig<TName, { data: SensitiveString<C>; driverData: string | null }>
>;

function build<C extends SensitivityClass, TName extends string>(
  klass: C,
  sqlType: string,
  name: TName,
  options: SensitiveColumnOptions
): SensitiveMySqlColumn<C, TName> {
  return customType<{ data: SensitiveString<C>; driverData: string | null }>(
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
 * export const users = mysqlTable('users', {
 *   id: int('id').primaryKey().autoincrement(),
 *   name: varchar('name', { length: 255 }),
 *   email: sensitiveText('email', { table: 'users' }).notNull(),
 *   passwordHash: sensitiveText('password_hash', 'credential').notNull(),
 * });
 * ```
 */
export function sensitiveText<TName extends string>(
  name: TName,
  options?: SensitiveColumnOptions
): SensitiveMySqlColumn<'sensitive', TName>;
export function sensitiveText<C extends SensitivityClass, TName extends string>(
  name: TName,
  klass: C,
  options?: SensitiveColumnOptions
): SensitiveMySqlColumn<C, TName>;
export function sensitiveText<C extends SensitivityClass, TName extends string>(
  name: TName,
  klassOrOptions?: C | SensitiveColumnOptions,
  maybeOptions?: SensitiveColumnOptions
): SensitiveMySqlColumn<C, TName> {
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
): SensitiveMySqlColumn<'credential', TName> {
  return build('credential', 'text', name, options);
}

/**
 * A `varchar` column whose values are `SensitiveString`.
 *
 * `length` produces `varchar(n)` in the DDL exactly as Drizzle's own `varchar`
 * does. The length is not enforced here: MySQL enforces it, and a check in
 * TypeScript would have to reveal the value to count its characters.
 */
export function sensitiveVarchar<TName extends string>(
  name: TName,
  options?: SensitiveVarcharOptions
): SensitiveMySqlColumn<'sensitive', TName>;
export function sensitiveVarchar<C extends SensitivityClass, TName extends string>(
  name: TName,
  klass: C,
  options?: SensitiveVarcharOptions
): SensitiveMySqlColumn<C, TName>;
export function sensitiveVarchar<C extends SensitivityClass, TName extends string>(
  name: TName,
  klassOrOptions?: C | SensitiveVarcharOptions,
  maybeOptions?: SensitiveVarcharOptions
): SensitiveMySqlColumn<C, TName> {
  // The implementation signature carries the same type parameters as the wider
  // overload, so both overloads stay compatible with it. `klass` is narrowed by
  // the overloads rather than by anything visible here, which is what the cast
  // records.
  const { klass, options } = splitArgs('sensitive' as C, klassOrOptions, maybeOptions);
  return build(klass, varcharType(options), name, options);
}

/** {@link sensitiveVarchar} fixed to the `credential` class. */
export function credentialVarchar<TName extends string>(
  name: TName,
  options: SensitiveVarcharOptions = {}
): SensitiveMySqlColumn<'credential', TName> {
  return build('credential', varcharType(options), name, options);
}
