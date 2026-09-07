import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { eq, relations } from 'drizzle-orm';
import { integer, sqliteTable, text } from 'drizzle-orm/sqlite-core';
import { pgTable, serial, varchar } from 'drizzle-orm/pg-core';
import { expectTypeOf } from 'vitest';
import { credentialText, sensitiveText, sensitiveVarchar } from './pg.js';
import {
  credentialText as sqliteCredentialText,
  sensitiveText as sqliteSensitiveText,
} from './sqlite.js';

/**
 * The seam checks. Nothing here runs: the file is named `.test-d.ts` so
 * `pnpm typecheck` compiles it and `vitest run` does not collect it.
 *
 * There is more to check here than in the TypeORM integration, and that is the
 * point of the file. A `ValueTransformer` is two methods over `any`, so TypeORM
 * publishes no type for a transformed column and the property type is the
 * author's own annotation. A Drizzle `customType` publishes one, so the
 * classification and the type come from the same declaration and the compiler
 * checks them against each other.
 */

export const users = pgTable('users', {
  id: serial('id').primaryKey(),
  name: varchar('name', { length: 255 }),
  email: sensitiveText('email', { table: 'users' }).notNull(),
  passwordHash: credentialText('password_hash', { table: 'users' }).notNull(),
  ssn: sensitiveVarchar('ssn', { length: 11, table: 'users' }),
});

type Selected = typeof users.$inferSelect;
type Inserted = typeof users.$inferInsert;

// INV-DRIZZLE-006: the select type is a SensitiveString of the declared class,
// not a union with string.
expectTypeOf<Selected['email']>().toEqualTypeOf<SensitiveString<'sensitive'>>();
expectTypeOf<Selected['passwordHash']>().toEqualTypeOf<SensitiveString<'credential'>>();

// INV-DRIZZLE-011: an unclassified column is untouched.
expectTypeOf<Selected['name']>().toEqualTypeOf<string | null>();
expectTypeOf<Selected['id']>().toEqualTypeOf<number>();

// A nullable classified column is nullable in the type, and .notNull() removes
// the null exactly as it does for a built-in column.
expectTypeOf<Selected['ssn']>().toEqualTypeOf<SensitiveString<'sensitive'> | null>();

// INV-DRIZZLE-014, as it actually is. The insert type is the same
// SensitiveString, because customType has one `data` type serving both
// directions. A plain string is a compile error rather than the warning the
// design document described, and widening it here would widen the select type
// by the same amount.
expectTypeOf<Inserted['email']>().toEqualTypeOf<SensitiveString<'sensitive'>>();
expectTypeOf<Inserted['ssn']>().toExtend<SensitiveString<'sensitive'> | null | undefined>();
expectTypeOf<Inserted['name']>().toExtend<string | null | undefined>();

// @ts-expect-error a plain string is not an accepted insert value
const bad: Inserted = { email: 'a@example.com', passwordHash: 'hash' };
void bad;

// The two argument forms of the roadmap and of the design document both work,
// and the class flows into the type either way.
export const both = pgTable('both', {
  a: sensitiveText('a', 'credential'),
  b: sensitiveText('b', { label: 'b' }),
  c: sensitiveText('c', 'credential', { label: 'c' }),
  d: sensitiveText('d'),
});
expectTypeOf<
  (typeof both.$inferSelect)['a']
>().toEqualTypeOf<SensitiveString<'credential'> | null>();
expectTypeOf<
  (typeof both.$inferSelect)['b']
>().toEqualTypeOf<SensitiveString<'sensitive'> | null>();
expectTypeOf<
  (typeof both.$inferSelect)['c']
>().toEqualTypeOf<SensitiveString<'credential'> | null>();
expectTypeOf<
  (typeof both.$inferSelect)['d']
>().toEqualTypeOf<SensitiveString<'sensitive'> | null>();

// @ts-expect-error 'secret' is not a sensitivity class
sensitiveText('x', 'secret');

// A relational query carries the wrapping through the nesting, which is the
// invariant the design document called INV-DRIZZLE-004 and the reason the
// classification belongs on the column rather than in a configuration object.
const sqliteUsers = sqliteTable('users', {
  id: integer('id').primaryKey(),
  email: sqliteSensitiveText('email').notNull(),
  token: sqliteCredentialText('token'),
});
const sqlitePosts = sqliteTable('posts', {
  id: integer('id').primaryKey(),
  authorId: integer('author_id'),
  body: text('body'),
});
export const sqliteUsersRelations = relations(sqliteUsers, ({ many }) => ({
  posts: many(sqlitePosts),
}));
export const sqlitePostsRelations = relations(sqlitePosts, ({ one }) => ({
  author: one(sqliteUsers, { fields: [sqlitePosts.authorId], references: [sqliteUsers.id] }),
}));

declare const nested: { author: typeof sqliteUsers.$inferSelect };
expectTypeOf(nested.author.email).toEqualTypeOf<SensitiveString<'sensitive'>>();
expectTypeOf(nested.author.token).toEqualTypeOf<SensitiveString<'credential'> | null>();
expectTypeOf(nested.author.email.reveal({ name: 'x' })).toEqualTypeOf<string>();

// The column keeps its literal name in the type, which is what lets Drizzle's
// own casing and alias machinery stay precise across the wrapper. Read off the
// column's config rather than its `name` property, which Drizzle declares as a
// plain `string` on every column in every dialect.
expectTypeOf<(typeof users.email)['_']['name']>().toEqualTypeOf<'email'>();
expectTypeOf<(typeof users.passwordHash)['_']['name']>().toEqualTypeOf<'password_hash'>();

// `eq` takes the column's data type, so a plain literal in a predicate is a
// compile error even though the runtime accepts it. That is the trade the
// single `data` type forces, and it is the right way round for a classified
// column: the cast is visible in review.
// @ts-expect-error a bare string is not the column's data type
eq(users.email, 'a@example.com');
