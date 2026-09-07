import type { SensitiveString } from '@platform-sec/sensitive-string-core';
import { DataSource, EntitySchema } from 'typeorm';
import type { DataSourceOptions } from 'typeorm';
import { defineSchema } from '../schema.js';
import type { DataSchema } from '../schema.js';
import type { SensitiveColumnOptions } from '../types.js';

/**
 * The canary every suite in this package writes.
 *
 * One constant, so a test that asserts absence and a test that asserts presence
 * cannot drift apart into agreeing for the wrong reason.
 */
export const CANARY = 'LEAKED_SECRET_abc123xyz';

/** A second one, for the credential column, so the two are distinguishable. */
export const KEY_CANARY = 'LEAKED_KEY_zyx987cba';

/**
 * The specification the suites share.
 *
 * `users.email` and `users.api_key` are named exactly; `posts.body` arrives
 * through a rule, so the rule half of the specification is exercised too.
 * `users.name` is left to the fallback and is the control: a column that must
 * come back a plain string.
 */
export function testSchema(defaults: SensitiveColumnOptions = {}): DataSchema {
  return defineSchema(
    {
      fields: {
        'users.email': 'sensitive',
        'users.api_key': 'credential',
      },
      rules: [{ pattern: /^body$/i, klass: 'sensitive' }],
      fallback: 'plain',
    },
    defaults
  );
}

/**
 * The rows as the application sees them.
 *
 * Declared because the annotation is the author's, not TypeORM's: nothing in
 * the ORM checks that a transformed column's property type matches what the
 * transformer produces. Writing it out here is what the README recommends, so
 * the fixtures use the shape the documentation does.
 */
export interface UserRow {
  id: number;
  name: string;
  email: SensitiveString<'sensitive'>;
  apiKey: SensitiveString<'credential'> | null;
  deletedAt: Date | null;
  posts: PostRow[];
}

export interface PostRow {
  id: number;
  body: SensitiveString<'sensitive'>;
  author: UserRow;
}

/** The entities, built from a schema so each suite gets its own transformers. */
export function entities(schema: DataSchema): {
  User: EntitySchema<UserRow>;
  Post: EntitySchema<PostRow>;
} {
  const User = new EntitySchema<UserRow>({
    name: 'User',
    tableName: 'users',
    columns: {
      id: { type: Number, primary: true, generated: true },
      name: { type: String },
      email: { type: String, transformer: schema.column('users.email') },
      apiKey: {
        type: String,
        name: 'api_key',
        nullable: true,
        transformer: schema.column('users.api_key'),
      },
      // Present so the suite can assert what a soft delete does to a
      // classified column, which is nothing.
      deletedAt: { type: Date, deleteDate: true, nullable: true },
    },
    relations: {
      posts: { type: 'one-to-many', target: 'Post', inverseSide: 'author' },
    },
  });

  const Post = new EntitySchema<PostRow>({
    name: 'Post',
    tableName: 'posts',
    columns: {
      id: { type: Number, primary: true, generated: true },
      body: { type: String, transformer: schema.column('posts.body') },
    },
    relations: {
      author: { type: 'many-to-one', target: 'User', inverseSide: 'posts', joinColumn: true },
    },
  });

  return { User, Post };
}

/**
 * An initialised in-memory `DataSource`.
 *
 * A real database rather than a mock, because the whole finding this package
 * exists for is that the three drivers disagree about what to do with an object
 * and a mock would agree with whichever one it was written against.
 */
export async function makeDataSource(
  schema: DataSchema,
  options: Partial<DataSourceOptions> = {}
): Promise<DataSource> {
  const { User, Post } = entities(schema);
  const ds = new DataSource({
    type: 'better-sqlite3',
    database: ':memory:',
    synchronize: true,
    entities: [User, Post],
    ...options,
  } as DataSourceOptions);
  await ds.initialize();
  return ds;
}

/**
 * A raw query with its row type named.
 *
 * `DataSource.query` is generic over the whole result and defaults to `any`,
 * which spreads through every assertion made on what comes back. Every suite
 * here reads rows through this so a canary sweep is checking a typed value
 * rather than an `any`.
 */
export function rawRows<T = Record<string, unknown>>(
  ds: DataSource,
  sql: string,
  parameters?: unknown[]
): Promise<T[]> {
  return ds.query<T[]>(sql, parameters);
}
