import Database from 'better-sqlite3';
import { relations } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { integer, sqliteTable, text } from 'drizzle-orm/sqlite-core';
import { credentialText, sensitiveText } from '../sqlite.js';
import { sensitiveLogger } from '../logger.js';
import type { LoggerLike, SensitiveLoggerOptions } from '../types.js';

/** The value every canary assertion looks for. */
export const CANARY = 'LEAKED_SECRET_abc123xyz';

export const users = sqliteTable('users', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  name: text('name'),
  email: sensitiveText('email', { table: 'users' }).notNull(),
  token: credentialText('token', { table: 'users' }),
});

export const posts = sqliteTable('posts', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  authorId: integer('author_id').references(() => users.id),
  body: sensitiveText('body', { table: 'posts' }),
});

export const usersRelations = relations(users, ({ many }) => ({ posts: many(posts) }));
export const postsRelations = relations(posts, ({ one }) => ({
  author: one(users, { fields: [posts.authorId], references: [users.id] }),
}));

export const schema = { users, posts, usersRelations, postsRelations };

const DDL = `
  CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name text,
    email text NOT NULL,
    token text
  );
  CREATE TABLE posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id integer,
    body text
  );
`;

/** Everything one test needs, with the query log captured. */
export interface Harness {
  readonly db: ReturnType<typeof drizzle<typeof schema>>;
  readonly sqlite: Database.Database;
  /** Every statement the logger saw, after redaction. */
  readonly lines: [string, unknown[]][];
  /** Every statement the driver saw, before Drizzle touched the result. */
  readonly statements: [string, unknown[]][];
  close(): void;
}

/**
 * A database on an in-memory SQLite file, with this package's logger installed.
 *
 * `statements` is captured by wrapping `better-sqlite3`'s own `prepare`, which
 * is under the guard rather than in front of it: what it records is what the
 * driver was actually given, so a canary assertion over it is an assertion
 * about the wire and not about the ORM's intentions.
 */
export function harness(options: SensitiveLoggerOptions = {}): Harness {
  const sqlite = new Database(':memory:');
  sqlite.exec(DDL);

  const statements: [string, unknown[]][] = [];
  const originalPrepare = sqlite.prepare.bind(sqlite);
  Object.defineProperty(sqlite, 'prepare', {
    value: (source: string) => {
      const stmt = originalPrepare(source);
      for (const method of ['run', 'all', 'get'] as const) {
        const original = stmt[method].bind(stmt);
        Object.defineProperty(stmt, method, {
          value: (...args: unknown[]) => {
            statements.push([source, args]);
            return original(...args);
          },
          configurable: true,
          writable: true,
        });
      }
      return stmt;
    },
    configurable: true,
    writable: true,
  });

  const lines: [string, unknown[]][] = [];
  const inner: LoggerLike = { logQuery: (q, p) => void lines.push([q, p]) };
  const db = drizzle(sqlite, {
    schema,
    logger: sensitiveLogger({ inner, ...options }),
  });

  return { db, sqlite, lines, statements, close: () => sqlite.close() };
}

/** Everything a harness saw, as one string, for a canary assertion. */
export function everythingSeen(h: Harness): string {
  return JSON.stringify([h.lines, h.statements]);
}
