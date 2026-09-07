import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { eq, sql } from 'drizzle-orm';
import { int, mysqlTable } from 'drizzle-orm/mysql-core';
import { drizzle as mysqlDrizzle } from 'drizzle-orm/mysql2';
import { drizzle as pgDrizzle } from 'drizzle-orm/node-postgres';
import type { NodePgClient } from 'drizzle-orm/node-postgres';
import { pgTable, serial, text } from 'drizzle-orm/pg-core';
import { describe, expect, it } from 'vitest';
import { checkSchema } from '../check.js';
import { DrizzleParameterRefusedError } from '../errors.js';
import { sensitiveLogger } from '../logger.js';
import {
  credentialText as mysqlCredentialText,
  sensitiveVarchar as mysqlSensitiveVarchar,
} from '../mysql.js';
import { credentialText, sensitiveText, sensitiveVarchar } from '../pg.js';
import { CANARY } from './fixtures.js';

/**
 * The two dialects the SQLite suite does not cover.
 *
 * Both run against a stub client rather than a live server. What is being
 * checked is Drizzle's own behaviour, which happens entirely in the ORM: which
 * SQL type reaches the DDL, which values reach the parameter array, and whether
 * the guard is in the path. None of that involves the database, and standing
 * one up would trade a fast deterministic assertion for a slow flaky one.
 *
 * The transaction assertion is the exception in importance rather than in kind.
 * `node-postgres` builds a *new session* for a transaction when the client is a
 * pool, which is why the guard is installed as the logger rather than by
 * assigning to `db.session`: the logger is carried into the new session through
 * the options, and a mutation of the outer session would not be.
 */

const canary = new SensitiveString(CANARY, 'credential', 'token');

/**
 * A `pg` pool that answers every statement with an empty result.
 *
 * Not a subclass of `pg.Pool`: the real one opens a socket on construction and
 * its `query` is a set of overloads a stub cannot restate. The name is what
 * matters to Drizzle, which decides whether to reserve a connection for a
 * transaction with `constructor.name.includes('Pool')`.
 */
class StubPool {
  readonly seen: [string, unknown[]][] = [];
  query(config: unknown, values?: unknown[]): Promise<unknown> {
    const conf = config as { text?: string; values?: unknown[] };
    const statement = typeof config === 'string' ? config : (conf.text ?? '');
    this.seen.push([statement, (typeof config === 'string' ? values : conf.values) ?? []]);
    return Promise.resolve({ rows: [], fields: [], rowCount: 0 });
  }
  connect(): Promise<unknown> {
    return Promise.resolve({
      query: (config: unknown, values?: unknown[]) => this.query(config, values),
      release: () => undefined,
    });
  }
}

/** The stub, at the type `drizzle()` asks for. */
const asClient = (pool: StubPool): NodePgClient => pool as unknown as NodePgClient;

describe('postgres', () => {
  const users = pgTable('users', {
    id: serial('id').primaryKey(),
    name: text('name'),
    token: credentialText('token', { table: 'users' }),
    ssn: sensitiveVarchar('ssn', { length: 11, table: 'users' }),
    email: sensitiveText('email', { table: 'users' }),
  });
  const schema = { users };

  it('declares standard SQL types, so a migration is an ordinary migration', () => {
    expect(users.token.getSQLType()).toBe('text');
    expect(users.ssn.getSQLType()).toBe('varchar(11)');
    expect(users.email.getSQLType()).toBe('text');
  });

  it('produces a bare varchar when no length was given', () => {
    const t = pgTable('t', { v: sensitiveVarchar('v') });
    expect(t.v.getSQLType()).toBe('varchar');
  });

  it('reveals into the parameter array on insert', () => {
    const db = pgDrizzle(asClient(new StubPool()), { schema, logger: sensitiveLogger() });
    expect(db.insert(users).values({ token: canary }).toSQL().params).toEqual([CANARY]);
  });

  it('wraps what the driver returned', async () => {
    const pool = new StubPool();
    Object.defineProperty(pool, 'query', {
      value: () =>
        Promise.resolve({
          rows: [[1, 'A', CANARY, null, null]],
          fields: [
            { name: 'id' },
            { name: 'name' },
            { name: 'token' },
            { name: 'ssn' },
            { name: 'email' },
          ],
          rowCount: 1,
        }),
    });
    const db = pgDrizzle(asClient(pool), { schema, logger: sensitiveLogger() });
    const [row] = await db.select().from(users);
    expect(row?.token).toBeInstanceOf(SensitiveString);
    expect(JSON.stringify(row)).not.toContain(CANARY);
  });

  it('refuses a placeholder fill inside a transaction, on the session pg builds fresh', async () => {
    const pool = new StubPool();
    const db = pgDrizzle(asClient(pool), { schema, logger: sensitiveLogger() });
    await expect(
      db.transaction(async (tx) => {
        const prepared = tx
          .select()
          .from(users)
          .where(eq(users.token, sql.placeholder('t')))
          .prepare('p');
        await prepared.execute({ t: canary });
      })
    ).rejects.toThrow(DrizzleParameterRefusedError);
    expect(JSON.stringify(pool.seen)).not.toContain(CANARY);
  });

  it('is a different session object inside the transaction, which is why the logger is the seam', async () => {
    const pool = new StubPool();
    const db = pgDrizzle(asClient(pool), { schema, logger: sensitiveLogger() });
    let inner: unknown;
    await db.transaction((tx) => {
      inner = (tx as unknown as { session: unknown }).session;
      return Promise.resolve();
    });
    expect(inner).not.toBe((db as unknown as { session: unknown }).session);
    // ... and the guard reached it anyway, because it travels in the options.
    expect(() =>
      checkSchema({ session: { logger: (inner as { logger: unknown }).logger } }, schema)
    ).not.toThrow();
  });

  it('passes checkSchema when constructed with the guard', () => {
    const db = pgDrizzle(asClient(new StubPool()), { schema, logger: sensitiveLogger() });
    const result = checkSchema(db, schema);
    expect(result.classified.map((c) => c.path).sort()).toEqual([
      'users.email',
      'users.ssn',
      'users.token',
    ]);
  });
});

describe('mysql', () => {
  const users = mysqlTable('users', {
    id: int('id').primaryKey(),
    token: mysqlCredentialText('token', { table: 'users' }),
    ssn: mysqlSensitiveVarchar('ssn', { length: 11, table: 'users' }),
  });
  const schema = { users };
  const stubClient = {
    query: () => Promise.resolve([[], []]),
    execute: () => Promise.resolve([[], []]),
  };

  it('declares standard SQL types', () => {
    expect(users.token.getSQLType()).toBe('text');
    expect(users.ssn.getSQLType()).toBe('varchar(11)');
  });

  it('reveals into the parameter array on insert', () => {
    const db = mysqlDrizzle({
      client: stubClient as never,
      schema,
      mode: 'default',
      logger: sensitiveLogger(),
    });
    expect(db.insert(users).values({ id: 1, token: canary }).toSQL().params).toEqual([1, CANARY]);
  });

  it('refuses an instance that reached the parameter array unmapped', async () => {
    const db = mysqlDrizzle({
      client: stubClient as never,
      schema,
      mode: 'default',
      logger: sensitiveLogger(),
    });
    await expect(db.execute(sql`select * from users where token = ${canary}`)).rejects.toThrow(
      DrizzleParameterRefusedError
    );
  });

  it('passes checkSchema when constructed with the guard', () => {
    const db = mysqlDrizzle({
      client: stubClient as never,
      schema,
      mode: 'default',
      logger: sensitiveLogger(),
    });
    expect(
      checkSchema(db, schema)
        .classified.map((c) => c.path)
        .sort()
    ).toEqual(['users.ssn', 'users.token']);
  });
});
