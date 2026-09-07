import { inspect } from 'node:util';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import Database from 'better-sqlite3';
import { eq, sql } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { DrizzleQueryError } from 'drizzle-orm/errors';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { checkSchema } from '../check.js';
import { DrizzleParameterRefusedError } from '../errors.js';
import { hydrateRawRows } from '../raw.js';
import { sanitizeQueryError } from '../sanitize.js';
import { CANARY, everythingSeen, harness, schema, users } from './fixtures.js';
import type { Harness } from './fixtures.js';

let h: Harness;

beforeEach(() => {
  h = harness();
  h.db
    .insert(users)
    .values({
      name: 'A',
      email: new SensitiveString('a@example.com', 'sensitive'),
      token: new SensitiveString(CANARY, 'credential'),
    })
    .run();
});

afterEach(() => {
  h.close();
});

describe('a canary read back from the database', () => {
  it('does not appear in JSON.stringify of the row', () => {
    const rows = h.db.select().from(users).all();
    expect(JSON.stringify(rows)).not.toContain(CANARY);
  });

  it('does not appear in a template string', () => {
    const row = h.db.select().from(users).get();
    expect(`${String(row?.token)}`).not.toContain(CANARY);
  });

  it('does not appear in util.inspect, which is what console.log prints', () => {
    const rows = h.db.select().from(users).all();
    expect(inspect(rows, { depth: null })).not.toContain(CANARY);
  });

  it('does not appear in console.log', () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
    // eslint-disable-next-line no-console
    console.log(h.db.select().from(users).all());
    const printed = log.mock.calls.map((c) => inspect(c)).join('');
    expect(printed).not.toContain(CANARY);
    log.mockRestore();
  });

  it('does not appear in a nested relational result', () => {
    const rows = h.db.query.users.findMany({ with: { posts: true } }).sync();
    expect(JSON.stringify(rows)).not.toContain(CANARY);
  });

  it('is still there when explicitly revealed, which is the whole contract', () => {
    const row = h.db.select().from(users).get();
    expect(row?.token?.reveal({ name: 'test', reason: 'assertion' })).toBe(CANARY);
  });

  it('compares in constant time, because the column carries the credential class', () => {
    const row = h.db.select().from(users).get();
    expect(row?.token?.klass).toBe('credential');
    expect(row?.token?.equals(new SensitiveString(CANARY, 'credential'))).toBe(true);
    expect(row?.token?.equals(new SensitiveString('wrong', 'credential'))).toBe(false);
  });
});

describe('the query log', () => {
  it('loses the parameters of a statement touching a classified column', () => {
    h.db
      .select()
      .from(users)
      .where(eq(users.token, new SensitiveString(CANARY, 'credential')))
      .all();
    expect(JSON.stringify(h.lines)).not.toContain(CANARY);
  });

  it('loses them on the write side too', () => {
    h.lines.length = 0;
    h.db
      .insert(users)
      .values({ name: 'B', email: new SensitiveString(CANARY, 'sensitive') })
      .run();
    expect(JSON.stringify(h.lines)).not.toContain(CANARY);
  });

  it("leaks without this package's logger, which is the reason it exists", () => {
    // The negative control. Drizzle's own logger receives the revealed
    // parameters, because by the time it is called the column has done its job.
    const sqlite = new Database(':memory:');
    sqlite.exec(
      'CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, name text, email text NOT NULL, token text)'
    );
    const lines: string[] = [];
    const db = drizzle(sqlite, {
      schema,
      logger: { logQuery: (q, p) => void lines.push(`${q} ${JSON.stringify(p)}`) },
    });
    db.insert(users)
      .values({ name: 'A', email: new SensitiveString(CANARY, 'sensitive') })
      .run();
    expect(lines.join('')).toContain(CANARY);
    sqlite.close();
  });
});

describe('a failing statement', () => {
  it('carries the revealed parameters in three places before sanitizing', () => {
    const error = new DrizzleQueryError(
      'insert into "users" ("email") values ($1)',
      [CANARY],
      undefined
    );
    expect(error.params).toContain(CANARY);
    expect(error.message).toContain(CANARY);
    expect(String(error.stack)).toContain(CANARY);
  });

  it('carries none of them after', () => {
    const error = new DrizzleQueryError(
      'insert into "users" ("email") values ($1)',
      [CANARY],
      undefined
    );
    const sanitized = sanitizeQueryError(error) as DrizzleQueryError;
    const everything = JSON.stringify(
      sanitized,
      Object.getOwnPropertyNames(sanitized).concat(['message', 'stack'])
    );
    expect(everything).not.toContain(CANARY);
    expect(String(sanitized.stack)).not.toContain(CANARY);
  });
});

describe('the paths that reach the driver unmapped', () => {
  it('a sql template is refused, and nothing is sent', () => {
    h.statements.length = 0;
    expect(() =>
      h.db.all(sql`select * from users where token = ${new SensitiveString(CANARY, 'credential')}`)
    ).toThrow(DrizzleParameterRefusedError);
    expect(everythingSeen(h)).not.toContain(CANARY);
  });

  it('a placeholder fill is refused, and nothing is sent', () => {
    const prepared = h.db
      .select()
      .from(users)
      .where(eq(users.token, sql.placeholder('t')))
      .prepare();
    h.statements.length = 0;
    expect(() => prepared.all({ t: new SensitiveString(CANARY, 'credential') })).toThrow(
      DrizzleParameterRefusedError
    );
    expect(everythingSeen(h)).not.toContain(CANARY);
  });

  it('the refusal message never quotes the value', () => {
    try {
      h.db.all(sql`select * from users where token = ${new SensitiveString(CANARY, 'credential')}`);
      expect.unreachable('should have refused');
    } catch (error) {
      expect(String((error as Error).message)).not.toContain(CANARY);
      expect(String((error as Error).stack)).not.toContain(CANARY);
    }
  });
});

describe('a misconfigured deployment fails rather than quietly storing plaintext', () => {
  it('a database built without the guard is refused at check time', () => {
    const sqlite = new Database(':memory:');
    const db = drizzle(sqlite, { schema });
    expect(() => checkSchema(db, schema)).toThrow(/sensitiveLogger/);
    sqlite.close();
  });

  it('the guarded database this suite runs on passes', () => {
    expect(() => checkSchema(h.db, schema)).not.toThrow();
  });
});

describe('hydrateRawRows', () => {
  it('puts the canary back behind a SensitiveString after a raw read', () => {
    const rows = h.db.all<{ id: number; token: string }>(sql`select id, token from users`);
    expect(JSON.stringify(rows)).toContain(CANARY);
    const hydrated = hydrateRawRows(rows, users);
    expect(JSON.stringify(hydrated)).not.toContain(CANARY);
    expect(hydrated[0]?.['token']).toBeInstanceOf(SensitiveString);
  });
});
