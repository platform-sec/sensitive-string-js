import { SensitiveString, withRevealContext } from '@platform-sec/sensitive-string-core';
import type { AuditContext } from '@platform-sec/sensitive-string-core';
import { eq, inArray, like, sql } from 'drizzle-orm';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { DrizzleParameterRefusedError } from '../errors.js';
import { CANARY, harness, posts, users } from './fixtures.js';
import type { Harness } from './fixtures.js';

/**
 * Which Drizzle operations route a value through the column, measured against
 * `drizzle-orm` 0.45.2 and `better-sqlite3` on a real database.
 *
 * The point of the suite is the two halves together. The first says the hook
 * covers far more than TypeORM's `ValueTransformer` does, which is what makes
 * this integration worth having; the second says exactly where it stops, and
 * every one of those is a case the guard has to catch instead. A release that
 * silently gained coverage would fail the second half, which is the direction
 * that matters: it would mean the guard's job had changed.
 */

let h: Harness;
const ss = (value: string): SensitiveString<'sensitive'> => new SensitiveString(value, 'sensitive');
const cred = (value: string): SensitiveString<'credential'> =>
  new SensitiveString(value, 'credential');

beforeEach(() => {
  h = harness();
  h.db
    .insert(users)
    .values({ name: 'A', email: ss('a@example.com'), token: cred(CANARY) })
    .run();
});

afterEach(() => {
  h.close();
});

/** The parameters the driver was actually handed for the last statement. */
const lastDriverParams = (): unknown[] => h.statements.at(-1)?.[1] ?? [];

describe('paths the column covers', () => {
  it('insert reveals each classified value exactly once', () => {
    h.statements.length = 0;
    h.db
      .insert(users)
      .values({ name: 'B', email: ss('b@example.com') })
      .run();
    expect(lastDriverParams()).toContain('b@example.com');
  });

  it('insert of many rows reveals each row', () => {
    h.statements.length = 0;
    h.db
      .insert(users)
      .values([
        { name: 'C', email: ss('c@example.com') },
        { name: 'D', email: ss('d@example.com') },
      ])
      .run();
    expect(lastDriverParams()).toContain('c@example.com');
    expect(lastDriverParams()).toContain('d@example.com');
  });

  it('select wraps every classified column', () => {
    const [row] = h.db.select().from(users).all();
    expect(row?.email).toBeInstanceOf(SensitiveString);
    expect(row?.token).toBeInstanceOf(SensitiveString);
    expect(row?.name).toBe('A');
    expect(typeof row?.id).toBe('number');
  });

  it('a partial select wraps too', () => {
    const [row] = h.db.select({ e: users.email }).from(users).all();
    expect(row?.e).toBeInstanceOf(SensitiveString);
  });

  it('a null column stays null rather than being wrapped', () => {
    h.db
      .insert(users)
      .values({ name: 'N', email: ss('n@example.com'), token: null })
      .run();
    const row = h.db.select().from(users).where(eq(users.name, 'N')).get();
    expect(row?.token).toBeNull();
  });

  it('an eq predicate reveals through the column', () => {
    const rows = h.db
      .select()
      .from(users)
      .where(eq(users.email, ss('a@example.com')))
      .all();
    expect(rows).toHaveLength(1);
  });

  it('an inArray predicate reveals each element', () => {
    const rows = h.db
      .select()
      .from(users)
      .where(inArray(users.email, [ss('a@example.com'), ss('nobody@example.com')]))
      .all();
    expect(rows).toHaveLength(1);
  });

  it('a plain string in a predicate still works, which is why strictWrites is off', () => {
    // A cast, because `eq` takes the column's data type and that type is a
    // SensitiveString. The runtime accepts it: the literal goes through the
    // same mapping, which passes a plain string through.
    const literal = 'a@example.com' as unknown as SensitiveString<'sensitive'>;
    expect(h.db.select().from(users).where(eq(users.email, literal)).all()).toHaveLength(1);
  });

  it('a like pattern is bound without the column mapping, and the guard covers it', () => {
    // `like` wants a string pattern and a string column, so a classified column
    // needs the cast in the other direction. Measured on 0.45.2, the pattern
    // does not go through mapToDriverValue at all: a plain pattern is fine, and
    // an instance used as one would reach the driver, which is the guard's job.
    const column = users.email as never;
    expect(h.db.select().from(users).where(like(column, '%example.com')).all()).toHaveLength(1);
    expect(() =>
      h.db
        .select()
        .from(users)
        .where(like(column, ss('%example.com') as never))
        .all()
    ).toThrow(DrizzleParameterRefusedError);
  });

  it('update reveals what it sets', () => {
    h.db
      .update(users)
      .set({ email: ss('a2@example.com') })
      .where(eq(users.id, 1))
      .run();
    const row = h.db.select().from(users).where(eq(users.id, 1)).get();
    expect(row?.email.reveal({ name: 't' })).toBe('a2@example.com');
  });

  it('delete reveals its predicate', () => {
    h.db
      .delete(users)
      .where(eq(users.email, ss('a@example.com')))
      .run();
    expect(h.db.select().from(users).all()).toHaveLength(0);
  });

  it('returning wraps what comes back', () => {
    const [row] = h.db
      .insert(users)
      .values({ name: 'R', email: ss('r@example.com') })
      .returning()
      .all();
    expect(row?.email).toBeInstanceOf(SensitiveString);
  });

  it('the relational query builder wraps a nested row', () => {
    h.db
      .insert(posts)
      .values({ authorId: 1, body: ss('a secret post') })
      .run();
    const [post] = h.db.query.posts.findMany({ with: { author: true } }).sync();
    expect(post?.body).toBeInstanceOf(SensitiveString);
    expect(post?.author?.email).toBeInstanceOf(SensitiveString);
    expect(post?.author?.token).toBeInstanceOf(SensitiveString);
  });

  it('the relational query builder wraps a column subset', () => {
    const row = h.db.query.users.findFirst({ columns: { email: true } }).sync();
    expect(row?.email).toBeInstanceOf(SensitiveString);
  });

  it('a subquery select wraps', () => {
    const sub = h.db.select().from(users).as('sub');
    const [row] = h.db.select().from(sub).all();
    expect(row?.email).toBeInstanceOf(SensitiveString);
  });

  it('a transaction reveals and wraps as usual', () => {
    h.db.transaction((tx) => {
      tx.insert(users)
        .values({ name: 'T', email: ss('t@example.com') })
        .run();
    });
    const row = h.db.select().from(users).where(eq(users.name, 'T')).get();
    expect(row?.email).toBeInstanceOf(SensitiveString);
  });

  it('a prepared statement whose values were bound at build time reveals', () => {
    const prepared = h.db
      .insert(users)
      .values({ name: 'P', email: ss('p@example.com') })
      .prepare();
    prepared.run();
    expect(h.db.select().from(users).where(eq(users.name, 'P')).all()).toHaveLength(1);
  });

  it('sql.param binds a value to a column, which is the audited raw escape hatch', () => {
    const rows = h.db.all(
      sql`select * from users where email = ${sql.param(ss('a@example.com'), users.email)}`
    );
    expect(rows).toHaveLength(1);
  });
});

describe('paths the column does not cover, which the guard refuses instead', () => {
  it('a value interpolated into a sql template', () => {
    expect(() => h.db.all(sql`select * from users where email = ${ss('a@example.com')}`)).toThrow(
      DrizzleParameterRefusedError
    );
  });

  it("a prepared statement's placeholder, the form Drizzle recommends for hot queries", () => {
    const prepared = h.db
      .select()
      .from(users)
      .where(eq(users.email, sql.placeholder('e')))
      .prepare();
    expect(() => prepared.all({ e: ss('a@example.com') })).toThrow(DrizzleParameterRefusedError);
  });

  it('an instance passed for a column that is not classified', () => {
    expect(() =>
      h.db
        .select()
        .from(users)
        .where(eq(users.name, ss('A') as never))
        .all()
    ).toThrow(DrizzleParameterRefusedError);
  });

  it('the refusal happens before the driver sees anything', () => {
    h.statements.length = 0;
    expect(() => h.db.all(sql`select * from users where email = ${ss('a@example.com')}`)).toThrow(
      DrizzleParameterRefusedError
    );
    expect(h.statements).toHaveLength(0);
  });

  it('a sql selection reads back plain, which hydrateRawRows is the answer to', () => {
    const [row] = h.db
      .select({ e: sql<string>`${users.email}` })
      .from(users)
      .all();
    expect(row?.e).toBe('a@example.com');
    expect(row?.e).not.toBeInstanceOf(SensitiveString);
  });

  it('.values() returns the driver arrays untouched', () => {
    const rows = h.db.select().from(users).values();
    expect(rows[0]?.some((v) => v instanceof SensitiveString)).toBe(false);
  });
});

describe('the reveal context', () => {
  it('reaches the column from an ambient withRevealContext', async () => {
    const seen: (AuditContext | undefined)[] = [];
    await withRevealContext(
      { name: 'req-42', auditReveal: (_v, _d, ctx) => seen.push(ctx) },
      async () => {
        await h.db.insert(users).values({ name: 'X', email: ss('x@example.com') });
      }
    );
    expect(seen.map((c) => c?.name)).toEqual(['req-42']);
    expect(seen[0]?.tags).toMatchObject({ table: 'users', column: 'email', sink: 'drizzle' });
  });

  it('reaches it inside a transaction, which is what a per-request context needs', () => {
    const seen: string[] = [];
    withRevealContext(
      { name: 'tx-req', auditReveal: (_v, _d, ctx) => seen.push(String(ctx?.name)) },
      () => {
        h.db.transaction((tx) => {
          tx.insert(users)
            .values({ name: 'Y', email: ss('y@example.com') })
            .run();
        });
      }
    );
    expect(seen).toEqual(['tx-req']);
  });

  it('is taken at execution rather than at description, so a deferred query is audited late', async () => {
    // Drizzle builds a statement's parameters lazily. The design document
    // assumed the opposite and proposed a second AsyncLocalStorage for write
    // context; this is the measurement that made it unnecessary.
    const query = h.db.insert(users).values({ name: 'Z', email: ss('z@example.com') });
    const seen: string[] = [];
    await withRevealContext(
      { name: 'late', auditReveal: (_v, _d, ctx) => seen.push(String(ctx?.name)) },
      async () => {
        await query;
      }
    );
    expect(seen).toEqual(['late']);
  });

  it('costs exactly one reveal per classified value per statement', async () => {
    let reveals = 0;
    await withRevealContext({ name: 'count', auditReveal: () => (reveals += 1) }, async () => {
      await h.db
        .insert(users)
        .values({ name: 'C1', email: ss('c1@example.com'), token: cred('T1') });
    });
    expect(reveals).toBe(2);
  });
});
