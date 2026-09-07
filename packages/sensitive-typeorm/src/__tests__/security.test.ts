import { SensitiveString, withRevealContext } from '@platform-sec/sensitive-string-core';
import { DataSource, EntitySchema, IsNull } from 'typeorm';
import { afterEach, describe, expect, it } from 'vitest';
import {
  TypeOrmCacheRefusedError,
  TypeOrmMarkerReadError,
  TypeOrmWriteRefusedError,
} from '../errors.js';
import { redactionMatchers } from '@platform-sec/sensitive-string-core';
import { defineSchema } from '../schema.js';
import { sensitiveColumn } from '../transformer.js';
import { CANARY, KEY_CANARY, makeDataSource, rawRows, testSchema } from './fixtures.js';

/** Every table in the database, so a sweep cannot miss one that was added later. */
async function tables(ds: DataSource): Promise<string[]> {
  const rows = await rawRows<{ name: string }>(
    ds,
    `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`
  );
  return rows.map((r) => r.name);
}

/** Every string cell of every table, read through a connection that does not wrap. */
async function allCells(
  ds: DataSource
): Promise<{ table: string; column: string; value: string }[]> {
  const cells: { table: string; column: string; value: string }[] = [];
  for (const table of await tables(ds)) {
    const rows = await rawRows(ds, `SELECT * FROM "${table}"`);
    for (const row of rows) {
      for (const [column, value] of Object.entries(row)) {
        if (typeof value === 'string') cells.push({ table, column, value });
      }
    }
  }
  return cells;
}

describe('the canary sweep', () => {
  let ds: DataSource;
  afterEach(async () => {
    if (ds.isInitialized) await ds.destroy();
  });

  it('puts the canary in the classified columns and nowhere else', async () => {
    ds = await makeDataSource(testSchema());
    await ds.getRepository('User').insert({
      name: 'sweep',
      email: new SensitiveString(CANARY, 'sensitive'),
      apiKey: new SensitiveString(KEY_CANARY, 'credential'),
    });

    // Read with raw SQL rather than through the repository, because this
    // package's own read path would wrap the answer and the sweep would be
    // asserting against itself.
    const cells = await allCells(ds);
    const holdingCanary = cells.filter((c) => c.value.includes(CANARY));
    const holdingKey = cells.filter((c) => c.value.includes(KEY_CANARY));

    expect(holdingCanary.map((c) => `${c.table}.${c.column}`)).toEqual(['users.email']);
    expect(holdingKey.map((c) => `${c.table}.${c.column}`)).toEqual(['users.api_key']);
  });

  it('finds no redaction marker anywhere after a write', async () => {
    // The inverted sweep. A marker in a column is data corruption rather than a
    // leak, and it fails later and further away than a leak does: the value is
    // already gone by the time anything notices.
    ds = await makeDataSource(testSchema());
    await ds.getRepository('User').insert({
      name: 'inverted',
      email: new SensitiveString(CANARY, 'sensitive'),
      apiKey: new SensitiveString(KEY_CANARY, 'credential'),
    });

    const cells = await allCells(ds);
    for (const matcher of redactionMatchers()) {
      const holding = cells.filter((c) =>
        typeof matcher === 'string' ? c.value.includes(matcher) : c.value.search(matcher) !== -1
      );
      expect(holding).toEqual([]);
    }
  });

  it('leaks the canary when the same row is written through ds.query()', async () => {
    // The negative control for both sweeps above. A migration or a seed script
    // that writes with queryRunner.query() bypasses everything in this package,
    // and this asserts the sweep would notice.
    ds = await makeDataSource(testSchema());
    await ds.query('INSERT INTO users(name, email, api_key) VALUES (?, ?, ?)', [
      'raw',
      CANARY,
      KEY_CANARY,
    ]);
    const rows = await rawRows<{ email: string }>(ds, 'SELECT email FROM users');
    expect(rows[0]?.email).toBe(CANARY);
  });
});

describe('the reveal count', () => {
  let ds: DataSource;
  afterEach(async () => {
    if (ds.isInitialized) await ds.destroy();
  });

  /** Count reveals inside one unit of work, through the ambient audit hook. */
  async function reveals(fn: () => Promise<unknown>): Promise<number> {
    let count = 0;
    await withRevealContext({ name: 'counting', auditReveal: () => (count += 1) }, fn);
    return count;
  }

  it('is N for insert, one per patched column for update, and 2N + k for save', async () => {
    ds = await makeDataSource(testSchema());
    const repo = ds.getRepository('User');

    const inserted = await reveals(() =>
      repo.insert({
        name: 'counts',
        email: new SensitiveString('a@example.com', 'sensitive'),
        apiKey: new SensitiveString('K', 'credential'),
      })
    );
    expect(inserted).toBe(2);

    const updated = await reveals(() =>
      repo.update({ name: 'counts' }, { email: new SensitiveString('b@example.com', 'sensitive') })
    );
    expect(updated).toBe(1);

    const found = await repo.findOneByOrFail({ name: 'counts' });
    // N = 2 classified columns, k = 0 changed. Two reveals per column, and no
    // UPDATE is issued at all: the second reveal of each pair exists to answer
    // "did this change" and its result is compared and discarded.
    expect(await reveals(() => repo.save(found))).toBe(4);

    const changed = await repo.findOneByOrFail({ name: 'counts' });
    changed['email'] = new SensitiveString('c@example.com', 'sensitive');
    // k = 1.
    expect(await reveals(() => repo.save(changed))).toBe(5);
  });

  it('issues no UPDATE for a save() that changed nothing', async () => {
    const statements: string[] = [];
    ds = await makeDataSource(testSchema(), {
      logging: ['query'],
      logger: {
        logQuery: (q: string) => statements.push(q),
        logQueryError: () => undefined,
        logQuerySlow: () => undefined,
        logSchemaBuild: () => undefined,
        logMigration: () => undefined,
        log: () => undefined,
      },
    });
    const repo = ds.getRepository('User');
    await repo.insert({ name: 'noop', email: new SensitiveString('a@example.com', 'sensitive') });
    const found = await repo.findOneByOrFail({ name: 'noop' });
    statements.length = 0;
    await repo.save(found);
    expect(statements.filter((s) => s.startsWith('UPDATE'))).toEqual([]);
  });
});

describe('the undefined guard', () => {
  let ds: DataSource;
  afterEach(async () => {
    if (ds.isInitialized) await ds.destroy();
  });

  it('survives IsNull() and an upsert that omits a classified column', async () => {
    ds = await makeDataSource(testSchema());
    const repo = ds.getRepository('User');
    await repo.insert({ name: 'u', email: new SensitiveString('a@example.com', 'sensitive') });

    await expect(repo.find({ where: { apiKey: IsNull() } })).resolves.toHaveLength(1);
    await expect(
      repo.upsert(
        [{ id: 1, name: 'u', email: new SensitiveString('b@example.com', 'sensitive') }],
        ['id']
      )
    ).resolves.toBeDefined();
  });

  it('fails against a transformer that only guards null', () => {
    // The published sketch this package corrects. Kept as a test so the
    // one-character fix cannot silently regress: both paths above are ordinary
    // and both throw a TypeError from inside the ORM without it.
    const patternC = {
      to(value: unknown) {
        if (value === null) return null;
        return (value as SensitiveString<'sensitive'>).reveal({ name: 'x' });
      },
      from(value: unknown) {
        if (value === null) return null;
        return new SensitiveString(value as string, 'sensitive');
      },
    };
    expect(() => patternC.to(undefined)).toThrow(TypeError);
    expect(() => patternC.from(undefined)).toThrow(TypeError);
  });
});

describe('the marker refusals', () => {
  let ds: DataSource;
  afterEach(async () => {
    if (ds.isInitialized) await ds.destroy();
  });

  it('refuses a write of a string holding a marker', async () => {
    ds = await makeDataSource(testSchema());
    await expect(
      ds.getRepository('User').insert({ name: 'm', email: '[REDACTED:sensitive]' })
    ).rejects.toThrow(TypeOrmWriteRefusedError);
  });

  it('raises rather than returning a marker read back from a column', async () => {
    ds = await makeDataSource(testSchema());
    // Written the only way a marker gets into a column: a path that never saw
    // the transformer.
    await ds.query('INSERT INTO users(name, email) VALUES (?, ?)', ['m', '[REDACTED:sensitive]']);
    await expect(ds.getRepository('User').find()).rejects.toThrow(TypeOrmMarkerReadError);
  });
});

describe('the query result cache', () => {
  let ds: DataSource;
  afterEach(async () => {
    if (ds.isInitialized) await ds.destroy();
  });

  it('is refused when anything is classified', async () => {
    const schema = testSchema();
    ds = await makeDataSource(schema, { cache: true });
    expect(() => schema.check(ds)).toThrow(TypeOrmCacheRefusedError);
  });

  it('proceeds under the bypass, and then holds the plaintext', async () => {
    // The bypass documents its own consequence: this is what the deployment
    // that sets it is accepting, asserted rather than described.
    const schema = testSchema();
    ds = await makeDataSource(schema, { cache: true });
    expect(() => schema.check(ds, { allowCachedPlaintext: true })).not.toThrow();

    await ds.getRepository('User').insert({
      name: 'cached',
      email: new SensitiveString(CANARY, 'sensitive'),
    });
    await ds.getRepository('User').find({
      where: { email: new SensitiveString(CANARY, 'sensitive') },
      cache: true,
    });

    const rows = await rawRows<{ query: string; result: string }>(
      ds,
      'SELECT query, result FROM "query-result-cache"'
    );
    expect(rows.length).toBeGreaterThan(0);
    // Both halves: the rows, cached before the read transformer runs, and the
    // statement's bound parameters, which the cache uses as part of its key.
    expect(rows.some((r) => r.result.includes(CANARY))).toBe(true);
    expect(rows.some((r) => r.query.includes(CANARY))).toBe(true);
  });

  it('is allowed when nothing is classified', async () => {
    const schema = defineSchema({ fallback: 'plain' });
    const Plain = new EntitySchema({
      name: 'Plain',
      tableName: 'plain',
      columns: { id: { type: Number, primary: true, generated: true }, v: { type: String } },
    });
    ds = new DataSource({
      type: 'better-sqlite3',
      database: ':memory:',
      synchronize: true,
      entities: [Plain],
      cache: true,
    });
    await ds.initialize();
    expect(() => schema.check(ds)).not.toThrow();
  });
});

describe('DDL and composition', () => {
  let ds: DataSource;
  afterEach(async () => {
    if (ds.isInitialized) await ds.destroy();
  });

  it('generates the same DDL as an unclassified column and no pending migration', async () => {
    ds = await makeDataSource(testSchema());
    const withTransformer = await rawRows<{ sql: string }>(
      ds,
      `SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'users'`
    );

    const Plain = new EntitySchema({
      name: 'User',
      tableName: 'users',
      columns: {
        id: { type: Number, primary: true, generated: true },
        name: { type: String },
        email: { type: String },
        apiKey: { type: String, name: 'api_key', nullable: true },
        deletedAt: { type: Date, deleteDate: true, nullable: true },
      },
    });
    const plainDs = new DataSource({
      type: 'better-sqlite3',
      database: ':memory:',
      synchronize: true,
      entities: [Plain],
    });
    await plainDs.initialize();
    const without = await rawRows<{ sql: string }>(
      plainDs,
      `SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'users'`
    );

    expect(withTransformer[0]?.sql).toBe(without[0]?.sql);

    const pending = await ds.driver.createSchemaBuilder().log();
    expect(pending.upQueries).toEqual([]);
    await plainDs.destroy();
  });

  it('round-trips through a second transformer placed after this one', async () => {
    const schema = testSchema();
    const upper = { to: (v: unknown) => String(v).toUpperCase(), from: (v: unknown) => v };
    const Composed = new EntitySchema({
      name: 'Composed',
      tableName: 'composed',
      columns: {
        id: { type: Number, primary: true, generated: true },
        // Left to right on the way to the database, right to left on the way
        // back. So the reveal happens first going out and the wrap happens
        // last coming in, and an encryption transformer in the second position
        // never sees a SensitiveString.
        v: { type: String, transformer: [schema.column('users.email'), upper] },
      },
    });
    ds = new DataSource({
      type: 'better-sqlite3',
      database: ':memory:',
      synchronize: true,
      entities: [Composed],
    });
    await ds.initialize();
    await ds.getRepository('Composed').insert({ v: new SensitiveString('mixed', 'sensitive') });

    const stored = await rawRows<{ v: string }>(ds, 'SELECT v FROM composed');
    expect(stored[0]?.v).toBe('MIXED');

    const read = (await ds.getRepository('Composed').find()) as unknown as {
      v: SensitiveString<'sensitive'>;
    }[];
    expect(read[0]?.v).toBeInstanceOf(SensitiveString);
    expect(read[0]?.v.reveal({ name: 't' })).toBe('MIXED');
  });

  it('refuses a reversed array whose transform leaves the marker recognisable', async () => {
    // The order is load bearing. With this package second, the first
    // transformer sees the instance rather than a string, stringifies it
    // through toString(), and hands this package a redaction marker that has
    // already been through the other transform.
    //
    // Whether the write refusal catches that depends on what the other
    // transform did to it, and this case it does catch: uppercasing does not
    // touch `[REDACTED:`, and the detector matches on that prefix rather than
    // on the exact per-class marker. It did not catch it before the detector
    // moved to core, where two copies enumerated the registry and looked for
    // `[REDACTED:sensitive]` exactly, which uppercasing defeats.
    const schema = testSchema();
    const upper = { to: (v: unknown) => String(v).toUpperCase(), from: (v: unknown) => v };
    const Reversed = new EntitySchema({
      name: 'Reversed',
      tableName: 'reversed',
      columns: {
        id: { type: Number, primary: true, generated: true },
        v: { type: String, transformer: [upper, schema.column('users.email')] },
      },
    });
    ds = new DataSource({
      type: 'better-sqlite3',
      database: ':memory:',
      synchronize: true,
      entities: [Reversed],
    });
    await ds.initialize();

    await expect(
      ds.getRepository('Reversed').insert({ v: new SensitiveString('mixed', 'sensitive') })
    ).rejects.toThrow(TypeOrmWriteRefusedError);

    const stored = await rawRows<{ v: string }>(ds, 'SELECT v FROM reversed');
    expect(stored).toEqual([]);
  });

  it('stores a transformed marker when the reversed transform destroys it', async () => {
    // The half the refusal cannot reach, and the reason array order is the
    // defence rather than the guard. A transform that renders the marker
    // unrecognisable hands this package a string that matches nothing, and a
    // real encryption transformer is exactly that: ciphertext. The value is
    // already gone by then, so what lands in the column is an encoded
    // redaction rather than the secret, which is the failure this asserts
    // rather than a leak.
    const schema = testSchema();
    const b64 = {
      to: (v: unknown) => Buffer.from(String(v)).toString('base64'),
      from: (v: unknown) => v,
    };
    const Encoded = new EntitySchema({
      name: 'Encoded',
      tableName: 'encoded',
      columns: {
        id: { type: Number, primary: true, generated: true },
        v: { type: String, transformer: [b64, schema.column('users.email')] },
      },
    });
    ds = new DataSource({
      type: 'better-sqlite3',
      database: ':memory:',
      synchronize: true,
      entities: [Encoded],
    });
    await ds.initialize();
    await ds.getRepository('Encoded').insert({ v: new SensitiveString('mixed', 'sensitive') });

    const stored = await rawRows<{ v: string }>(ds, 'SELECT v FROM encoded');
    expect(stored[0]?.v).toBe(Buffer.from('[REDACTED:sensitive]').toString('base64'));
    expect(Buffer.from(stored[0]?.v ?? '', 'base64').toString()).not.toContain('mixed');
  });
});

describe('a standalone transformer', () => {
  it('carries the class through a write and a read with its label intact', async () => {
    const Standalone = new EntitySchema({
      name: 'Standalone',
      tableName: 'standalone',
      columns: {
        id: { type: Number, primary: true, generated: true },
        secret: {
          type: String,
          transformer: sensitiveColumn('credential', {
            table: 'vault',
            column: 'secret',
            label: 'vault-secret',
          }),
        },
      },
    });
    const ds = new DataSource({
      type: 'better-sqlite3',
      database: ':memory:',
      synchronize: true,
      entities: [Standalone],
    });
    await ds.initialize();
    await ds
      .getRepository('Standalone')
      .insert({ secret: new SensitiveString(KEY_CANARY, 'credential') });
    const rows = (await ds.getRepository('Standalone').find()) as unknown as {
      secret: SensitiveString<'credential'>;
    }[];
    expect(rows[0]?.secret.klass).toBe('credential');
    expect(rows[0]?.secret.label).toBe('vault-secret');
    expect(rows[0]?.secret.reveal({ name: 't' })).toBe(KEY_CANARY);
    expect(String(rows[0]?.secret)).not.toContain(KEY_CANARY);
    await ds.destroy();
  });
});
