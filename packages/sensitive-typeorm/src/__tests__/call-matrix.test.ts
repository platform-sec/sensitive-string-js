import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { In, IsNull, Like, Not, Raw } from 'typeorm';
import type { DataSource } from 'typeorm';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { sensitiveColumn } from '../transformer.js';
import type { SensitiveTransformer } from '../types.js';
import { CANARY, makeDataSource, rawRows, testSchema } from './fixtures.js';

/**
 * Section 2.1 of the design as a table-driven test.
 *
 * This is a regression test on TypeORM rather than on this package: it asserts
 * the exact number of `to()` and `from()` calls, and the exact kind of argument
 * each received, for every operation the design measured. It is the test that
 * fires the day an upgrade moves a call site, and three of its rows are the
 * reason the package has a parameter guard at all.
 */

interface Call {
  readonly direction: 'to' | 'from';
  readonly column: string;
  readonly kind: string;
}

const calls: Call[] = [];

function kindOf(value: unknown): string {
  if (value === null) return 'null';
  if (value === undefined) return 'undefined';
  if (value instanceof SensitiveString) return 'SensitiveString';
  return typeof value;
}

/** A recording transformer that still behaves exactly like the real one. */
function recording(inner: SensitiveTransformer, column: string): SensitiveTransformer {
  const wrapper: SensitiveTransformer = {
    ...inner,
    to(value: unknown) {
      calls.push({ direction: 'to', column, kind: kindOf(value) });
      return inner.to(value);
    },
    from(value: unknown) {
      calls.push({ direction: 'from', column, kind: kindOf(value) });
      return inner.from(value);
    },
  };
  return wrapper;
}

function count(direction: 'to' | 'from', column: string): number {
  return calls.filter((c) => c.direction === direction && c.column === column).length;
}

function kinds(direction: 'to' | 'from', column: string): string[] {
  return calls.filter((c) => c.direction === direction && c.column === column).map((c) => c.kind);
}

describe('the transformer call matrix', () => {
  let ds: DataSource;
  const ss = (value: string) => new SensitiveString(value, 'sensitive');
  const key = (value: string) => new SensitiveString(value, 'credential');

  beforeEach(async () => {
    const schema = testSchema();
    // The recording wrappers replace the schema's transformers on the same
    // columns, so the counts are of the real hook and not of a stand-in.
    const email = recording(
      sensitiveColumn('sensitive', { table: 'users', column: 'email' }),
      'email'
    );
    const apiKey = recording(
      sensitiveColumn('credential', { table: 'users', column: 'api_key' }),
      'api_key'
    );
    const patched: typeof schema = {
      ...schema,
      column(path: string) {
        if (path === 'users.email') return email;
        if (path === 'users.api_key') return apiKey;
        return schema.column(path);
      },
    };
    ds = await makeDataSource(patched);
    await ds.getRepository('User').save({ name: 'seed', email: ss(CANARY), apiKey: key('K1') });
    calls.length = 0;
  });

  afterEach(async () => {
    await ds.destroy();
    calls.length = 0;
  });

  it('insert() calls to() once per column and from() never', async () => {
    await ds.getRepository('User').insert({ name: 'i', email: ss('i@example.com'), apiKey: null });
    expect(kinds('to', 'email')).toEqual(['SensitiveString']);
    expect(kinds('to', 'api_key')).toEqual(['null']);
    expect(count('from', 'email')).toBe(0);
  });

  it('save() on a new entity calls to() once per column', async () => {
    await ds
      .getRepository('User')
      .save({ name: 'n', email: ss('n@example.com'), apiKey: key('K2') });
    expect(count('to', 'email')).toBe(1);
    expect(count('to', 'api_key')).toBe(1);
  });

  it('save() on an existing entity calls to() twice per column and writes nothing', async () => {
    const repo = ds.getRepository('User');
    const found = await repo.findOneByOrFail({ name: 'seed' });
    calls.length = 0;
    await repo.save(found);
    // Two reveals per column: one from ColumnMetadata.getEntityValue, which
    // applies the transformer unguarded, and one from
    // SubjectChangedColumnsComputer, which reveals purely to answer "did this
    // change" and then discards the answer.
    expect(count('to', 'email')).toBe(2);
    expect(count('to', 'api_key')).toBe(2);
  });

  it('update() calls to() once per patched column only', async () => {
    await ds.getRepository('User').update({ name: 'seed' }, { email: ss('u@example.com') });
    expect(count('to', 'email')).toBe(1);
    expect(count('to', 'api_key')).toBe(0);
  });

  it('upsert() passes undefined to to() for an omitted column', async () => {
    await ds
      .getRepository('User')
      .upsert([{ id: 1, name: 'seed', email: ss('up@example.com') }], ['id']);
    expect(kinds('to', 'api_key')).toEqual(['undefined']);
  });

  it('IsNull() passes undefined to to()', async () => {
    await ds.getRepository('User').find({ where: { apiKey: IsNull() } });
    expect(kinds('to', 'api_key')).toEqual(['undefined']);
  });

  it('In() calls to() once per operand', async () => {
    await ds.getRepository('User').find({ where: { email: In([ss('a@x'), ss('b@x')]) } });
    expect(count('to', 'email')).toBe(2);
  });

  it('Not() and Like() go through the same path', async () => {
    await ds.getRepository('User').find({ where: { email: Not(ss('a@x')) } });
    expect(count('to', 'email')).toBe(1);
    calls.length = 0;
    await ds.getRepository('User').find({ where: { email: Like(ss('%@x')) } });
    expect(count('to', 'email')).toBe(1);
  });

  it('Raw() binds nothing through the transformer', async () => {
    await ds.getRepository('User').find({
      where: { email: Raw((alias) => `${alias} LIKE '%example.com'`) },
    });
    expect(count('to', 'email')).toBe(0);
  });

  it('a query builder named parameter never reaches to()', async () => {
    // The finding the whole package turns on. `u.email = :e` is a SQL fragment
    // and `:e` is a name; nothing connects the name to a column, so there is no
    // ColumnMetadata to consult and the value goes to the driver as it is.
    await ds.createQueryBuilder('User', 'u').where('u.email = :e', { e: 'a@example.com' }).getOne();
    expect(count('to', 'email')).toBe(0);
  });

  it('the find-options form of the query builder does reach to()', async () => {
    await ds
      .createQueryBuilder('User', 'u')
      .where({ email: ss('a@example.com') })
      .getOne();
    expect(count('to', 'email')).toBe(1);
  });

  it('from() runs once per classified column per row, relations included', async () => {
    await ds
      .getRepository('Post')
      .save({ body: new SensitiveString('b', 'sensitive'), author: { id: 1 } });
    calls.length = 0;
    const rows = await ds.getRepository('User').find({ relations: { posts: true } });
    expect(rows).toHaveLength(1);
    expect(count('from', 'email')).toBe(1);
    expect(count('from', 'api_key')).toBe(1);
  });

  it('select omitting a classified column calls neither direction', async () => {
    await ds.getRepository('User').find({ select: { id: true, name: true } });
    expect(count('from', 'email')).toBe(0);
    expect(count('to', 'email')).toBe(0);
  });

  it('count() calls neither direction', async () => {
    await ds.getRepository('User').count();
    expect(calls).toHaveLength(0);
  });

  it('getRawMany() and ds.query() call neither direction', async () => {
    await ds.createQueryBuilder('User', 'u').select('u.email', 'email').getRawMany();
    await ds.query('SELECT email FROM users');
    expect(calls).toHaveLength(0);
  });

  it('softDelete() calls neither direction and leaves the plaintext in place', async () => {
    await ds.getRepository('User').softDelete(1);
    expect(count('to', 'email')).toBe(0);
    expect(count('from', 'email')).toBe(0);
    // A deletedAt column reads like a deletion to a compliance reviewer and is
    // not one. This package is the thing that claims to know where sensitive
    // data is, so it says so rather than implying erasure.
    const raw = await rawRows<{ email: string }>(ds, 'SELECT email FROM users WHERE id = 1');
    expect(raw[0]?.email).toBe(CANARY);
  });
});
