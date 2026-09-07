import { SensitiveString } from '@platform-sec/sensitive-string-core';
import type { DataSource } from 'typeorm';
import { afterEach, describe, expect, it } from 'vitest';
import { TypeOrmParameterRefusedError } from './errors.js';
import { assertParametersSafe, guardParameters } from './guard.js';
import { CANARY, makeDataSource, testSchema } from './__tests__/fixtures.js';

describe('assertParametersSafe', () => {
  const statement = 'SELECT 1';

  it('passes ordinary parameters', () => {
    expect(() =>
      assertParametersSafe(statement, ['a', 1, null, undefined, new Date()])
    ).not.toThrow();
  });

  it('refuses a SensitiveString instance and names its position', () => {
    try {
      assertParametersSafe(statement, ['a', new SensitiveString(CANARY, 'sensitive')]);
      expect.unreachable('should have refused');
    } catch (error) {
      expect(error).toBeInstanceOf(TypeOrmParameterRefusedError);
      const refusal = error as TypeOrmParameterRefusedError;
      expect(refusal.parameter).toBe('1');
      expect(refusal.kind).toBe('instance');
      expect(refusal.message).not.toContain(CANARY);
    }
  });

  it('refuses a string holding a redaction marker', () => {
    expect(() => assertParametersSafe(statement, ['[REDACTED:credential]'])).toThrow(
      TypeOrmParameterRefusedError
    );
  });

  it('finds an instance nested in an array or a plain object', () => {
    const instance = new SensitiveString(CANARY, 'sensitive');
    expect(() => assertParametersSafe(statement, [[1, instance]])).toThrow(
      TypeOrmParameterRefusedError
    );
    expect(() => assertParametersSafe(statement, [{ a: { b: instance } }])).toThrow(
      TypeOrmParameterRefusedError
    );
  });

  it('does not walk into a class instance or a buffer', () => {
    // A Date, a Buffer and a driver's own wrapper hold no SensitiveString, and
    // walking a Buffer's indices would cost more than the statement it is about
    // to be bound to.
    expect(() =>
      assertParametersSafe(statement, [Buffer.from('x'), new Date(), /re/])
    ).not.toThrow();
  });

  it('survives a cycle', () => {
    const cyclic: Record<string, unknown> = {};
    cyclic['self'] = cyclic;
    expect(() => assertParametersSafe(statement, [cyclic])).not.toThrow();
  });

  it('truncates the statement it quotes and never quotes a parameter', () => {
    const long = `SELECT ${'x'.repeat(400)}`;
    try {
      assertParametersSafe(long, [new SensitiveString(CANARY, 'sensitive')]);
      expect.unreachable('should have refused');
    } catch (error) {
      const message = (error as Error).message;
      expect(message).toContain('...');
      expect(message).not.toContain(CANARY);
      expect(message.length).toBeLessThan(1000);
    }
  });

  it('ignores a parameter list that is neither an array nor a map', () => {
    expect(() => assertParametersSafe(statement, undefined)).not.toThrow();
    expect(() => assertParametersSafe(statement, 'not a list')).not.toThrow();
    expect(() => assertParametersSafe(statement, new Date())).not.toThrow();
  });

  it('checks a named parameter map, not just an array', () => {
    // `DataSource.query(sql, { e: value })` hands the runner that object
    // unchanged, so a check that only understood arrays would let every value
    // in it through. `better-sqlite3` rejects named placeholders, which makes
    // this one more hole the driver you develop against does not show you.
    try {
      assertParametersSafe(statement, { id: 1, e: new SensitiveString(CANARY, 'sensitive') });
      expect.unreachable('should have refused');
    } catch (error) {
      expect(error).toBeInstanceOf(TypeOrmParameterRefusedError);
      const refusal = error as TypeOrmParameterRefusedError;
      expect(refusal.parameter).toBe('e');
      expect(refusal.message).not.toContain(CANARY);
    }
    expect(() => assertParametersSafe(statement, { e: '[REDACTED:sensitive]' })).toThrow(
      TypeOrmParameterRefusedError
    );
    expect(() => assertParametersSafe(statement, { id: 1, name: 'ann' })).not.toThrow();
  });
});

describe('guardParameters', () => {
  let ds: DataSource;
  afterEach(async () => {
    if (ds.isInitialized) await ds.destroy();
  });

  it('refuses a SensitiveString bound through a query builder parameter', async () => {
    ds = await makeDataSource(testSchema());
    guardParameters(ds);

    await expect(
      ds
        .createQueryBuilder('User', 'u')
        .where('u.email = :e', { e: new SensitiveString(CANARY, 'sensitive') })
        .getOne()
    ).rejects.toThrow(TypeOrmParameterRefusedError);
  });

  it('names the find-options form as the fix', async () => {
    ds = await makeDataSource(testSchema());
    guardParameters(ds);
    try {
      await ds
        .createQueryBuilder('User', 'u')
        .where('u.email = :e', { e: new SensitiveString(CANARY, 'sensitive') })
        .getOne();
      expect.unreachable('should have refused');
    } catch (error) {
      expect((error as Error).message).toContain('.where({ email: value })');
    }
  });

  it('lets the same query through in the find-options form', async () => {
    ds = await makeDataSource(testSchema());
    await ds.getRepository('User').insert({
      name: 'guarded',
      email: new SensitiveString(CANARY, 'sensitive'),
    });
    guardParameters(ds);

    const found = await ds
      .createQueryBuilder('User', 'u')
      .where({ email: new SensitiveString(CANARY, 'sensitive') })
      .getOne();
    expect(found).not.toBeNull();
  });

  it('covers ds.query() and a transaction manager', async () => {
    ds = await makeDataSource(testSchema());
    guardParameters(ds);

    await expect(
      ds.query('SELECT * FROM users WHERE email = ?', [new SensitiveString(CANARY, 'sensitive')])
    ).rejects.toThrow(TypeOrmParameterRefusedError);

    await expect(
      ds.transaction(async (manager) => {
        await manager.query<unknown[]>('SELECT * FROM users WHERE email = ?', [
          new SensitiveString(CANARY, 'sensitive'),
        ]);
      })
    ).rejects.toThrow(TypeOrmParameterRefusedError);
  });

  it('is idempotent, so the cached SQLite runner is not wrapped twice', async () => {
    // The SQLite family caches one query runner and returns it from every
    // createQueryRunner() call, so a wrapper that did not check would layer
    // itself once per call. Installing twice and running many queries is what
    // that failure looks like from the outside.
    ds = await makeDataSource(testSchema());
    guardParameters(ds);
    guardParameters(ds);
    for (let i = 0; i < 50; i += 1) await ds.query('SELECT 1');
    await expect(
      ds.query('SELECT 1 WHERE ? = 1', [new SensitiveString(CANARY, 'sensitive')])
    ).rejects.toThrow(TypeOrmParameterRefusedError);
  });

  it('mutates no prototype and no DataSource option', async () => {
    ds = await makeDataSource(testSchema());
    const prototype = Object.getPrototypeOf(ds) as object;
    const prototypeBefore = Object.getOwnPropertyNames(prototype).sort().join(',');
    const optionsBefore = JSON.stringify(ds.options);
    const createBefore = (prototype as { createQueryRunner: unknown }).createQueryRunner;

    const uninstall = guardParameters(ds);

    expect(Object.getOwnPropertyNames(prototype).sort().join(',')).toBe(prototypeBefore);
    expect((prototype as { createQueryRunner: unknown }).createQueryRunner).toBe(createBefore);
    expect(JSON.stringify(ds.options)).toBe(optionsBefore);
    uninstall();
  });

  it('refuses a named parameter map handed to ds.query()', async () => {
    ds = await makeDataSource(testSchema());
    guardParameters(ds);
    await expect(
      ds.query('SELECT * FROM users WHERE email = :e', {
        e: new SensitiveString(CANARY, 'sensitive'),
      })
    ).rejects.toThrow(TypeOrmParameterRefusedError);
  });

  it('wraps every fresh runner, and one uninstall silences all of them', () => {
    // A `pg`-shaped DataSource: a new query runner per call, rather than the
    // single cached one the SQLite drivers hand back. This is the arm where
    // retaining a restorer per runner would keep every query runner the process
    // ever made alive, so the uninstall stops the checking through a shared
    // flag instead of by restoring each one.
    const fake = {
      createQueryRunner: () => ({ query: (_sql: string, _parameters?: unknown) => 'ran' }),
    };

    const uninstall = guardParameters(fake);
    const made = Array.from({ length: 5 }, () => fake.createQueryRunner());
    expect(new Set(made).size).toBe(5);

    for (const runner of made) {
      expect(() => runner.query('SELECT ?', [new SensitiveString(CANARY, 'sensitive')])).toThrow(
        TypeOrmParameterRefusedError
      );
    }

    uninstall();

    // Every one of them, including the first, which was created long before.
    for (const runner of made) {
      expect(runner.query('SELECT ?', [new SensitiveString(CANARY, 'sensitive')])).toBe('ran');
    }
  });

  it('resumes checking when a second guard is installed after an uninstall', async () => {
    // The runner the SQLite drivers cache is already wrapped, so a second
    // install has to reactivate that wrapper rather than add another one.
    ds = await makeDataSource(testSchema());
    const uninstall = guardParameters(ds);
    await ds.query('SELECT 1');
    uninstall();

    guardParameters(ds);
    await expect(
      ds.query('SELECT 1 WHERE ? = 1', [new SensitiveString(CANARY, 'sensitive')])
    ).rejects.toThrow(TypeOrmParameterRefusedError);
  });

  it('stops checking after the uninstall, on runners it already handed out', async () => {
    ds = await makeDataSource(testSchema());
    const uninstall = guardParameters(ds);
    // Force the cached runner into existence while the guard is installed.
    await ds.query('SELECT 1');
    uninstall();

    // No refusal: the wrapper is off the DataSource and off the runner it had
    // already wrapped, which on SQLite is the only runner there is.
    await expect(ds.query('SELECT ? ', ['[REDACTED:sensitive]'])).resolves.toBeDefined();
  });
});
