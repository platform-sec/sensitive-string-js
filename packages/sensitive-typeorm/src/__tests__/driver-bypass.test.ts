import { SensitiveString } from '@platform-sec/sensitive-string-core';
import mysql from 'mysql2';
import pgUtils from 'pg/lib/utils.js';
import type { DataSource } from 'typeorm';
import { afterEach, describe, expect, it } from 'vitest';
import { CANARY, makeDataSource, testSchema } from './fixtures.js';

/**
 * What the three common drivers do with a `SensitiveString` that reached them.
 *
 * This is the evidence for `guardParameters()` existing at all, kept as a test
 * so that the day a driver changes its mind, this suite says so rather than the
 * package silently relying on a behaviour that moved. Only SQLite fails loudly;
 * on the two drivers TypeORM applications overwhelmingly run on, the query
 * executes and matches nothing.
 *
 * `pg` and `mysql2` are exercised through the functions that do the binding
 * rather than against running servers, so these establish what the driver does
 * with the value, not what a particular server version then stores.
 */
describe('what happens without the guard', () => {
  let ds: DataSource;
  const instance = new SensitiveString(CANARY, 'sensitive');
  /**
   * The instance as a bound parameter, which is how it reaches a driver.
   *
   * The cast is the finding rather than a convenience. `mysql2` types a bound
   * parameter as a scalar or a plain record and a `SensitiveString` is neither,
   * but a caller writing `.where('email = :e', { e: value })` never meets that
   * type: TypeORM's parameter map is an `ObjectLiteral`, so nothing between the
   * call site and the driver is in a position to object.
   */
  const asParameter: Record<string, unknown> = instance as unknown as Record<string, unknown>;

  afterEach(async () => {
    if (ds?.isInitialized) await ds.destroy();
  });

  it('better-sqlite3 refuses to bind the object', async () => {
    ds = await makeDataSource(testSchema());
    await expect(
      ds.createQueryBuilder('User', 'u').where('u.email = :e', { e: instance }).getOne()
    ).rejects.toThrow(/can only bind/i);
  });

  it('pg binds the redaction marker, with the quotes JSON.stringify added', () => {
    // prepareValue falls through to JSON.stringify for an object with no
    // toPostgres method, and toJSON returns the marker. The query then runs and
    // matches nothing, having bound a string with literal double quotes in it.
    const bound: unknown = pgUtils.prepareValue(instance);
    expect(bound).toBe('"[REDACTED:sensitive]"');
    expect(bound).not.toContain(CANARY);
  });

  it('mysql2 binds the redaction marker as a plain string', () => {
    const bound = mysql.format('SELECT ? ', [asParameter]);
    expect(bound).toContain('[REDACTED:sensitive]');
    expect(bound).not.toContain(CANARY);
  });

  it('mysql2 assigns the instance metadata to columns that do not exist', () => {
    // SensitiveString has exactly two own enumerable properties, so `SET ?`
    // with an instance produces syntactically valid SQL that assigns klass and
    // label. This is the shape that makes the failure quiet rather than loud.
    expect(Object.keys(instance)).toEqual(['klass', 'label']);
    const assignment = mysql.escape(asParameter);
    expect(assignment).toContain('`klass`');
    expect(assignment).toContain('`label`');
    expect(assignment).not.toContain(CANARY);
  });
});
