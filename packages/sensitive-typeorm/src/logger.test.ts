import { SensitiveString } from '@platform-sec/sensitive-string-core';
import type { DataSource } from 'typeorm';
import { afterEach, describe, expect, it } from 'vitest';
import { PARAMETER_CENSOR, sensitiveLogger } from './logger.js';
import type { LoggerLike } from './logger.js';
import { defineSchema } from './schema.js';
import { CANARY, makeDataSource, testSchema } from './__tests__/fixtures.js';

interface Recorded {
  readonly method: string;
  readonly query: string;
  readonly parameters: unknown[] | undefined;
}

function recorder(): { logger: LoggerLike; entries: Recorded[]; other: unknown[] } {
  const entries: Recorded[] = [];
  const other: unknown[] = [];
  const logger: LoggerLike = {
    logQuery: (query, parameters) => entries.push({ method: 'logQuery', query, parameters }),
    logQueryError: (_error, query, parameters) =>
      entries.push({ method: 'logQueryError', query, parameters }),
    logQuerySlow: (_time, query, parameters) =>
      entries.push({ method: 'logQuerySlow', query, parameters }),
    logSchemaBuild: (message) => other.push(message),
    logMigration: (message) => other.push(message),
    log: (level, message) => other.push([level, message]),
  };
  return { logger, entries, other };
}

describe('sensitiveLogger', () => {
  const schema = testSchema();

  it('redacts the string parameters of a statement touching a classified column', () => {
    const { logger, entries } = recorder();
    sensitiveLogger(logger, schema).logQuery('INSERT INTO "users"("name", "email") VALUES (?, ?)', [
      'ann',
      CANARY,
    ]);
    expect(entries[0]?.parameters).toEqual([PARAMETER_CENSOR, PARAMETER_CENSOR]);
  });

  it('keeps the non-string parameters, which are what make an entry useful', () => {
    // A classified column's revealed value is always a string, so the ids and
    // the timestamps survive and the one shape that could carry a secret does
    // not.
    const { logger, entries } = recorder();
    const when = new Date(0);
    sensitiveLogger(logger, schema).logQuery(
      'UPDATE "users" SET "email" = ? WHERE "id" = ? AND "created" < ?',
      [CANARY, 42, when]
    );
    expect(entries[0]?.parameters).toEqual([PARAMETER_CENSOR, 42, when]);
  });

  it('leaves a statement touching nothing classified alone', () => {
    const { logger, entries } = recorder();
    const wrapped = sensitiveLogger(logger, schema);
    wrapped.logQuery('SELECT "id", "name" FROM "users" WHERE "name" = ?', ['ann']);
    expect(entries[0]?.parameters).toEqual(['ann']);
  });

  it('matches a rule-classified column it cannot enumerate', () => {
    // Only the exact `fields` entries can be listed. A rule is a pattern with
    // no names behind it, so the rule half is answered the other way round:
    // every identifier in the statement is classified.
    const { logger, entries } = recorder();
    sensitiveLogger(logger, schema).logQuery('INSERT INTO "posts"("body") VALUES (?)', [CANARY]);
    expect(entries[0]?.parameters).toEqual([PARAMETER_CENSOR]);
  });

  it('matches backtick and bracket quoting as well as double quotes', () => {
    const { logger, entries } = recorder();
    const wrapped = sensitiveLogger(logger, schema);
    wrapped.logQuery('INSERT INTO `users`(`email`) VALUES (?)', [CANARY]);
    wrapped.logQuery('INSERT INTO [users]([email]) VALUES (?)', [CANARY]);
    expect(entries[0]?.parameters).toEqual([PARAMETER_CENSOR]);
    expect(entries[1]?.parameters).toEqual([PARAMETER_CENSOR]);
  });

  it('redacts an instance and a marker whatever the statement says', () => {
    // An instance among the parameters means the transformer never ran, which
    // is the query builder bypass; a marker means a column is already corrupt.
    // Neither should reach a log looking ordinary.
    const { logger, entries } = recorder();
    sensitiveLogger(logger, schema).logQuery('SELECT * FROM "unrelated" WHERE a = ? AND b = ?', [
      new SensitiveString(CANARY, 'sensitive'),
      '[REDACTED:credential]',
    ]);
    expect(entries[0]?.parameters).toEqual([PARAMETER_CENSOR, PARAMETER_CENSOR]);
  });

  it('gives logQueryError and logQuerySlow the same treatment', () => {
    const { logger, entries } = recorder();
    const wrapped = sensitiveLogger(logger, schema);
    wrapped.logQueryError(new Error('boom'), 'INSERT INTO "users"("email") VALUES (?)', [CANARY]);
    wrapped.logQuerySlow(1000, 'INSERT INTO "users"("email") VALUES (?)', [CANARY]);
    expect(entries[0]?.parameters).toEqual([PARAMETER_CENSOR]);
    expect(entries[1]?.parameters).toEqual([PARAMETER_CENSOR]);
  });

  it('delegates the three methods that carry no parameters', () => {
    const { logger, other } = recorder();
    const wrapped = sensitiveLogger(logger, schema);
    wrapped.logSchemaBuild('build');
    wrapped.logMigration('migrate');
    wrapped.log('warn', 'careful');
    expect(other).toEqual(['build', 'migrate', ['warn', 'careful']]);
  });

  it('redacts a named parameter map as well as an array', () => {
    // `DataSource.query(sql, { e: value })` reaches the logger as that object.
    // TypeORM's own Logger types the argument as an array, which is what makes
    // this shape easy to miss.
    const { logger, entries } = recorder();
    sensitiveLogger(logger, schema).logQuery('SELECT * FROM "users" WHERE "email" = :e', {
      id: 7,
      e: CANARY,
    } as unknown as unknown[]);
    expect(entries[0]?.parameters).toEqual({ id: 7, e: PARAMETER_CENSOR });
  });

  it('leaves a named parameter map alone when nothing is classified', () => {
    const { logger, entries } = recorder();
    sensitiveLogger(logger, schema).logQuery('SELECT * FROM "users" WHERE "name" = :n', {
      n: 'ann',
    } as unknown as unknown[]);
    expect(entries[0]?.parameters).toEqual({ n: 'ann' });
  });

  it('returns the same array when nothing changed', () => {
    const { logger, entries } = recorder();
    const parameters = ['ann'];
    sensitiveLogger(logger, schema).logQuery('SELECT "name" FROM "users"', parameters);
    expect(entries[0]?.parameters).toBe(parameters);
  });

  it('touches nothing for a schema that classifies nothing', () => {
    const { logger, entries } = recorder();
    const empty = defineSchema({ fallback: 'plain' });
    sensitiveLogger(logger, empty).logQuery('INSERT INTO "users"("email") VALUES (?)', [CANARY]);
    expect(entries[0]?.parameters).toEqual([CANARY]);
  });
});

describe('sensitiveLogger against a live DataSource', () => {
  let ds: DataSource;
  afterEach(async () => {
    if (ds?.isInitialized) await ds.destroy();
  });

  it('keeps the canary out of the log a getting-started template would produce', async () => {
    const schema = testSchema();
    const { logger, entries } = recorder();
    ds = await makeDataSource(schema, {
      logging: ['query'],
      logger: sensitiveLogger(logger, schema),
    });
    await ds
      .getRepository('User')
      .insert({ name: 'logged', email: new SensitiveString(CANARY, 'sensitive') });

    const printed = JSON.stringify(entries);
    expect(printed).toContain('INSERT INTO');
    expect(printed).not.toContain(CANARY);
  });

  it('proves the same log holds the canary without the wrapper', async () => {
    const { logger, entries } = recorder();
    ds = await makeDataSource(testSchema(), { logging: ['query'], logger });
    await ds
      .getRepository('User')
      .insert({ name: 'logged', email: new SensitiveString(CANARY, 'sensitive') });
    expect(JSON.stringify(entries)).toContain(CANARY);
  });
});
