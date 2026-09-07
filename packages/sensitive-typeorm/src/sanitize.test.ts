import { inspect } from 'node:util';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { QueryFailedError } from 'typeorm';
import type { DataSource } from 'typeorm';
import { afterEach, describe, expect, it } from 'vitest';
import { ERROR_PARAMETER_CENSOR, sanitizeQueryFailedError } from './sanitize.js';
import { CANARY, makeDataSource, testSchema } from './__tests__/fixtures.js';

/** Provoke a real unique-constraint violation with the canary in the parameters. */
async function provoke(ds: DataSource): Promise<unknown> {
  await ds.query('CREATE UNIQUE INDEX users_email_uq ON users(email)');
  await ds
    .getRepository('User')
    .insert({ name: 'a', email: new SensitiveString(CANARY, 'sensitive') });
  try {
    await ds
      .getRepository('User')
      .insert({ name: 'b', email: new SensitiveString(CANARY, 'sensitive') });
  } catch (error) {
    return error;
  }
  throw new Error('the insert was expected to fail');
}

describe('sanitizeQueryFailedError', () => {
  let ds: DataSource;
  afterEach(async () => {
    if (ds?.isInitialized) await ds.destroy();
  });

  it('removes the canary from a real QueryFailedError and keeps the error usable', async () => {
    ds = await makeDataSource(testSchema());
    const raw = await provoke(ds);

    // The measurement the fix exists for, asserted first: without the
    // sanitizer the plaintext is on an own enumerable property, which is
    // exactly what an error tracker serialises.
    expect(inspect(raw)).toContain(CANARY);
    expect(Object.keys(raw as object)).toContain('parameters');

    const safe = sanitizeQueryFailedError(raw);

    expect(inspect(safe)).not.toContain(CANARY);
    expect(JSON.stringify(safe, Object.getOwnPropertyNames(safe as object))).not.toContain(CANARY);
    expect((safe as { stack?: string }).stack ?? '').not.toContain(CANARY);
    expect(safe).toBeInstanceOf(QueryFailedError);
    expect(safe).toBeInstanceOf(Error);
    expect((safe as Error).name).toBe('QueryFailedError');
    expect((safe as Error).message).toBe((raw as Error).message);
    expect((safe as { parameters: unknown[] }).parameters).toEqual([
      ERROR_PARAMETER_CENSOR,
      ERROR_PARAMETER_CENSOR,
    ]);
  });

  it('leaves an error that is not a query failure alone', () => {
    const other = new TypeError('unrelated');
    expect(sanitizeQueryFailedError(other)).toBe(other);
  });

  it('returns non-objects unchanged', () => {
    expect(sanitizeQueryFailedError(undefined)).toBeUndefined();
    expect(sanitizeQueryFailedError('a string')).toBe('a string');
    expect(sanitizeQueryFailedError(null)).toBeNull();
  });

  it('survives a frozen error by copying it, prototype and all', () => {
    const error = new QueryFailedError('SELECT ?', [CANARY], new Error('driver'));
    Object.freeze(error);
    const safe = sanitizeQueryFailedError(error);
    expect(safe).toBeInstanceOf(QueryFailedError);
    expect(inspect(safe)).not.toContain(CANARY);
    expect((safe as { parameters: unknown[] }).parameters).toEqual([ERROR_PARAMETER_CENSOR]);
  });

  it('survives a null prototype', () => {
    const error = Object.create(null) as Record<string, unknown>;
    error['name'] = 'QueryFailedError';
    error['query'] = 'SELECT ?';
    error['parameters'] = [CANARY];
    const safe = sanitizeQueryFailedError(error);
    expect(inspect(safe)).not.toContain(CANARY);
  });

  it('survives a getter that throws, without invoking it', () => {
    const error = new QueryFailedError('SELECT ?', [CANARY], new Error('driver'));
    Object.defineProperty(error, 'detail', {
      enumerable: true,
      get() {
        throw new Error('this getter must not be called');
      },
    });
    expect(() => sanitizeQueryFailedError(error)).not.toThrow();
    expect((error as unknown as { parameters: unknown[] }).parameters).toEqual([
      ERROR_PARAMETER_CENSOR,
    ]);
  });

  it('redacts the driver error parameters too', () => {
    const driverError = { parameters: [CANARY], code: 'X' };
    const error = new QueryFailedError('SELECT ?', [CANARY], driverError as unknown as Error);
    sanitizeQueryFailedError(error);
    expect(driverError.parameters).toEqual([ERROR_PARAMETER_CENSOR]);
  });

  it('preserves the parameter count, which is what makes an error readable', () => {
    const error = new QueryFailedError('SELECT ?, ?, ?', [1, CANARY, null], new Error('d'));
    const safe = sanitizeQueryFailedError(error) as { parameters: unknown[] };
    expect(safe.parameters).toHaveLength(3);
  });
});
