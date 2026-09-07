import { DrizzleQueryError } from 'drizzle-orm/errors';
import { describe, expect, it } from 'vitest';
import { ERROR_PARAMETER_CENSOR, sanitizeQueryError } from './sanitize.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

const queryError = (params: unknown[] = [CANARY]): DrizzleQueryError =>
  new DrizzleQueryError(
    'select * from users where token = $1',
    params,
    new Error('driver said no')
  );

describe('sanitizeQueryError', () => {
  it('removes the parameters from all three places Drizzle put them', () => {
    const sanitized = sanitizeQueryError(queryError()) as DrizzleQueryError;
    expect(sanitized.params).toEqual([ERROR_PARAMETER_CENSOR]);
    expect(sanitized.message).not.toContain(CANARY);
    expect(String(sanitized.stack)).not.toContain(CANARY);
  });

  it('leaves the statement in the message, which is what makes the error useful', () => {
    const sanitized = sanitizeQueryError(queryError()) as DrizzleQueryError;
    expect(sanitized.message).toContain('select * from users where token = $1');
  });

  it('preserves the parameter count, so the shape of the failure survives', () => {
    const sanitized = sanitizeQueryError(queryError([CANARY, 'b', 'c'])) as DrizzleQueryError;
    expect(sanitized.params).toHaveLength(3);
  });

  it('keeps identity, query and cause', () => {
    const original = queryError();
    const sanitized = sanitizeQueryError(original);
    expect(sanitized).toBe(original);
    expect((sanitized as DrizzleQueryError).query).toBe('select * from users where token = $1');
    expect((sanitized as { cause?: Error }).cause?.message).toBe('driver said no');
  });

  it('keeps the frames of the stack', () => {
    const sanitized = sanitizeQueryError(queryError()) as DrizzleQueryError;
    expect(String(sanitized.stack)).toContain('sanitize.test.ts');
  });

  it('survives a frozen error by returning a copy with the same prototype', () => {
    const original = Object.freeze(queryError());
    const sanitized = sanitizeQueryError(original) as DrizzleQueryError;
    expect(sanitized).not.toBe(original);
    expect(sanitized).toBeInstanceOf(DrizzleQueryError);
    expect(sanitized.params).toEqual([ERROR_PARAMETER_CENSOR]);
    expect(sanitized.message).not.toContain(CANARY);
    expect(String(sanitized.stack)).not.toContain(CANARY);
  });

  it('never invokes a getter that would produce the parameters', () => {
    let invoked = 0;
    const error = queryError();
    Object.defineProperty(error, 'params', {
      get() {
        invoked += 1;
        return [CANARY];
      },
      configurable: true,
      enumerable: true,
    });
    const sanitized = sanitizeQueryError(error) as DrizzleQueryError;
    expect(invoked).toBe(0);
    expect(sanitized.params).toEqual([ERROR_PARAMETER_CENSOR]);
  });

  it('falls back to a bare error, without the original stack, when nothing can move', () => {
    const error = queryError();
    Object.defineProperty(error, 'params', {
      get() {
        return [CANARY];
      },
      configurable: false,
      enumerable: true,
    });
    Object.freeze(error);
    const sanitized = sanitizeQueryError(error) as Error;
    expect(JSON.stringify(sanitized, Object.getOwnPropertyNames(sanitized))).not.toContain(CANARY);
    expect(String(sanitized.stack)).not.toContain(CANARY);
    expect(sanitized.message).not.toContain(CANARY);
  });

  it('recognises the error by shape, not by class', () => {
    const lookalike = Object.assign(new Error('Failed query: select 1\nparams: ' + CANARY), {
      query: 'select 1',
      params: [CANARY],
    });
    const sanitized = sanitizeQueryError(lookalike) as { params: unknown[] };
    expect(sanitized.params).toEqual([ERROR_PARAMETER_CENSOR]);
  });

  it('leaves anything that is not a query error alone', () => {
    const other = new Error('unrelated');
    expect(sanitizeQueryError(other)).toBe(other);
    expect(sanitizeQueryError('a string')).toBe('a string');
    expect(sanitizeQueryError(null)).toBeNull();
    expect(sanitizeQueryError(undefined)).toBeUndefined();
  });

  it('handles a query error whose message Drizzle did not build', () => {
    const odd = Object.assign(new Error('something else entirely'), {
      query: 'select 1',
      params: [CANARY],
    });
    const sanitized = sanitizeQueryError(odd) as { params: unknown[]; message: string };
    expect(sanitized.params).toEqual([ERROR_PARAMETER_CENSOR]);
    expect(sanitized.message).toBe('something else entirely');
  });

  it('is what an error serialiser sees, on every own property', () => {
    const sanitized = sanitizeQueryError(queryError()) as object;
    const serialised = JSON.stringify(
      sanitized,
      Object.getOwnPropertyNames(sanitized).concat(['message', 'stack'])
    );
    expect(serialised).not.toContain(CANARY);
  });
});
