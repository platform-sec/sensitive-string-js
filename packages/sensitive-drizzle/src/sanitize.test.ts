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

  it('cleans a stack that was already materialised before sanitizing', () => {
    // The case the suite missed for a whole commit. `stack` is an own accessor
    // on a real error and stays one, so a sanitizer keyed on
    // `descriptor.value` rewrites nothing; its tests pass anyway, because V8
    // formats the stack at first access from whatever `message` says by then.
    // Reading it first is what breaks that, and is what a logger or an APM
    // agent between the throw and the catch does.
    const error = queryError();
    expect(String(error.stack)).toContain(CANARY);
    const sanitized = sanitizeQueryError(error) as DrizzleQueryError;
    expect(String(sanitized.stack)).not.toContain(CANARY);
    expect(String(sanitized.stack)).toContain('sanitize.test.ts');
  });

  it('reads the stack through the getter rather than looking for a value', () => {
    // Pinning the mechanism, not just the outcome: on a real error the property
    // is an accessor, and asserting that keeps the regression from coming back
    // in a form the outcome test cannot see.
    const error = queryError();
    const descriptor = Object.getOwnPropertyDescriptor(error, 'stack');
    expect(descriptor).toBeDefined();
    expect(descriptor && 'value' in descriptor).toBe(false);
    sanitizeQueryError(error);
    const after = Object.getOwnPropertyDescriptor(error, 'stack');
    expect(after && 'value' in after).toBe(true);
    expect(String((after as { value: string }).value)).not.toContain(CANARY);
  });

  it('withholds the frames when the message was rewritten before it got here', () => {
    // An error normaliser between the throw and the catch leaves a stack whose
    // header no longer matches any text we hold, and nothing left to bound the
    // parameters with. Guessing the boundary is what the frame-scanning version
    // did, and a parameter holding a newline and an indented `at ` fools it.
    const error = queryError();
    void error.stack;
    error.message = 'Something went wrong';
    const sanitized = sanitizeQueryError(error) as DrizzleQueryError;
    expect(String(sanitized.stack)).not.toContain(CANARY);
    expect(String(sanitized.stack)).toContain('stack withheld');
  });

  it('is not fooled by a parameter value that looks like a stack frame', () => {
    const nasty = `${CANARY}\n   at the office`;
    const error = new DrizzleQueryError('select 1 where a = $1', [nasty], undefined);
    void error.stack;
    const sanitized = sanitizeQueryError(error) as DrizzleQueryError;
    expect(String(sanitized.stack)).not.toContain(CANARY);
    expect(String(sanitized.message)).not.toContain(CANARY);
  });

  it('cleans a stack it cannot write to, by returning a copy that carries the clean one', () => {
    const error = queryError();
    Object.defineProperty(error, 'stack', {
      value: `Error: ${error.message}\n    at somewhere`,
      writable: false,
      configurable: false,
    });
    const sanitized = sanitizeQueryError(error) as DrizzleQueryError;
    expect(sanitized).not.toBe(error);
    expect(String(sanitized.stack)).not.toContain(CANARY);
    expect(String(sanitized.stack)).toContain('at somewhere');
    expect(sanitized.params).toEqual([ERROR_PARAMETER_CENSOR]);
    expect(sanitized.message).not.toContain(CANARY);
  });

  it('leaves a stack alone when the message is not one Drizzle built', () => {
    // Nothing to key off, and nothing to justify rewriting someone else's
    // stack. The parameters are still censored on the property.
    const odd = Object.assign(new Error('unrecognised'), { query: 'select 1', params: [CANARY] });
    const sanitized = sanitizeQueryError(odd) as { params: unknown[]; stack?: string };
    expect(sanitized.params).toEqual([ERROR_PARAMETER_CENSOR]);
    expect(String(sanitized.stack)).toContain('unrecognised');
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
