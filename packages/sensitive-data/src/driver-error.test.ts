import { describe, expect, it } from 'vitest';
import { sanitizeQueryError } from './driver-error.js';
import type { SanitizeShape } from './driver-error.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';
const CENSOR = '[REDACTED:parameter]';
const PARAMS_MARKER = '\nparams: ';

/** A consumer whose message is clean and whose parameters sit on a nested error. */
const structuredOnly: SanitizeShape = {
  name: 'QueryFailedError',
  identifyBy: ['query', 'parameters'],
  parameterKeys: ['parameters'],
  nestedKeys: ['driverError'],
  censor: CENSOR,
  fallbackMessage: 'A query failed and its error could not be sanitized.',
};

/** A consumer that interpolates the parameters into its message. */
const inMessage: SanitizeShape = {
  name: 'DrizzleQueryError',
  identifyBy: ['query', 'params'],
  parameterKeys: ['params'],
  censor: CENSOR,
  sanitizeMessage: (message) => {
    const at = message.indexOf(PARAMS_MARKER);
    return at === -1 ? undefined : `${message.slice(0, at)}${PARAMS_MARKER}${CENSOR}`;
  },
  stackMarker: PARAMS_MARKER,
  fallbackMessage: 'A query failed and its error could not be sanitized.',
};

function structuredError(): Error & { query: string; parameters: unknown[] } {
  const error = new Error('insert into "users" failed') as Error & {
    query: string;
    parameters: unknown[];
  };
  error.name = 'QueryFailedError';
  error.query = 'insert into "users" ("email") values ($1)';
  error.parameters = [CANARY, 42];
  return error;
}

function messageError(): Error & { query: string; params: unknown[] } {
  const query = 'insert into "users" ("email") values (?)';
  const error = new Error(`Failed query: ${query}${PARAMS_MARKER}${CANARY}`) as Error & {
    query: string;
    params: unknown[];
  };
  error.name = 'DrizzleQueryError';
  error.query = query;
  error.params = [CANARY];
  return error;
}

describe('a structured-only error', () => {
  it('censors the parameters in place, keeping identity and the diagnosis', () => {
    const error = structuredError();
    const out = sanitizeQueryError(error, structuredOnly);

    expect(out).toBe(error);
    expect(error.parameters).toEqual([CENSOR, CENSOR]);
    expect(error.query).toBe('insert into "users" ("email") values ($1)');
    expect(error).toBeInstanceOf(Error);
  });

  it('censors a nested driver error too', () => {
    const error = structuredError();
    (error as unknown as { driverError: unknown }).driverError = {
      code: '23505',
      constraint: 'users_email_key',
      parameters: [CANARY],
    };

    sanitizeQueryError(error, structuredOnly);

    const driver = (error as { driverError: Record<string, unknown> }).driverError;
    expect(driver['parameters']).toEqual([CENSOR]);
    expect(driver['code']).toBe('23505');
    expect(driver['constraint']).toBe('users_email_key');
  });

  it('leaves an unrecognised error entirely alone', () => {
    const error = new TypeError('not a query error');
    expect(sanitizeQueryError(error, structuredOnly)).toBe(error);
    expect(sanitizeQueryError('a string', structuredOnly)).toBe('a string');
    expect(sanitizeQueryError(null, structuredOnly)).toBe(null);
  });

  it('recognises by shape when the name was lost', () => {
    const error = structuredError();
    error.name = 'Error';
    sanitizeQueryError(error, structuredOnly);
    expect(error.parameters).toEqual([CENSOR, CENSOR]);
  });

  it('never invokes a getter that would leak, and replaces it', () => {
    let read = 0;
    const error = new Error('boom') as Error & { query: string };
    error.name = 'QueryFailedError';
    error.query = 'select 1';
    Object.defineProperty(error, 'parameters', {
      get() {
        read += 1;
        return [CANARY];
      },
      configurable: true,
      enumerable: true,
    });

    const out = sanitizeQueryError(error, structuredOnly) as { parameters: unknown };

    expect(read).toBe(0);
    expect(out.parameters).toEqual([CENSOR]);
  });

  it('falls back to a copy when the error is frozen', () => {
    const error = Object.freeze(structuredError());
    const out = sanitizeQueryError(error, structuredOnly) as typeof error;

    expect(out).not.toBe(error);
    expect(out).toBeInstanceOf(Error);
    expect(out.name).toBe('QueryFailedError');
    expect(out.parameters).toEqual([CENSOR, CENSOR]);
    expect(JSON.stringify(out.parameters)).not.toContain(CANARY);
  });

  it('keeps the stack when the message never held a value', () => {
    const error = structuredError();
    const stack = error.stack;
    sanitizeQueryError(error, structuredOnly);
    expect(error.stack).toBe(stack);
  });
});

describe('an error carrying the parameters in its message', () => {
  it('rewrites message, stack and params together', () => {
    const error = messageError();
    const out = sanitizeQueryError(error, inMessage) as typeof error;

    expect(out).toBe(error);
    expect(error.params).toEqual([CENSOR]);
    expect(error.message).not.toContain(CANARY);
    expect(error.message).toContain('insert into "users"');
    expect(error.stack).not.toContain(CANARY);
  });

  it('rewrites a stack that was already materialised', () => {
    // The measured case. `stack` is an own accessor installed by
    // `Error.captureStackTrace` and it stays one; V8 formats it at first access
    // from whatever `message` says by then. One `console.error` between the
    // throw and the catch fixes the string with the plaintext in the header,
    // and a sanitizer that only rewrote `message` would leave it there.
    const error = messageError();
    const materialised = error.stack;
    expect(materialised).toContain(CANARY);

    sanitizeQueryError(error, inMessage);

    expect(error.stack).not.toContain(CANARY);
    expect(error.stack).toContain('at ');
  });

  it('withholds the frames when the message no longer bounds them', () => {
    const error = messageError();
    void error.stack;
    error.message = 'rewritten by something else';

    sanitizeQueryError(error, inMessage);

    expect(error.stack).not.toContain(CANARY);
  });

  it('is not fooled by a parameter that looks like a frame boundary', () => {
    // A value holding a newline and an indented `at ` splits the header inside
    // the parameters. A frame-boundary implementation splices the tail back on
    // and produces a stack that reads as censored and carries the value.
    const query = 'insert into "notes" ("body") values (?)';
    const nasty = `${CANARY}\n    at somewhere/else.js:1:1`;
    const error = new Error(`Failed query: ${query}${PARAMS_MARKER}${nasty}`) as Error & {
      query: string;
      params: unknown[];
    };
    error.name = 'DrizzleQueryError';
    error.query = query;
    error.params = [nasty];
    void error.stack;

    sanitizeQueryError(error, inMessage);

    expect(error.stack).not.toContain(CANARY);
    expect(error.message).not.toContain(CANARY);
  });

  it('drops the stack rather than carrying it on the total-failure path', () => {
    const error = messageError();
    Object.defineProperty(error, 'params', { get: () => [CANARY], configurable: false });
    Object.freeze(error);

    const out = sanitizeQueryError(error, inMessage) as Error;

    expect(out).not.toBe(error);
    expect(out.stack ?? '').not.toContain(CANARY);
    expect(out.message).not.toContain(CANARY);
    expect(out.name).toBe('DrizzleQueryError');
  });
});

describe('the canary sweep', () => {
  it('leaves the value in no own property of either shape', () => {
    for (const [error, shape] of [
      [structuredError(), structuredOnly],
      [messageError(), inMessage],
    ] as const) {
      const out = sanitizeQueryError(error, shape) as object;

      for (const key of Reflect.ownKeys(out)) {
        const descriptor = Object.getOwnPropertyDescriptor(out, key);
        if (descriptor === undefined || !('value' in descriptor)) continue;
        // `query` is the statement with its placeholders, which is the half
        // that makes the error useful and holds no value.
        if (key === 'query') continue;
        expect(JSON.stringify(descriptor.value) ?? '').not.toContain(CANARY);
      }
    }
  });
});
