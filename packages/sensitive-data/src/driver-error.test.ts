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

    const driver = (error as unknown as { driverError: Record<string, unknown> }).driverError;
    expect(driver['parameters']).toEqual([CENSOR]);
    expect(driver['code']).toBe('23505');
    expect(driver['constraint']).toBe('users_email_key');
  });

  it('replaces a nested error that would not take the censor in place', () => {
    // The worst of the three possible outcomes, and the one that looks like
    // success: the outer error reads as sanitized while the nested one it
    // carries by reference still holds the plaintext. Copying the nested error
    // across by descriptor is what produces it.
    const error = structuredError();
    (error as unknown as { driverError: unknown }).driverError = Object.freeze({
      code: '23505',
      constraint: 'users_email_key',
      parameters: [CANARY],
    });

    const out = sanitizeQueryError(error, structuredOnly) as typeof error & {
      driverError: Record<string, unknown>;
    };

    expect(out.driverError['parameters']).toEqual([CENSOR]);
    expect(JSON.stringify(out.driverError)).not.toContain(CANARY);
    // The diagnosis survives the replacement.
    expect(out.driverError['code']).toBe('23505');
    expect(out.driverError['constraint']).toBe('users_email_key');
  });

  it('keeps the message and the stack on the total-failure path', () => {
    // A shape with no `sanitizeMessage` is one whose message carries no value,
    // measured for that ORM rather than assumed, so both are the diagnosis and
    // both are worth keeping when everything else failed.
    const error = structuredError();
    Object.defineProperty(error, 'parameters', {
      get: () => [CANARY],
      configurable: false,
    });
    Object.freeze(error);

    const out = sanitizeQueryError(error, structuredOnly) as Error;

    expect(out).not.toBe(error);
    expect(out.message).toBe('insert into "users" failed');
    expect(out.stack ?? '').not.toContain(CANARY);
    expect(out.name).toBe('QueryFailedError');
  });

  it('never throws, even when every property it would read throws', () => {
    // The recovery path is not exempt from the contract it exists to keep. A
    // property read there can invoke a throwing getter exactly as one in the
    // main path can, and an exception escaping here would destroy the error
    // the caller was trying to hand onwards.
    const hostile = new Error('start') as Error & { query?: unknown; parameters?: unknown };
    for (const key of ['name', 'message', 'stack', 'query', 'parameters']) {
      Object.defineProperty(hostile, key, {
        get() {
          throw new Error('hostile getter');
        },
        configurable: false,
        enumerable: true,
      });
    }

    let out: unknown;
    expect(() => {
      out = sanitizeQueryError(hostile, structuredOnly);
    }).not.toThrow();

    // Read through descriptors, because the accessors this object was built
    // with are carried across to the copy and are the caller's own behaviour.
    // Only `parameters` is replaced, and it is replaced with data.
    const descriptor = Object.getOwnPropertyDescriptor(out, 'parameters');
    expect(descriptor).toBeDefined();
    expect(descriptor?.value).toEqual([CENSOR]);
  });

  it('never throws from the recovery path either', () => {
    // The fixture above is handled by the ordinary descriptor path and never
    // reaches the `catch`. This one does: an exotic object whose descriptor
    // trap throws puts the main path into recovery, and whose `get` trap then
    // throws for every property the recovery path would read. Without a guard
    // there, the exception escapes the function whose whole contract is that it
    // does not throw while an error is already in flight.
    // One property is hostile rather than all of them, which is what makes the
    // per-read guard observable: the recovery path still recovers the name and
    // the message, where an unguarded read would lose both to the one throw.
    const target = structuredError();
    const hostile = new Proxy(target, {
      getOwnPropertyDescriptor(inner, key) {
        if (key === 'parameters') throw new Error('hostile descriptor trap');
        return Reflect.getOwnPropertyDescriptor(inner, key);
      },
      get(inner, key, receiver) {
        if (key === 'stack') throw new Error('hostile get trap');
        return Reflect.get(inner, key, receiver) as unknown;
      },
    });

    let out: unknown;
    expect(() => {
      out = sanitizeQueryError(hostile, structuredOnly);
    }).not.toThrow();

    const recovered = out as Error;
    expect(recovered).toBeInstanceOf(Error);
    expect(recovered.name).toBe('QueryFailedError');
    expect(recovered.message).toBe('insert into "users" failed');
    expect(recovered.stack ?? '').not.toContain(CANARY);
  });

  it('never throws when every property of the recovery path is hostile', () => {
    const target = structuredError();
    const hostile = new Proxy(target, {
      getOwnPropertyDescriptor(inner, key) {
        if (key === 'parameters') throw new Error('hostile descriptor trap');
        return Reflect.getOwnPropertyDescriptor(inner, key);
      },
      get() {
        throw new Error('hostile get trap');
      },
    });

    let out: unknown;
    expect(() => {
      out = sanitizeQueryError(hostile, structuredOnly);
    }).not.toThrow();

    const recovered = out as Error;
    expect(recovered).toBeInstanceOf(Error);
    expect(recovered.message).toBe(structuredOnly.fallbackMessage);
    expect(recovered.stack ?? '').not.toContain(CANARY);
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
