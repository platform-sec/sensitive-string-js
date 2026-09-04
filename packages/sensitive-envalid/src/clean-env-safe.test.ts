import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { bool, cleanEnv, num, port, str } from 'envalid';
import { describe, it, expect, vi, afterEach } from 'vitest';

import { cleanEnvSafe } from './clean-env.js';
import { EnvValidationError } from './errors.js';
import { toEnvRecord } from './record.js';
import { credential, sensitive } from './validators.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';
const CTX = { name: 'test', reason: 'assert' };

afterEach(() => {
  vi.restoreAllMocks();
});

describe('the aggregate report', () => {
  it('names every failing variable in one throw', () => {
    try {
      cleanEnvSafe(
        { A: 'not-a-number', B: 'not-a-port' },
        { A: num(), B: port(), C: str(), D: credential() }
      );
      expect.unreachable();
    } catch (error) {
      const failures = (error as EnvValidationError).failures;

      // envalid's own `reporter: null` would have reported A and stopped.
      expect(failures.map((f) => f.variable).sort()).toEqual(['A', 'B', 'C', 'D']);
    }
  });

  it('separates invalid from missing', () => {
    try {
      cleanEnvSafe({ A: 'not-a-number' }, { A: num(), B: str() });
      expect.unreachable();
    } catch (error) {
      const failures = (error as EnvValidationError).failures;

      expect(failures.find((f) => f.variable === 'A')?.kind).toBe('invalid');
      expect(failures.find((f) => f.variable === 'B')?.kind).toBe('missing');
    }
  });

  it('replaces the invalid message and keeps the missing one', () => {
    try {
      cleanEnvSafe(
        { A: CANARY },
        {
          A: bool(),
          C: str({
            desc: 'the C service base url',
            example: 'https://c.example',
            docs: 'https://d',
          }),
        }
      );
      expect.unreachable();
    } catch (error) {
      const failures = (error as EnvValidationError).failures;

      // envalid's own message here is `Invalid bool input: "<the value>"`.
      expect(failures.find((f) => f.variable === 'A')?.detail).not.toContain(CANARY);
      // And `formatSpecDescription` builds this from the caller's own fields.
      expect(failures.find((f) => f.variable === 'C')?.detail).toBe(
        'the C service base url (eg. "https://c.example"). See https://d'
      );
    }
  });

  it('falls back to (required) for a variable with no description', () => {
    try {
      cleanEnvSafe({}, { A: str() });
      expect.unreachable();
    } catch (error) {
      expect((error as EnvValidationError).failures[0]?.detail).toBe('(required)');
    }
  });

  it('reports the class of a sensitive variable and plain for a stock one', () => {
    try {
      cleanEnvSafe({}, { A: credential(), B: sensitive(), C: port() });
      expect.unreachable();
    } catch (error) {
      const byName = new Map(
        (error as EnvValidationError).failures.map((f) => [f.variable, f.klass])
      );

      expect(byName.get('A')).toBe('credential');
      expect(byName.get('B')).toBe('sensitive');
      expect(byName.get('C')).toBe('plain');
    }
  });

  it('renders both sections in the message', () => {
    try {
      cleanEnvSafe({ A: 'x' }, { A: num(), B: str() });
      expect.unreachable();
    } catch (error) {
      const message = (error as Error).message;

      expect(message).toContain('Invalid environment variables:');
      expect(message).toContain('Missing environment variables:');
      expect(message).toContain('A (plain)');
      expect(message).toContain('B (plain)');
    }
  });

  it('chains no cause', () => {
    try {
      cleanEnvSafe({ A: CANARY }, { A: num() });
      expect.unreachable();
    } catch (error) {
      expect((error as { cause?: unknown }).cause).toBeUndefined();
      expect(JSON.stringify(error)).not.toContain(CANARY);
      expect((error as Error).stack).not.toContain(CANARY);
    }
  });
});

describe('what it refuses to do', () => {
  it('never calls process.exit', () => {
    const exit = vi.spyOn(process, 'exit').mockImplementation((() => undefined) as never);

    expect(() => cleanEnvSafe({}, { A: str() })).toThrow(EnvValidationError);
    expect(exit).not.toHaveBeenCalled();
  });

  it('never logs through envalid default reporter', () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => undefined);

    expect(() => cleanEnvSafe({ A: CANARY }, { A: num() })).toThrow(EnvValidationError);
    expect(error).not.toHaveBeenCalled();
  });

  it('never returns a partially populated object', () => {
    let returned: unknown;

    try {
      returned = cleanEnvSafe({ A: '3000' }, { A: port(), B: str() });
    } catch {
      // expected
    }

    expect(returned).toBeUndefined();
  });

  it('returns silently when nothing failed', () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => undefined);

    const env = cleanEnvSafe({ A: '3000' }, { A: port() });

    expect(env.A).toBe(3000);
    expect(error).not.toHaveBeenCalled();
  });
});

describe('the returned object', () => {
  it('is a strict proxy, which is a feature for a typo', () => {
    const env = cleanEnvSafe({ A: '3000' }, { A: port() });

    expect(() => (env as unknown as Record<string, unknown>)['B']).toThrow(ReferenceError);
  });

  it('keeps envalid accessors', () => {
    const env = cleanEnvSafe({ NODE_ENV: 'test', A: '1' }, { A: str() });

    expect(env.isTest).toBe(true);
    expect(env.isProduction).toBe(false);
  });

  it('answers for extra inspectables when the caller declares them', () => {
    const env = cleanEnvSafe({ A: '1' }, { A: str() }, { extraInspectables: ['B'] });

    expect(() => (env as unknown as Record<string, unknown>)['B']).not.toThrow();
  });
});

describe('toEnvRecord', () => {
  it('splits the wrapped half from the plain half', () => {
    const env = cleanEnvSafe(
      { DB_PASSWORD: CANARY, PORT: '3000', DEBUG: 'true' },
      { DB_PASSWORD: credential(), PORT: port(), DEBUG: bool() }
    );

    const record = toEnvRecord(env);

    expect([...record.fields.keys()]).toEqual(['DB_PASSWORD']);
    expect(record.plain.get('PORT')).toBe('3000');
    expect(record.plain.get('DEBUG')).toBe('true');
    expect(record.names).toEqual(['DB_PASSWORD', 'PORT', 'DEBUG']);
  });

  it('reports removal and the kernel copy as this package cannot know them', () => {
    const record = toEnvRecord(cleanEnvSafe({ A: '1' }, { A: str() }));

    expect(record.removed).toEqual([]);
    expect(record.kernelCopy).toBe('unknown');
  });

  it('does not throw on the strict proxy it is given', () => {
    const env = cleanEnvSafe({ A: '1' }, { A: str() });

    expect(() => toEnvRecord(env)).not.toThrow();
  });

  it('keeps the instance rather than copying it apart', () => {
    const env = cleanEnvSafe({ DB_PASSWORD: CANARY }, { DB_PASSWORD: credential() });
    const record = toEnvRecord(env);

    expect(record.fields.get('DB_PASSWORD')).toBe(env.DB_PASSWORD);
    expect(record.fields.get('DB_PASSWORD')?.reveal(CTX)).toBe(CANARY);
  });

  it('leaves a structural value out of both maps', () => {
    const env = cleanEnvSafe({ A: '1' }, { A: str() });
    const withObject = { ...env, STRUCT: { nested: true } };

    const record = toEnvRecord(withObject);

    expect(record.names).toContain('STRUCT');
    expect(record.plain.has('STRUCT')).toBe(false);
    expect(record.fields.has('STRUCT')).toBe(false);
  });
});

/**
 * The third-party pins for envalid 8.2.0. Each records a measurement a design
 * decision rests on, so an upgrade that changes it fails a test rather than
 * silently invalidating the decision.
 */
describe('envalid 8.2.0, pinned', () => {
  it('assigns default without passing it through the validator', () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => undefined);

    // Raw `cleanEnv`, with a validator that always wraps. The type says
    // SensitiveString. The runtime has a string.
    const raw = cleanEnv(
      {},
      {
        API_KEY: { _parse: (v: string) => new SensitiveString(v, 'credential'), default: 'dev' },
      }
    ) as unknown as { API_KEY: unknown };

    expect(typeof raw.API_KEY).toBe('string');
    expect(raw.API_KEY).not.toBeInstanceOf(SensitiveString);
    expect(error).not.toHaveBeenCalled();
  });

  it('embeds the raw input in a built-in validator message', () => {
    let raw: string | undefined;

    try {
      cleanEnv({ A: CANARY }, { A: bool() }, { reporter: null });
    } catch (error) {
      raw = (error as Error).message;
    }

    expect(raw).toContain(CANARY);
    // And this package's own report of the same failure does not.
    try {
      cleanEnvSafe({ A: CANARY }, { A: bool() });
    } catch (error) {
      expect((error as Error).message).not.toContain(CANARY);
    }
  });

  it('reports one variable with reporter: null and every one through a reporter', () => {
    let first: string[] = [];

    try {
      cleanEnv({ A: 'x' }, { A: num(), B: port(), C: str() }, { reporter: null });
    } catch {
      first = ['A'];
    }

    expect(first).toEqual(['A']);

    let all: string[] = [];
    cleanEnv(
      { A: 'x' },
      { A: num(), B: port(), C: str() },
      {
        reporter: ({ errors }) => {
          all = Object.keys(errors).sort();
        },
      }
    );

    expect(all).toEqual(['A', 'B', 'C']);
  });

  it('builds a missing-variable message only from the caller fields', () => {
    let message = '';

    cleanEnv(
      {},
      { C: str({ desc: 'the C url', example: 'https://c.example', docs: 'https://d' }) },
      {
        reporter: ({ errors }) => {
          message = (errors as Record<string, Error>)['C']?.message ?? '';
        },
      }
    );

    expect(message).toBe('the C url (eg. "https://c.example"). See https://d');
  });

  it('throws on a direct read of an undeclared name', () => {
    const env = cleanEnv({ A: '1' }, { A: str() }) as unknown as Record<string, unknown>;

    expect(() => env['B']).toThrow(/Env var not found/);
  });

  it('returns an unvalidated object when a reporter neither throws nor exits', () => {
    // The failure mode `cleanEnvSafe` exists to avoid, and it is quieter than
    // it looks. An *absent* variable is assigned `undefined` before the
    // EnvMissingError is raised, so it stays an own property and the strict
    // proxy answers `undefined` rather than throwing: the caller has a variable
    // typed `string` holding `undefined`, and nothing points at the validation
    // that did not happen. An *invalid* one is never assigned at all, so that
    // one does throw.
    const env = cleanEnv(
      { B: 'not-a-port' },
      { A: str(), B: port() },
      { reporter: () => undefined }
    ) as unknown as Record<string, unknown>;

    expect(env['A']).toBeUndefined();
    // The proxy's message for an invalid variable is the misleading one: the
    // variable *was* declared and *did* fail, and envalid reports it as one
    // nobody wrote a validator for.
    expect(() => env['B']).toThrow(/accessed but not validated/);
  });

  it('freezes its result and still reveals through it', () => {
    const env = cleanEnvSafe({ A: CANARY }, { A: credential() });

    expect(Object.isFrozen(env)).toBe(true);
    expect(env.A.reveal(CTX)).toBe(CANARY);
  });
});
