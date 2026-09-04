import { SensitiveString } from '@platform-sec/sensitive-string-core';
import type { RevealContext } from '@platform-sec/sensitive-string-core';
import { describe, it, expect } from 'vitest';

import { carriesRedactionMarker, toChildEnv } from './child.js';
import { loadEnv } from './load.js';
import { ChildEnvRefusedError, EnvValueError } from './types.js';
import type { EnvRecord } from './types.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';
const CTX = { name: 'pg_dump', reason: 'take a backup' };

function record(source: Record<string, string>): EnvRecord {
  return loadEnv(
    { fields: { DB_PASSWORD: 'credential', API_KEY: 'credential' }, fallback: 'plain' },
    { source }
  );
}

describe('toChildEnv', () => {
  it('reveals exactly the names it was given', () => {
    const env = toChildEnv(
      record({ DB_PASSWORD: CANARY, API_KEY: 'other', PORT: '3000' }),
      ['DB_PASSWORD'],
      CTX
    );

    expect(env).toEqual({ DB_PASSWORD: CANARY });
  });

  it('does not spread process.env into the result', () => {
    const env = toChildEnv(record({ DB_PASSWORD: CANARY }), ['DB_PASSWORD'], CTX);

    expect(Object.keys(env)).toEqual(['DB_PASSWORD']);
    expect(env['PATH']).toBeUndefined();
  });

  it('copies a plain variable without a reveal', () => {
    const env = toChildEnv(record({ PORT: '3000' }), ['PORT'], CTX);

    expect(env).toEqual({ PORT: '3000' });
  });

  it('is an ordinary object a spawn can spread', () => {
    const env = toChildEnv(record({ DB_PASSWORD: CANARY }), ['DB_PASSWORD'], CTX);

    expect(Object.getPrototypeOf(env)).toBe(Object.prototype);
    expect({ PATH: '/usr/bin', ...env }).toEqual({ PATH: '/usr/bin', DB_PASSWORD: CANARY });
  });

  it('audits the reveal under the context it was given', () => {
    const seen: string[] = [];
    const ctx: RevealContext = {
      name: 'pg_dump',
      reason: 'take a backup',
      auditReveal: (value) => seen.push(value.label ?? '?'),
    };

    toChildEnv(record({ DB_PASSWORD: CANARY }), ['DB_PASSWORD'], ctx);

    expect(seen).toEqual(['DB_PASSWORD']);
  });

  it('refuses a name that is in neither map', () => {
    expect(() => toChildEnv(record({ PORT: '3000' }), ['NOPE'], CTX)).toThrow(ChildEnvRefusedError);

    try {
      toChildEnv(record({ PORT: '3000' }), ['NOPE'], CTX);
      expect.unreachable();
    } catch (error) {
      expect((error as ChildEnvRefusedError).reason).toBe('unknown-name');
      expect((error as ChildEnvRefusedError).variable).toBe('NOPE');
    }
  });

  it('refuses to run without an explicit context', () => {
    try {
      toChildEnv(record({ DB_PASSWORD: CANARY }), ['DB_PASSWORD'], undefined as never);
      expect.unreachable();
    } catch (error) {
      expect((error as ChildEnvRefusedError).reason).toBe('no-context');
    }
  });
});

describe('the marker guard', () => {
  /**
   * The failure this exists for. Anything assigned into an environment object
   * is coerced with `String()`, so an instance that reaches a spawn arrives at
   * the child as the literal text `[REDACTED:credential]` and the child
   * authenticates with it.
   */
  it('refuses a value that already stringified through a template literal', () => {
    // eslint-disable-next-line @typescript-eslint/restrict-template-expressions -- the implicit coercion is the subject of this test
    const stringified = `${new SensitiveString(CANARY, 'credential')}`;
    const stringifiedRecord = loadEnv(
      { fallback: 'plain' },
      { source: { DB_PASSWORD: stringified } }
    );

    try {
      toChildEnv(stringifiedRecord, ['DB_PASSWORD'], CTX);
      expect.unreachable();
    } catch (error) {
      expect((error as ChildEnvRefusedError).reason).toBe('marker');
      expect((error as ChildEnvRefusedError).variable).toBe('DB_PASSWORD');
    }
  });

  it('names the fix and never the value', () => {
    const stringifiedRecord = loadEnv(
      { fallback: 'plain' },
      { source: { DB_PASSWORD: '[REDACTED:credential]', OK: CANARY } }
    );

    try {
      toChildEnv(stringifiedRecord, ['DB_PASSWORD', 'OK'], CTX);
      expect.unreachable();
    } catch (error) {
      const message = (error as Error).message;
      expect(message).toContain('DB_PASSWORD');
      expect(message).toMatch(/reveal/);
      expect(message).not.toContain(CANARY);
    }
  });

  it('refuses before any of the environment is returned', () => {
    const mixed = loadEnv(
      { fields: { API_KEY: 'credential' }, fallback: 'plain' },
      { source: { API_KEY: CANARY, BAD: 'prefix [REDACTED:credential] suffix' } }
    );

    let returned: Record<string, string> | undefined;

    try {
      returned = toChildEnv(mixed, ['API_KEY', 'BAD'], CTX);
    } catch {
      // expected
    }

    expect(returned).toBeUndefined();
  });

  it('accepts a value that is merely similar', () => {
    const near = loadEnv({ fallback: 'plain' }, { source: { A: '[REDACTED]', B: 'REDACTED:x' } });

    expect(toChildEnv(near, ['A', 'B'], CTX)).toEqual({ A: '[REDACTED]', B: 'REDACTED:x' });
  });
});

describe('carriesRedactionMarker', () => {
  it('is true for an instance and for a stringified one', () => {
    expect(carriesRedactionMarker(new SensitiveString(CANARY, 'credential'))).toBe(true);
    expect(carriesRedactionMarker('[REDACTED:sensitive]')).toBe(true);
  });

  it('is false for an ordinary value', () => {
    expect(carriesRedactionMarker(CANARY)).toBe(false);
    expect(carriesRedactionMarker(undefined)).toBe(false);
    expect(carriesRedactionMarker(3000)).toBe(false);
  });
});

describe('EnvValueError', () => {
  it('names the variable and the class, and leaves `name` an error name', () => {
    const error = new EnvValueError('PORT', 'plain', 'not an integer');

    expect(error.variable).toBe('PORT');
    expect(error.klass).toBe('plain');
    expect(error.message).toBe(
      "Environment variable 'PORT' (plain) failed validation: not an integer"
    );
    // `name` on an Error is the error's own type name. Putting the variable
    // there would break every `catch` that switches on it, which is why the
    // variable is on `variable`.
    expect(error.name).toBe('EnvValueError');
    expect(error.cause).toBeUndefined();
  });

  it('is what a caller uses instead of an error that echoes the value', () => {
    const error = new EnvValueError('DB_PASSWORD', 'credential', 'shorter than 12 characters');

    expect(error.message).not.toContain(CANARY);
    expect(error).toBeInstanceOf(Error);
  });
});
