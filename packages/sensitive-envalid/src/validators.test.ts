import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { port, str } from 'envalid';
import { describe, it, expect, expectTypeOf } from 'vitest';

import { cleanEnvSafe } from './clean-env.js';
import { EnvValidationError } from './errors.js';
import { credential, makeSensitiveValidator, sensitive, sensitiveMeta } from './validators.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';
const CTX = { name: 'test', reason: 'assert' };

describe('the sensitive validators', () => {
  it('produces a SensitiveString of the declared class', () => {
    const env = cleanEnvSafe(
      { DB_PASSWORD: CANARY, SUPPORT_EMAIL: 'a@b.example' },
      { DB_PASSWORD: credential(), SUPPORT_EMAIL: sensitive() }
    );

    expect(env.DB_PASSWORD).toBeInstanceOf(SensitiveString);
    expect(env.DB_PASSWORD.klass).toBe('credential');
    expect(env.SUPPORT_EMAIL.klass).toBe('sensitive');
    expect(env.DB_PASSWORD.reveal(CTX)).toBe(CANARY);
  });

  /**
   * The class parameter surviving into the inferred type is the reason this is
   * built on envalid's own `makeValidator`. A generic factory typed as
   * `Function` would give the caller `any` here.
   */
  it('carries the class into the inferred type', () => {
    const env = cleanEnvSafe(
      { DB_PASSWORD: CANARY, SUPPORT_EMAIL: 'a@b.example', PORT: '3000' },
      { DB_PASSWORD: credential(), SUPPORT_EMAIL: sensitive(), PORT: port() }
    );

    expectTypeOf(env.DB_PASSWORD).toEqualTypeOf<SensitiveString<'credential'>>();
    expectTypeOf(env.SUPPORT_EMAIL).toEqualTypeOf<SensitiveString<'sensitive'>>();
    expectTypeOf(env.PORT).toEqualTypeOf<number>();
  });

  it('labels a value with its own variable name by default', () => {
    const env = cleanEnvSafe({ API_KEY: CANARY }, { API_KEY: credential() });

    expect(env.API_KEY.label).toBe('API_KEY');
  });

  it('uses an explicit label when one is given', () => {
    const env = cleanEnvSafe({ API_KEY: CANARY }, { API_KEY: credential({ label: 'api_key' }) });

    expect(env.API_KEY.label).toBe('api_key');
  });

  it('redacts through the frozen result', () => {
    const env = cleanEnvSafe({ API_KEY: CANARY }, { API_KEY: credential() });

    expect(Object.isFrozen(env)).toBe(true);
    expect(String(env.API_KEY)).toBe('[REDACTED:credential]');
    expect(JSON.stringify(env)).toBe('{"API_KEY":"[REDACTED:credential]"}');
    expect(env.API_KEY.reveal(CTX)).toBe(CANARY);
  });

  it('accepts any class through the factory', () => {
    const other = makeSensitiveValidator('sensitive');
    const env = cleanEnvSafe({ X: CANARY }, { X: other({ label: 'x' }) });

    expect(env.X.klass).toBe('sensitive');
  });
});

describe('the format check', () => {
  it('runs on the raw string, before wrapping', () => {
    const seen: string[] = [];

    cleanEnvSafe(
      { TOKEN: CANARY },
      {
        TOKEN: credential({
          format: {
            check: (raw) => {
              seen.push(raw);
              return true;
            },
            detail: 'anything',
          },
        }),
      }
    );

    expect(seen).toEqual([CANARY]);
  });

  it('rejects a value the check refuses, naming the check and not the input', () => {
    try {
      cleanEnvSafe(
        { TOKEN: CANARY },
        {
          TOKEN: credential({
            format: { check: (raw) => raw.startsWith('ghp_'), detail: 'a GitHub token prefix' },
          }),
        }
      );
      expect.unreachable();
    } catch (error) {
      const message = (error as Error).message;

      expect(message).toContain('a GitHub token prefix');
      expect(message).toContain('TOKEN');
      expect(message).not.toContain(CANARY);
    }
  });

  it('replaces the message when the check itself throws with the input in it', () => {
    try {
      cleanEnvSafe(
        { TOKEN: CANARY },
        {
          TOKEN: credential({
            // The shape that makes this necessary: a check written around a
            // parser puts its input in its own error.
            format: {
              check: (raw) => Boolean(new URL(raw)),
              detail: 'a URL',
            },
          }),
        }
      );
      expect.unreachable();
    } catch (error) {
      expect((error as Error).message).toContain("the 'a URL' check threw");
      expect((error as Error).message).not.toContain(CANARY);
    }
  });

  it('treats a non-boolean return as a rejection', () => {
    expect(() =>
      cleanEnvSafe(
        { TOKEN: CANARY },
        {
          TOKEN: credential({
            format: { check: (() => 'yes') as unknown as (raw: string) => boolean, detail: 'x' },
          }),
        }
      )
    ).toThrow(EnvValidationError);
  });
});

describe('sensitiveDefault', () => {
  /**
   * The type erosion this replaces. envalid assigns `default` without passing
   * it through validation, so a variable typed `SensitiveString<'credential'>`
   * holds a raw `string` at run time and every later `.reveal()` throws.
   */
  it('wraps the fallback like a parsed value', () => {
    const env = cleanEnvSafe({}, { API_KEY: credential({ sensitiveDefault: 'dev-fallback' }) });

    expect(env.API_KEY).toBeInstanceOf(SensitiveString);
    expect(env.API_KEY.klass).toBe('credential');
    expect(env.API_KEY.reveal(CTX)).toBe('dev-fallback');
    expect(JSON.stringify(env)).toBe('{"API_KEY":"[REDACTED:credential]"}');
  });

  it('gives the fallback the same label a parsed value would get', () => {
    const named = cleanEnvSafe({}, { API_KEY: credential({ sensitiveDefault: 'x' }) });
    const labelled = cleanEnvSafe(
      {},
      { API_KEY: credential({ sensitiveDefault: 'x', label: 'k' }) }
    );

    expect(named.API_KEY.label).toBe('API_KEY');
    expect(labelled.API_KEY.label).toBe('k');
  });

  it('is not used when the variable is present', () => {
    const env = cleanEnvSafe(
      { API_KEY: CANARY },
      { API_KEY: credential({ sensitiveDefault: 'dev-fallback' }) }
    );

    expect(env.API_KEY.reveal(CTX)).toBe(CANARY);
  });

  it('keeps the variable from being reported missing', () => {
    expect(() =>
      cleanEnvSafe({}, { API_KEY: credential({ sensitiveDefault: 'x' }) })
    ).not.toThrow();
  });

  it('builds a fresh instance per call rather than sharing one', () => {
    const validators = { API_KEY: credential({ sensitiveDefault: 'x' }) };

    const first = cleanEnvSafe({}, validators);
    const second = cleanEnvSafe({}, validators);

    expect(first.API_KEY).not.toBe(second.API_KEY);
  });
});

describe('sensitiveMeta', () => {
  it('finds the class on a sensitive spec and nothing on a stock one', () => {
    expect(sensitiveMeta(credential({ label: 'k' }))?.klass).toBe('credential');
    expect(sensitiveMeta(sensitive())?.klass).toBe('sensitive');
    expect(sensitiveMeta(str())).toBeUndefined();
    expect(sensitiveMeta(port())).toBeUndefined();
  });

  it('answers undefined for anything that is not a spec', () => {
    expect(sensitiveMeta(null)).toBeUndefined();
    expect(sensitiveMeta(undefined)).toBeUndefined();
    expect(sensitiveMeta(CANARY)).toBeUndefined();
    expect(sensitiveMeta({})).toBeUndefined();
  });

  it('does not throw against an object that refuses to answer', () => {
    const hostile = new Proxy(
      {},
      {
        get(): never {
          throw new ReferenceError('refused');
        },
      }
    );

    expect(() => sensitiveMeta(hostile)).not.toThrow();
    expect(sensitiveMeta(hostile)).toBeUndefined();
  });

  it('survives envalid copying the spec, which is why the marker is a string key', () => {
    // envalid builds a ValidatorSpec with `{ ...spec, _parse }`, and tslib's
    // own fallback for Object.assign copies string keys only.
    const spec = credential({ label: 'k' });
    const copied = { ...spec };

    expect(sensitiveMeta(copied)?.klass).toBe('credential');
  });
});
