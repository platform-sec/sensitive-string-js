import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { beforeEach, describe, expect, it } from 'vitest';
import { resetClassifiedColumnNames, sensitiveMapping } from './column.js';
import { DrizzleParameterRefusedError } from './errors.js';
import {
  PARAMETER_CENSOR,
  SENSITIVE_LOGGER,
  assertParametersSafe,
  loggerBrand,
  redactParameters,
  sensitiveLogger,
  touchesClassifiedColumn,
} from './logger.js';
import { resetRedactionMarkerCache } from '@platform-sec/sensitive-string-core';
import type { LoggerLike } from './types.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

function recorder(): LoggerLike & { lines: [string, unknown[]][] } {
  const lines: [string, unknown[]][] = [];
  return { lines, logQuery: (q, p) => void lines.push([q, p]) };
}

beforeEach(() => {
  resetClassifiedColumnNames();
  resetRedactionMarkerCache();
});

describe('assertParametersSafe', () => {
  it('refuses an unwrapped instance and names its position', () => {
    const params = ['ok', new SensitiveString(CANARY, 'credential')];
    expect(() => assertParametersSafe('select 1', params)).toThrow(DrizzleParameterRefusedError);
    try {
      assertParametersSafe('select 1', params);
    } catch (error) {
      expect(error).toBeInstanceOf(DrizzleParameterRefusedError);
      const refusal = error as DrizzleParameterRefusedError;
      expect(refusal.parameter).toBe('1');
      expect(refusal.kind).toBe('instance');
      expect(refusal.code).toBe('DRIZZLE_SENSITIVE_PARAMETER');
    }
  });

  it('refuses a string that is already a redaction marker', () => {
    expect(() => assertParametersSafe('select 1', ['[REDACTED:credential]'])).toThrow(
      DrizzleParameterRefusedError
    );
  });

  it('never puts a parameter value in the message it raises', () => {
    try {
      assertParametersSafe(`select * from users where token = ?`, [
        new SensitiveString(CANARY, 'credential'),
      ]);
      expect.unreachable('should have refused');
    } catch (error) {
      expect(String((error as Error).message)).not.toContain(CANARY);
    }
  });

  it('truncates the statement it quotes', () => {
    const long = `select ${'x'.repeat(500)}`;
    try {
      assertParametersSafe(long, [new SensitiveString(CANARY, 'credential')]);
      expect.unreachable('should have refused');
    } catch (error) {
      const refusal = error as DrizzleParameterRefusedError;
      expect(refusal.statement.length).toBeLessThan(long.length);
      expect(refusal.statement.endsWith('...')).toBe(true);
    }
  });

  it('refuses a marker inside a longer string, which is how an array column arrives', () => {
    // A `text[]` or `jsonb` column serialises its contents before the parameter
    // array exists, so an instance inside one is already a marker embedded in a
    // longer string by the time the guard sees it. Equality would miss it.
    expect(() =>
      assertParametersSafe('insert into t (tags) values ($1)', [
        '{[REDACTED:credential],[REDACTED:credential]}',
      ])
    ).toThrow(DrizzleParameterRefusedError);
    expect(() =>
      assertParametersSafe('insert into t (meta) values ($1)', [
        '{"token":"[REDACTED:credential]"}',
      ])
    ).toThrow(DrizzleParameterRefusedError);
  });

  it('passes ordinary parameters through', () => {
    expect(() =>
      assertParametersSafe('select 1', ['a@example.com', 42, null, true, new Date()])
    ).not.toThrow();
  });

  it('understands a parameter bag as well as an array', () => {
    // Drizzle sends an array on every path measured, and the equivalent guard
    // in sensitive-typeorm shipped understanding only arrays with the shape it
    // missed being the one its development driver could not reach. One
    // Array.isArray to not repeat that.
    expect(() =>
      assertParametersSafe('select 1', { e: new SensitiveString(CANARY, 'credential') })
    ).toThrow(DrizzleParameterRefusedError);
    try {
      assertParametersSafe('select 1', { ok: 'fine', e: '[REDACTED:sensitive]' });
      expect.unreachable('should have refused');
    } catch (error) {
      expect((error as DrizzleParameterRefusedError).parameter).toBe('e');
    }
  });

  it('walks a class instance and a Map, not only a plain object', () => {
    class Bag {
      constructor(readonly e: unknown) {}
    }
    expect(() =>
      assertParametersSafe('select 1', new Bag(new SensitiveString(CANARY, 'credential')))
    ).toThrow(DrizzleParameterRefusedError);
    expect(() =>
      assertParametersSafe('select 1', new Map([['e', new SensitiveString(CANARY, 'credential')]]))
    ).toThrow(DrizzleParameterRefusedError);
    // A bag from another realm has Object.prototype from that realm, so a
    // prototype check would have passed it over.
    const foreign = Object.create(null) as Record<string, unknown>;
    foreign['e'] = new SensitiveString(CANARY, 'credential');
    expect(() => assertParametersSafe('select 1', foreign)).toThrow(DrizzleParameterRefusedError);
  });

  it('has nothing to walk in a primitive', () => {
    expect(() => assertParametersSafe('select 1', undefined)).not.toThrow();
    expect(() => assertParametersSafe('select 1', null)).not.toThrow();
    expect(() => assertParametersSafe('select 1', 'not a bag')).not.toThrow();
    expect(() => assertParametersSafe('select 1', 7)).not.toThrow();
  });
});

describe('touchesClassifiedColumn', () => {
  it('is false when nothing has been classified', () => {
    expect(touchesClassifiedColumn('select "email" from "users"')).toBe(false);
  });

  it('matches a quoted identifier in any of the three dialect styles', () => {
    sensitiveMapping('sensitive', 'text', 'email');
    expect(touchesClassifiedColumn('select "email" from "users"')).toBe(true);
    expect(touchesClassifiedColumn('select `email` from `users`')).toBe(true);
    expect(touchesClassifiedColumn('select [email] from [users]')).toBe(true);
  });

  it('matches a bare identifier, which a hand-written statement uses', () => {
    sensitiveMapping('sensitive', 'text', 'email');
    expect(touchesClassifiedColumn('select email from users')).toBe(true);
  });

  it('is case-insensitive', () => {
    sensitiveMapping('sensitive', 'text', 'Email');
    expect(touchesClassifiedColumn('SELECT "EMAIL" FROM "USERS"')).toBe(true);
  });

  it('is false for a statement that mentions no classified name', () => {
    sensitiveMapping('sensitive', 'text', 'email');
    expect(touchesClassifiedColumn('select "id", "name" from "users"')).toBe(false);
  });

  it('accepts extra names for a column classified somewhere else', () => {
    expect(touchesClassifiedColumn('select "ssn" from "v"', new Set(['ssn']))).toBe(true);
  });

  it('does not match a longer identifier that merely contains the name', () => {
    sensitiveMapping('sensitive', 'text', 'email');
    expect(touchesClassifiedColumn('select "email_verified" from "users"')).toBe(false);
  });
});

describe('redactParameters', () => {
  it('replaces every string when the statement touches a classified column', () => {
    expect(redactParameters(['a@example.com', 42, null], true, false)).toEqual([
      PARAMETER_CENSOR,
      42,
      null,
    ]);
  });

  it('leaves the array alone, identically, when it does not', () => {
    const params = ['a@example.com', 42];
    expect(redactParameters(params, false, false)).toBe(params);
  });

  it('replaces an instance whatever the statement looks like', () => {
    expect(redactParameters([new SensitiveString(CANARY, 'credential')], false, false)).toEqual([
      PARAMETER_CENSOR,
    ]);
  });

  it('replaces a marker whatever the statement looks like', () => {
    expect(redactParameters(['[REDACTED:sensitive]'], false, false)).toEqual([PARAMETER_CENSOR]);
  });

  it('replaces every string under redactAllParameters', () => {
    expect(redactParameters(['plain', 7], false, true)).toEqual([PARAMETER_CENSOR, 7]);
  });

  it('redacts a parameter bag as well as an array', () => {
    expect(redactParameters({ e: 'a@example.com', n: 7 }, true, false)).toEqual({
      e: PARAMETER_CENSOR,
      n: 7,
    });
  });

  it('leaves a shape it cannot rebuild identically alone', () => {
    // The guard walks more shapes than this does, deliberately: a refusal has
    // to be exhaustive, whereas a log line that keeps the shape it arrived in
    // is a nicety, and rebuilding a Map as a plain object would change what the
    // inner logger is handed.
    const odd = new Map([['e', 'a@example.com']]);
    expect(redactParameters(odd, true, false)).toBe(odd);
  });
});

describe('sensitiveLogger', () => {
  it('refuses an unwrapped instance before anything is printed', () => {
    const inner = recorder();
    const logger = sensitiveLogger({ inner });
    expect(() =>
      logger.logQuery('insert into "users" ("token") values (?)', [
        new SensitiveString(CANARY, 'credential'),
      ])
    ).toThrow(DrizzleParameterRefusedError);
    expect(inner.lines).toHaveLength(0);
  });

  it('guards with no inner logger, which is the default install', () => {
    const logger = sensitiveLogger();
    expect(() => logger.logQuery('select 1', [new SensitiveString(CANARY, 'sensitive')])).toThrow(
      DrizzleParameterRefusedError
    );
    expect(() => logger.logQuery('select 1', ['fine'])).not.toThrow();
  });

  it('can be told not to refuse, and then only redacts', () => {
    const inner = recorder();
    const logger = sensitiveLogger({ inner, refuse: false });
    logger.logQuery('select 1', [new SensitiveString(CANARY, 'credential')]);
    expect(inner.lines[0]?.[1]).toEqual([PARAMETER_CENSOR]);
  });

  it('censors the parameters of a statement touching a classified column', () => {
    sensitiveMapping('credential', 'text', 'token');
    const inner = recorder();
    sensitiveLogger({ inner }).logQuery('insert into "users" ("token") values (?)', [CANARY]);
    expect(inner.lines[0]?.[1]).toEqual([PARAMETER_CENSOR]);
    expect(JSON.stringify(inner.lines)).not.toContain(CANARY);
  });

  it('keeps the parameters of a statement that touches nothing classified', () => {
    sensitiveMapping('credential', 'text', 'token');
    const inner = recorder();
    sensitiveLogger({ inner }).logQuery('select "id" from "users" where "id" = ?', [7]);
    expect(inner.lines[0]?.[1]).toEqual([7]);
  });

  it('keeps the non-string parameters of a censored statement', () => {
    sensitiveMapping('credential', 'text', 'token');
    const inner = recorder();
    sensitiveLogger({ inner }).logQuery('select "token" from "users" limit ?', [CANARY, 10]);
    expect(inner.lines[0]?.[1]).toEqual([PARAMETER_CENSOR, 10]);
  });

  it('prints nothing when no inner logger was given', () => {
    // The guard is the whole point of the default install, and a deployment
    // that wants no query log still wants it.
    expect(() => sensitiveLogger().logQuery('select 1', [1])).not.toThrow();
  });

  it('carries a brand a check can recognise, under a registry-wide symbol', () => {
    expect(SENSITIVE_LOGGER).toBe(Symbol.for('platform-sec.sensitive-string.drizzle.logger'));
    expect(loggerBrand(sensitiveLogger())).toEqual({ refuse: true });
    expect(loggerBrand(sensitiveLogger({ refuse: false }))).toEqual({ refuse: false });
  });

  it('does not brand something it did not build', () => {
    expect(loggerBrand(recorder())).toBeUndefined();
    expect(loggerBrand(undefined)).toBeUndefined();
    expect(loggerBrand(null)).toBeUndefined();
  });

  it('keeps the brand off the enumerable surface', () => {
    const logger = sensitiveLogger();
    expect(Object.keys(logger)).toEqual(['logQuery']);
    expect(JSON.stringify(logger)).toBe('{}');
  });
});
