import {
  SensitiveString,
  redactInStructure,
  safeStringify,
} from '@platform-sec/sensitive-string-core';
import { toChildEnv } from '@platform-sec/sensitive-string-env';
import {
  assertNoCanary,
  errorText,
  hostileObjects,
  sweep,
} from '@platform-sec/sensitive-string-env/testing';
import type { SweepCase } from '@platform-sec/sensitive-string-env/testing';
import { bool, email, host, json, num, port, str, url } from 'envalid';
import { describe, it, expect, vi, afterEach } from 'vitest';

import { cleanEnvSafe } from '../clean-env.js';
import * as adapter from '../index.js';
import { toEnvRecord } from '../record.js';
import { credential, sensitive, sensitiveMeta } from '../validators.js';
import type { SensitiveSpec } from '../validators.js';

/**
 * The adapter's canary, error and hostile-object sweeps.
 *
 * Every entry point is driven with a canary in every position it accepts, each
 * failure mode is forced, and the canary is asserted absent from every
 * rendering of what came back, the `cause` chain included. The one deliberate
 * exception is asserted rather than excused: an `EnvMissingError` message
 * reaches the caller intact, and the sweep asserts it holds the spec text and
 * no value.
 */

const CANARY = 'LEAKED_SECRET_abc123xyz';
const CTX = { name: 'sweep', reason: 'test' };

afterEach(() => {
  vi.restoreAllMocks();
});

/**
 * Every built-in envalid validator, each of which embeds its input on failure.
 *
 * Typed as a plain map of nullary factories, because each one has its own
 * overload set and calling the union of them is not something TypeScript will
 * do. The sweep only needs to call each and hand the result to `cleanEnvSafe`.
 */
const BUILT_INS: Readonly<Record<string, () => unknown>> = {
  bool,
  email,
  host,
  json,
  num,
  port,
  str,
  url,
};

describe('the canary and error sweep', () => {
  it('lets no canary reach a result or an error, on any entry point', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => undefined);

    const cases: readonly SweepCase[] = [
      {
        name: 'cleanEnvSafe on a valid environment',
        covers: ['cleanEnvSafe'],
        run: () => cleanEnvSafe({ A: CANARY, P: '3000' }, { A: credential(), P: port() }),
      },
      {
        name: 'cleanEnvSafe with a missing variable',
        run: () => cleanEnvSafe({}, { A: credential({ desc: 'the key' }) }),
      },
      {
        name: 'cleanEnvSafe with every built-in validator rejecting the canary',
        run: () =>
          cleanEnvSafe(
            Object.fromEntries(Object.keys(BUILT_INS).map((name) => [name, CANARY])),
            Object.fromEntries(
              Object.entries(BUILT_INS).map(([name, validator]) => [name, validator()])
            )
          ),
      },
      {
        name: 'cleanEnvSafe with a format check that refuses',
        run: () =>
          cleanEnvSafe(
            { A: CANARY },
            { A: credential({ format: { check: () => false, detail: 'a prefix' } }) }
          ),
      },
      {
        name: 'cleanEnvSafe with a format check that throws with the input',
        run: () =>
          cleanEnvSafe(
            { A: CANARY },
            {
              A: credential({
                format: {
                  check: (raw) => {
                    throw new Error(`refused: ${raw}`);
                  },
                  detail: 'a throwing check',
                },
              }),
            }
          ),
      },
      {
        name: 'cleanEnvSafe with a sensitiveDefault',
        run: () => cleanEnvSafe({}, { A: credential({ sensitiveDefault: CANARY }) }),
      },
      {
        name: 'cleanEnvSafe over a source that is not an object',
        run: () => cleanEnvSafe(CANARY, { A: credential() }),
      },
      {
        name: 'cleanEnvSafe with no validators at all',
        run: () => cleanEnvSafe({ A: CANARY }, {}),
      },
      {
        name: 'credential with a refused option',
        covers: ['credential', 'makeSensitiveValidator'],
        run: () => credential({ default: CANARY } as unknown as SensitiveSpec),
      },
      {
        name: 'sensitive with a refused option',
        covers: ['sensitive'],
        run: () => sensitive({ choices: [CANARY] } as unknown as SensitiveSpec),
      },
      {
        name: 'sensitiveMeta over a spec',
        covers: ['sensitiveMeta'],
        run: () => sensitiveMeta(credential({ label: 'k' })),
      },
      {
        name: 'toEnvRecord',
        covers: ['toEnvRecord'],
        run: () => toEnvRecord(cleanEnvSafe({ A: CANARY }, { A: credential() })),
      },
      // The re-exported envalid symbols. Each is safe to use, and each is swept
      // so that a future re-export cannot land unchecked.
      ...Object.entries(BUILT_INS).map(([name, validator]) => ({
        name: `the re-exported ${name} validator`,
        covers: [name],
        run: () => validator(),
      })),
      {
        name: 'the re-exported makeValidator',
        covers: ['makeValidator', 'makeExactValidator'],
        run: () => adapter.makeValidator((raw: string) => raw)({}),
      },
    ];

    const results = await sweep(CANARY, cases);

    expect(results).toHaveLength(cases.length);

    const swept = new Set(cases.flatMap((sweepCase) => sweepCase.covers ?? []));
    const missing = Object.entries(adapter)
      .filter(
        ([, value]) =>
          typeof value === 'function' && !Object.prototype.isPrototypeOf.call(Error, value)
      )
      .map(([name]) => name)
      .filter((name) => !swept.has(name));

    expect(missing).toEqual([]);
  });

  it('chains no cause on the error it throws', () => {
    try {
      cleanEnvSafe({ A: CANARY }, { A: num() });
      expect.unreachable();
    } catch (error) {
      expect((error as { cause?: unknown }).cause).toBeUndefined();
      expect(errorText(error)).not.toContain(CANARY);
    }
  });

  /**
   * The one third-party message that survives verbatim, asserted rather than
   * excused. `formatSpecDescription` builds it from the caller's own `desc`,
   * `example` and `docs` and from nothing the environment supplied.
   */
  it('passes the missing-variable text through and nothing else', () => {
    try {
      cleanEnvSafe(
        { A: CANARY },
        {
          A: bool(),
          B: credential({ desc: 'the B key', example: 'k-123', docs: 'https://d' }),
        }
      );
      expect.unreachable();
    } catch (error) {
      const message = (error as Error).message;

      expect(message).toContain('the B key (eg. "k-123"). See https://d');
      expect(message).not.toContain(CANARY);
    }
  });

  it('keeps the canary out of every rendering of the result', () => {
    const env = cleanEnvSafe({ A: CANARY, P: '3000' }, { A: credential(), P: port() });

    assertNoCanary(CANARY, safeStringify(env), 'safeStringify of a cleaned env');
    assertNoCanary(CANARY, redactInStructure(env), 'redactInStructure of a cleaned env');
    assertNoCanary(CANARY, safeStringify({ config: env }), 'a nested cleaned env');
    assertNoCanary(CANARY, toEnvRecord(env), 'the record built from it');
    expect(JSON.stringify(env)).not.toContain(CANARY);
  });
});

describe('the hostile-object sweep', () => {
  const hostile = hostileObjects();

  for (const [name, object] of Object.entries(hostile)) {
    it(`does not make cleanEnvSafe fail on ${name} in a way that leaks`, () => {
      vi.spyOn(console, 'error').mockImplementation(() => undefined);

      try {
        cleanEnvSafe(object, { KNOWN: str(), OTHER: credential() });
      } catch (error) {
        expect(errorText(error)).not.toContain(CANARY);
        expect((error as { cause?: unknown }).cause).toBeUndefined();
      }
    });

    it(`does not make toEnvRecord throw on ${name}`, () => {
      expect(() => toEnvRecord(object)).not.toThrow();
    });

    it(`does not make sensitiveMeta throw on ${name}`, () => {
      expect(() => sensitiveMeta(object)).not.toThrow();
    });
  }

  it('reads the names a strict proxy does answer for', () => {
    const record = toEnvRecord(hostile['strictProxy'] as object);

    expect(record.plain.get('KNOWN')).toBe('known');
  });
});

describe('the marker guard, across the two packages', () => {
  it('refuses a cleaned env whose value stringified upstream', () => {
    const env = cleanEnvSafe(
      // eslint-disable-next-line @typescript-eslint/restrict-template-expressions -- the coercion is the subject
      { A: `${new SensitiveString(CANARY, 'credential')}` },
      { A: str() }
    );

    expect(() => toChildEnv(toEnvRecord(env), ['A'], CTX)).toThrow(/redaction marker/);
  });

  it('hands a child the revealed value when nothing coerced', () => {
    const env = cleanEnvSafe({ A: CANARY }, { A: credential() });

    expect(toChildEnv(toEnvRecord(env), ['A'], CTX)).toEqual({ A: CANARY });
  });
});
