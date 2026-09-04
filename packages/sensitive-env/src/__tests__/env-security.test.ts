import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  SensitiveString,
  redactInStructure,
  safeStringify,
} from '@platform-sec/sensitive-string-core';
import {
  containsSensitive,
  redactCopy,
  sensitiveClassesIn,
} from '@platform-sec/sensitive-string-core';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';

import { commonSecretNameRules } from '../classify.js';
import { toChildEnv } from '../child.js';
import { assertSensitiveFlags } from '../convict.js';
import * as env from '../index.js';
import { explainEnv, loadEnv } from '../load.js';
import {
  assertEveryExportSwept,
  assertNoCanary,
  errorText,
  findCrossContamination,
  hostileObjects,
  sweep,
} from '../testing.js';
import type { SweepCase } from '../testing.js';
import { wrapFlat, wrapTree } from '../wrap.js';

/**
 * The canary sweep, the error sweep and the hostile-object sweep.
 *
 * Every entry point is driven with a canary in every position it accepts, each
 * failure mode is forced, and the canary is asserted absent from every
 * rendering of what came back: the value, the error message, the stack,
 * `JSON.stringify` of the error, and the `cause` chain at any depth.
 *
 * The `cause` check is load bearing. This package deliberately drops a cause
 * that reflex would preserve, and a contributor restoring it must see a test
 * fail.
 *
 * No test here reads the real environment of the test runner, and every test
 * that writes to `process.env` restores it in a `finally`.
 */

const CANARY = 'LEAKED_SECRET_abc123xyz';
const CTX = { name: 'sweep', reason: 'test' };

const SPEC: env.EnvSpec = {
  fields: { DB_PASSWORD: 'credential', SUPPORT_EMAIL: 'sensitive' },
  rules: commonSecretNameRules,
  fallback: 'plain',
};

const SOURCE: Record<string, string> = {
  DB_PASSWORD: CANARY,
  API_KEY: CANARY,
  SUPPORT_EMAIL: CANARY,
  PORT: '3000',
};

let dir: string;

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'sensitive-env-security-'));
});

afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

function file(name: string, content: string): string {
  const path = join(dir, name);
  writeFileSync(path, content);
  return path;
}

describe('the canary and error sweep', () => {
  it('lets no canary reach a result or an error, on any entry point', async () => {
    const badFile = file('bad.env', `A=1\n${CANARY}\nTOKEN="a=${CANARY}"\nK="${CANARY}\n`);
    const goodFile = file('good.env', `DB_PASSWORD=${CANARY}\nPORT=3000\n`);

    const cases: readonly SweepCase[] = [
      { name: 'loadEnv', covers: ['loadEnv'], run: () => loadEnv(SPEC, { source: SOURCE }) },
      {
        name: 'loadEnv over a file',
        covers: ['loadEnv'],
        run: () => loadEnv(SPEC, { files: [goodFile], source: {} }),
      },
      {
        name: 'loadEnv over a file the parser mangles',
        run: () => loadEnv(SPEC, { files: [badFile], source: {} }),
      },
      {
        name: 'loadEnv over an absent file',
        run: () => loadEnv(SPEC, { files: [join(dir, 'absent.env')], source: SOURCE }),
      },
      {
        name: 'loadEnv over an unreadable path',
        run: () => loadEnv(SPEC, { files: [dir], source: SOURCE }),
      },
      {
        name: 'loadEnv with no fallback',
        run: () => loadEnv({} as env.EnvSpec, { source: SOURCE }),
      },
      {
        name: 'loadEnv with a throwing label function',
        run: () =>
          loadEnv(
            {
              ...SPEC,
              label: (name) => {
                throw new Error(`label refused for ${name}`);
              },
            },
            { source: SOURCE }
          ),
      },
      {
        name: 'loadEnv with an onLoad that throws',
        run: () =>
          loadEnv(SPEC, {
            source: SOURCE,
            onLoad: () => {
              throw new Error('audit sink refused');
            },
          }),
      },
      {
        name: 'explainEnv',
        covers: ['explainEnv'],
        run: () => explainEnv(SPEC, { source: SOURCE }),
      },
      {
        name: 'explainEnv over a mangled file',
        run: () => explainEnv(SPEC, { files: [badFile], source: {} }),
      },
      { name: 'wrapFlat', covers: ['wrapFlat'], run: () => wrapFlat(SOURCE, SPEC) },
      {
        name: 'wrapTree',
        covers: ['wrapTree'],
        run: () => wrapTree({ db: { password: CANARY } }, { 'db.password': 'credential' }),
      },
      {
        name: 'wrapTree with a path typo',
        run: () => wrapTree({ db: { password: CANARY } }, { 'db.passwrod': 'credential' }),
      },
      {
        name: 'parseEnvContent',
        covers: ['parseEnvContent'],
        run: () => env.parseEnvContent(`A=${CANARY}\n`, 'x.env'),
        rawResult: true,
      },
      {
        name: 'readEnvFile on a good file',
        covers: ['readEnvFile'],
        run: () => env.readEnvFile(goodFile),
        rawResult: true,
      },
      { name: 'readEnvFile on a directory', run: () => env.readEnvFile(dir) },
      { name: 'readEnvFile on an absent file', run: () => env.readEnvFile(join(dir, 'no.env')) },
      {
        name: 'toChildEnv',
        covers: ['toChildEnv'],
        run: () => toChildEnv(loadEnv(SPEC, { source: SOURCE }), ['PORT'], CTX),
      },
      {
        name: 'toChildEnv with an unknown name',
        run: () => toChildEnv(loadEnv(SPEC, { source: SOURCE }), ['NOPE'], CTX),
      },
      {
        name: 'toChildEnv with no context',
        run: () =>
          toChildEnv(loadEnv(SPEC, { source: SOURCE }), ['DB_PASSWORD'], undefined as never),
      },
      {
        name: 'toChildEnv over a stringified instance',
        run: () =>
          toChildEnv(
            loadEnv(
              { fallback: 'plain' },
              // eslint-disable-next-line @typescript-eslint/restrict-template-expressions -- the implicit coercion is the subject of this case
              { source: { X: `${new SensitiveString(CANARY, 'credential')}` } }
            ),
            ['X'],
            CTX
          ),
      },
      {
        name: 'carriesRedactionMarker',
        covers: ['carriesRedactionMarker'],
        run: () => env.carriesRedactionMarker(CANARY),
      },
      {
        name: 'kernelCopyNames',
        covers: ['kernelCopyNames'],
        run: () => env.kernelCopyNames(['PATH']),
      },
      {
        name: 'removeFromProcessEnv',
        covers: ['removeFromProcessEnv'],
        run: () => env.removeFromProcessEnv([]),
      },
      {
        name: 'assertSensitiveFlags on a compliant schema',
        covers: ['assertSensitiveFlags'],
        run: () =>
          assertSensitiveFlags(
            { db: { password: { default: CANARY, sensitive: true } } },
            { 'db.password': 'credential' }
          ),
      },
      {
        name: 'assertSensitiveFlags on a schema missing the flag',
        run: () =>
          assertSensitiveFlags(
            { db: { password: { default: CANARY } } },
            { 'db.password': 'credential' }
          ),
      },
      {
        name: 'assertSensitiveFlags on a path the schema lacks',
        run: () => assertSensitiveFlags({ db: {} }, { 'db.password': 'credential' }),
      },
      { name: 'compileEnvSpec', covers: ['compileEnvSpec'], run: () => env.compileEnvSpec(SPEC) },
      { name: 'envLabel', covers: ['envLabel'], run: () => env.envLabel(SPEC, 'DB_PASSWORD') },
      {
        name: 'probeProperty',
        covers: ['probeProperty'],
        run: () => env.probeProperty(SOURCE, 'DB_PASSWORD'),
        rawResult: true,
      },
      { name: 'probeKeys', covers: ['probeKeys'], run: () => env.probeKeys(SOURCE) },
    ];

    const results = await sweep(CANARY, cases);

    expect(results).toHaveLength(cases.length);
    // A registration check: a new public entry point cannot land unswept.
    assertEveryExportSwept(env, cases);
  });

  it('chains no cause on any error it throws', () => {
    const throwers: (() => unknown)[] = [
      () => loadEnv({} as env.EnvSpec, { source: SOURCE }),
      () => loadEnv(SPEC, { files: [dir], source: {} }),
      () => wrapTree({ db: {} }, { 'db.password': 'credential' }),
      () => toChildEnv(loadEnv(SPEC, { source: SOURCE }), ['NOPE'], CTX),
      () => assertSensitiveFlags({ db: {} }, { 'db.password': 'credential' }),
    ];

    for (const thrower of throwers) {
      try {
        thrower();
        expect.unreachable();
      } catch (error) {
        expect((error as { cause?: unknown }).cause).toBeUndefined();
        expect(errorText(error)).not.toContain(CANARY);
      }
    }
  });

  it('keeps the canary out of every rendering of a record', () => {
    const record = loadEnv(SPEC, { source: SOURCE });

    assertNoCanary(CANARY, redactInStructure(record), 'redactInStructure of a record');
    assertNoCanary(CANARY, safeStringify(record), 'safeStringify of a record');
    assertNoCanary(CANARY, redactCopy(record), 'redactCopy of a record');
    expect(String(record.fields.get('DB_PASSWORD'))).toBe('[REDACTED:credential]');
    expect(JSON.stringify([...record.fields])).not.toContain(CANARY);
  });

  it('finds a secret that expansion copied into a plain variable', () => {
    const expanded = {
      DB_PASSWORD: CANARY,
      DATABASE_HOST: 'db.internal',
      EXPANDED: `postgres://app:${CANARY}@db:5432/app`,
    };

    const findings = findCrossContamination(expanded, {
      fields: { DB_PASSWORD: 'credential', EXPANDED: 'plain' },
      fallback: 'plain',
    });

    expect(findings).toEqual(['EXPANDED contains the value of DB_PASSWORD']);
    expect(findings.join('')).not.toContain(CANARY);
  });

  it('finds nothing when both copies are classified', () => {
    const expanded = { DB_PASSWORD: CANARY, EXPANDED: `postgres://app:${CANARY}@db/app` };

    expect(
      findCrossContamination(expanded, {
        fields: { DB_PASSWORD: 'credential', EXPANDED: 'credential' },
        fallback: 'plain',
      })
    ).toEqual([]);
  });
});

/**
 * The hostile-object sweep.
 *
 * Every entry point that accepts caller data is driven with objects that refuse
 * to answer: a Proxy that throws for any name it was not given, one with
 * throwing `ownKeys` and `getOwnPropertyDescriptor` traps, an object with a
 * throwing prototype getter, and a null-prototype object. None of them may make
 * a load, an explain, or a redaction throw.
 *
 * Adversarial by construction rather than a replay of the one object that was
 * observed failing. envalid's strict proxy is what surfaced the first unguarded
 * probe in `core`; the second one was only found because the test drove a proxy
 * that refuses *every* unknown name rather than the one name the measurement
 * had shown.
 */
describe('the hostile-object sweep', () => {
  const hostile = hostileObjects();

  for (const [name, object] of Object.entries(hostile)) {
    describe(name, () => {
      it('does not make loadEnv throw', () => {
        expect(() =>
          loadEnv(
            { fallback: 'plain' },
            {
              source: object as Record<string, string | undefined>,
            }
          )
        ).not.toThrow();
      });

      it('does not make explainEnv throw', () => {
        expect(() =>
          explainEnv(
            { fallback: 'plain' },
            {
              source: object as Record<string, string | undefined>,
            }
          )
        ).not.toThrow();
      });

      it('does not make a guarded probe throw', () => {
        expect(() => env.probeProperty(object, 'anything')).not.toThrow();
        expect(() => env.probeKeys(object)).not.toThrow();
      });

      it('does not make assertSensitiveFlags propagate the refusal', () => {
        // Reporting a missing path is allowed. Propagating the object's own
        // refusal is not.
        try {
          assertSensitiveFlags(object, { 'db.password': 'credential' });
        } catch (error) {
          expect((error as Error).message).toMatch(/Classified convict paths/);
        }
      });

      it('does not make wrapFlat throw', () => {
        expect(() => wrapFlat(object as Record<string, string>, SPEC)).not.toThrow();
      });
    });
  }

  it('still finds the names a strict proxy does answer for', () => {
    const record = loadEnv(
      { fallback: 'plain' },
      {
        source: hostile['strictProxy'] as Record<string, string | undefined>,
      }
    );

    expect(record.plain.get('KNOWN')).toBe('known');
  });
});

/**
 * The same objects, driven through `core`'s redaction walks.
 *
 * The premise of this row is that `core` is safe against objects that refuse to
 * answer, and driving the full adversarial set rather than the one object that
 * was observed failing is what established it. The first defect of this class
 * came from a measurement against envalid's strict proxy, the second only from
 * a proxy that refuses *every* unknown name, and seven more only from driving
 * every hook a walk touches: the tag read, the prototype read, `has`, the
 * `toJSON` call, `ownKeys`, `getOwnPropertyDescriptor`, an enumerable getter,
 * and `toString`.
 *
 * `core` owns the exhaustive version of this suite, in
 * `sensitive-core/src/__tests__/hostile-objects.test.ts`. This is the part that
 * matters here: an `EnvRecord` and an envalid result are the objects this row
 * hands to a logger, so a hostile value inside one must not take the log line
 * down.
 */
describe("core's redaction walks against the same objects", () => {
  const hostile = hostileObjects();
  const walks = {
    redactInStructure,
    containsSensitive,
    safeStringify,
    sensitiveClassesIn,
    redactCopy,
  } as const;

  for (const [objectName, object] of Object.entries(hostile)) {
    it(`survives ${objectName}, directly and nested`, () => {
      for (const [walkName, walk] of Object.entries(walks)) {
        expect(() => walk(object), `${walkName} on ${objectName}`).not.toThrow();
        expect(() => walk({ config: object }), `${walkName} nested`).not.toThrow();
      }
    });
  }

  it('lets no canary through a walk with a hostile object in the same record', () => {
    for (const object of Object.values(hostile)) {
      const record = loadEnv(SPEC, { source: SOURCE });
      const payload = { record, hostile: object };

      assertNoCanary(CANARY, redactInStructure(payload), 'redactInStructure');
      assertNoCanary(CANARY, safeStringify(payload), 'safeStringify');
      assertNoCanary(CANARY, redactCopy(payload), 'redactCopy');
    }
  });

  it('substitutes a marker for an object it cannot read, rather than an empty one', () => {
    const redacted = redactInStructure({ config: hostile['throwingDescriptor'] }) as {
      config: unknown;
    };

    expect(redacted.config).toBe('[Unreadable]');
  });
});
