import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { SensitiveString, containsSensitive } from '@platform-sec/sensitive-string-core';
import convict from 'convict';
import dotenv from 'dotenv';
import dotenvExpand from 'dotenv-expand';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';

import { assertSensitiveFlags } from '../convict.js';
import { wrapTree } from '../wrap.js';

/**
 * The measurements this row's design decisions rest on, each pinned against the
 * version it was measured with, so an upgrade that changes the behaviour fails
 * a test rather than silently invalidating a decision.
 *
 * Versions: dotenv 17.4.2, dotenv-expand 1000.0.0, convict 6.2.5, node-config
 * 5.0.1, Node 22.15.0. `util.parseEnv` is pinned in `parse.test.ts`, next to
 * the code that depends on it.
 *
 * The libraries here are dev dependencies with no peer or runtime relationship
 * to this package. They exist so these pins actually run, which is the price of
 * deciding that dotenv, convict and node-config are recipes rather than
 * packages.
 */

const CANARY = 'LEAKED_SECRET_abc123xyz';

/**
 * `packages/sensitive-env`, where the dev dependencies below resolve from.
 *
 * Found through one of those dependencies rather than from `import.meta.url`,
 * because the root type-check compiles this file as CommonJS and rejects the
 * meta-property there.
 */
const packageRoot = join(dirname(require.resolve('convict/package.json')), '..', '..');

let dir: string;

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'sensitive-env-pins-'));
});

afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

function file(name: string, content: string): string {
  const path = join(dir, name);
  writeFileSync(path, content);
  return path;
}

describe('dotenv', () => {
  it('leaves process.env untouched when processEnv is redirected', () => {
    const path = file('redirect.env', `DB_PASSWORD=${CANARY}\nPORT=3000\n`);
    const target: Record<string, string> = {};

    const result = dotenv.config({ path, processEnv: target, quiet: true });

    expect(process.env['DB_PASSWORD']).toBeUndefined();
    expect(target['DB_PASSWORD']).toBe(CANARY);
    expect(result.parsed?.['DB_PASSWORD']).toBe(CANARY);
  });

  it('parses a buffer with no side effects at all', () => {
    const parsed = dotenv.parse(Buffer.from(`API_KEY=${CANARY}\n`));

    expect(parsed['API_KEY']).toBe(CANARY);
    expect(process.env['API_KEY']).toBeUndefined();
  });

  it('keeps an existing process.env entry unless override says otherwise', () => {
    const path = file('override.env', 'SENSITIVE_ENV_PIN=fromFile\n');
    process.env['SENSITIVE_ENV_PIN'] = 'fromEnv';

    try {
      dotenv.config({ path, quiet: true });
      expect(process.env['SENSITIVE_ENV_PIN']).toBe('fromEnv');

      dotenv.config({ path, override: true, quiet: true });
      expect(process.env['SENSITIVE_ENV_PIN']).toBe('fromFile');
    } finally {
      delete process.env['SENSITIVE_ENV_PIN'];
    }
  });
});

describe('dotenv-expand', () => {
  it('inlines a referenced secret into a second variable, verbatim', () => {
    const parsed = dotenv.parse(
      Buffer.from(
        `DB_PASSWORD=${CANARY}\nDATABASE_URL=postgres://app:\${DB_PASSWORD}@db:5432/app\n`
      )
    );

    const expanded = dotenvExpand.expand({ parsed, processEnv: {} });

    // A specification that classifies DB_PASSWORD and says nothing about
    // DATABASE_URL has wrapped one of two copies and reports success. This is
    // what `findCrossContamination` exists to catch.
    expect(expanded.parsed?.['DATABASE_URL']).toContain(CANARY);
  });
});

describe('convict', () => {
  const schema = {
    db: {
      password: { doc: 'db password', format: String, default: '', sensitive: true, env: 'DB_PW' },
      host: { doc: 'db host', format: String, default: 'localhost' },
    },
    smtp: {
      password: { doc: 'smtp password', format: String, default: '' },
    },
  };

  /** convict's own generics are exact, and every `set` below is deliberately off-shape. */
  type LooseConfig = {
    set(path: string, value: unknown): void;
    get(path: string): unknown;
    getProperties(): unknown;
    toString(): string;
    validate(options?: { allowed?: string }): void;
  };

  function configured(): LooseConfig {
    const config = convict(schema) as unknown as LooseConfig;
    config.set('db.password', CANARY);
    config.set('smtp.password', CANARY);
    return config;
  }

  it('masks a sensitive value in toString and nowhere else', () => {
    const config = configured();

    const rendered = JSON.parse(config.toString()) as {
      db: { password: string };
      smtp: { password: string };
    };

    // The flagged path is masked. The unflagged one, in the same document, is
    // not: the flag is per field and there is no document-wide default.
    expect(rendered.db.password).toBe('[Sensitive]');
    expect(rendered.smtp.password).toBe(CANARY);

    // The four paths the flag does not cover. Two of them are what a logger
    // reaches for.
    expect(config.get('db.password')).toBe(CANARY);
    expect(JSON.stringify(config.getProperties())).toContain(CANARY);
    expect(JSON.stringify(config)).toContain(CANARY);
  });

  it('suppresses the value in a failed validate, which is why the flag is kept', () => {
    const strict = convict({
      db: { password: { format: 'int', default: 0, sensitive: true } },
      other: { format: 'int', default: 0 },
    }) as unknown as LooseConfig;
    strict.set('db.password', CANARY);
    strict.set('other', CANARY);

    try {
      strict.validate({ allowed: 'strict' });
      expect.unreachable();
    } catch (error) {
      const message = (error as Error).message;

      // The unflagged field appends `: value was "..."`. The flagged one does not.
      expect(message).toContain('other');
      expect(message.split('db.password')[1]?.split('\n')[0] ?? '').not.toContain(CANARY);
    }
  });

  /**
   * Why `convict.addFormat` is not the hook, and why this is worse than a leak:
   * `config.get()` returns a `lodash.clonedeep`, which copies own enumerable
   * properties onto a fresh object with the same prototype. `klass` and `label`
   * survive, every private field is gone, and every method that reads one
   * throws. The redaction path is the one that crashes.
   */
  it('destroys an instance on the way out of get()', () => {
    const withFormat = convict({
      apiKey: { doc: 'key', format: '*', default: '' },
    }) as unknown as LooseConfig;
    withFormat.set('apiKey', new SensitiveString(CANARY, 'credential', 'apiKey'));

    const value = withFormat.get('apiKey') as SensitiveString<'credential'>;

    expect(value).toBeInstanceOf(SensitiveString);
    expect(value.klass).toBe('credential');
    expect(() => value.reveal()).toThrow(TypeError);
    expect(() => String(value)).toThrow(TypeError);

    // And the library's own leak detector reports the clone as protected, when
    // it is neither usable nor redactable.
    expect(containsSensitive({ apiKey: value })).toBe(true);
  });

  it('is integrated by wrapping the plain tree it hands out', () => {
    const config = configured();
    const settings = wrapTree(config.getProperties() as Record<string, unknown>, {
      'db.password': { klass: 'credential', label: 'db.password' },
      'smtp.password': 'credential',
    });

    expect(JSON.stringify(settings)).not.toContain(CANARY);
    expect((settings as { db: { host: string } }).db.host).toBe('localhost');

    // And the raw values are still in the convict instance. Wrapping copies,
    // it does not remove.
    expect(config.get('db.password')).toBe(CANARY);
  });

  it('is checked for the sensitive flag structurally, with no convict import', () => {
    expect(() =>
      assertSensitiveFlags(schema, {
        'db.password': 'credential',
        'smtp.password': 'credential',
      })
    ).toThrow(/smtp\.password/);

    expect(() => assertSensitiveFlags(schema, { 'db.password': 'credential' })).not.toThrow();
  });
});

describe('node-config', () => {
  /**
   * node-config reads its directory once, at first import, from the process
   * that imported it, so it is driven in a child rather than in this one.
   *
   * The measurement: an instance placed in a config file arrives without its
   * private field in both mutation modes, because the loader's own deep merge
   * copies own property descriptors onto a fresh object with the same
   * prototype. `instanceof` still passes and `klass` still reads, which is the
   * same misleading shape as convict's clone.
   *
   * And it is one step worse than the design predicted:
   * `config.util.toObject()` is documented here as safe to log because it
   * renders an instance as its marker, and it is safe only for a tree that does
   * *not* already hold one. On a tree that does, `toJSON` reaches `toString`,
   * `toString` reads the destroyed private field, and the redaction path is
   * what throws.
   */
  it.each([['default'], ['ALLOW_CONFIG_MUTATIONS']])(
    'destroys an instance in its own loader, mode %s',
    (mode) => {
      const configDir = join(dir, `config-${mode}`);
      mkdirSync(configDir, { recursive: true });

      writeFileSync(
        join(configDir, 'default.js'),
        `const { SensitiveString } = require(${JSON.stringify(
          require.resolve('@platform-sec/sensitive-string-core')
        )});\n` +
          `module.exports = { db: { password: new SensitiveString(${JSON.stringify(
            CANARY
          )}, 'credential', 'db.password') } };\n`
      );

      const source = `
        const config = require('config');
        const { SensitiveString } = require(${JSON.stringify(
          require.resolve('@platform-sec/sensitive-string-core')
        )});
        const value = config.get('db.password');
        let revealError = null;
        try { value.reveal(); } catch (e) { revealError = e.constructor.name; }
        let toObject = null;
        let toObjectError = null;
        try { toObject = config.util.toObject().db.password; }
        catch (e) { toObjectError = e.constructor.name; }
        process.stdout.write(JSON.stringify({
          isInstance: value instanceof SensitiveString,
          klass: value.klass,
          revealError,
          toObject,
          toObjectError,
        }));
      `;

      // The child runs from the package directory, because node-config is a
      // dev dependency of this package and resolves from the working
      // directory. It reads its own directory once, at first import, which is
      // why this is a child rather than an import here.
      const out = execFileSync(process.execPath, ['-e', source], {
        cwd: packageRoot,
        env: {
          ...process.env,
          NODE_CONFIG_DIR: configDir,
          SUPPRESS_NO_CONFIG_WARNING: 'true',
          // The runner sets NODE_ENV=test, and node-config warns on every run
          // that no `test.js` exists next to `default.js`. Neither the warning
          // nor a second fixture file is the subject here.
          NODE_ENV: 'development',
          ...(mode === 'ALLOW_CONFIG_MUTATIONS' ? { ALLOW_CONFIG_MUTATIONS: 'true' } : {}),
        },
        encoding: 'utf8',
      });

      const result = JSON.parse(out) as {
        isInstance: boolean;
        klass: string;
        revealError: string | null;
        toObject: string | null;
        toObjectError: string | null;
      };

      expect(result.isInstance).toBe(true);
      expect(result.klass).toBe('credential');
      expect(result.revealError).toBe('TypeError');

      // `config.util.toObject()` is `JSON.parse(JSON.stringify(config))`, so on
      // a tree of plain strings it is the mutable deep copy the recipe wants.
      // On a tree that already holds an instance it reaches `toJSON`, which
      // reaches `toString`, which reads the private field the merge destroyed,
      // and the accessor throws. So the recipe is one-directional: wrap the
      // tree node-config hands out, and never put an instance into a config
      // file.
      expect(result.toObject).toBeNull();
      expect(result.toObjectError).toBe('TypeError');
    }
  );
});
