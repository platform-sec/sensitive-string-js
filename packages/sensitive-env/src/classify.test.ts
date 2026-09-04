import { describe, it, expect } from 'vitest';
import safeRegex from 'safe-regex2';

import { commonSecretNameRules, compileEnvSpec, emptyCounts, envLabel } from './classify.js';
import type { EnvSpec } from './types.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

describe('compileEnvSpec', () => {
  it('requires an explicit fallback', () => {
    expect(() => compileEnvSpec({} as unknown as EnvSpec)).toThrow(/explicit fallback/);
  });

  it('names `plain` as the answer for the environment in the refusal', () => {
    expect(() => compileEnvSpec({} as unknown as EnvSpec)).toThrow(/`plain`/);
  });

  it('rejects anything that is not a spec object', () => {
    expect(() => compileEnvSpec(null as unknown as EnvSpec)).toThrow(/EnvSpec object/);
    expect(() => compileEnvSpec('plain' as unknown as EnvSpec)).toThrow(/EnvSpec object/);
  });

  it('puts fields first, then rules in order, then the fallback', () => {
    const compiled = compileEnvSpec({
      fields: { DB_PASSWORD: 'plain' },
      rules: [
        { pattern: /PASSWORD/, klass: 'credential' },
        { pattern: /^DB_/, klass: 'sensitive' },
      ],
      fallback: 'plain',
    });

    // `fields` wins even when a rule would classify the same name harder.
    expect(compiled.classify('DB_PASSWORD')).toBe('plain');
    // First matching rule wins.
    expect(compiled.classify('APP_PASSWORD')).toBe('credential');
    expect(compiled.classify('DB_HOST')).toBe('sensitive');
    expect(compiled.classify('PATH')).toBe('plain');
  });

  it('never tests a name that `fields` matched against `rules`', () => {
    const compiled = compileEnvSpec({
      fields: { API_KEY: 'sensitive' },
      rules: [{ pattern: /KEY/, klass: 'credential' }],
      fallback: 'plain',
    });

    expect(compiled.classify('API_KEY')).toBe('sensitive');
  });

  it('matches names and never values', () => {
    const compiled = compileEnvSpec({
      rules: [{ pattern: new RegExp(CANARY), klass: 'credential' }],
      fallback: 'plain',
    });

    // The pattern matches the canary. A variable whose *value* is the canary is
    // still plain, because classification never reads a value.
    expect(compiled.classify('SOME_NAME')).toBe('plain');
    expect(compiled.classify(CANARY)).toBe('credential');
  });

  it('rejects a rule whose pattern is not a RegExp', () => {
    expect(() =>
      compileEnvSpec({
        rules: [{ pattern: 'PASSWORD' as unknown as RegExp, klass: 'credential' }],
        fallback: 'plain',
      })
    ).toThrow(/must be a RegExp/);
  });

  it('rejects an unknown class', () => {
    expect(() => compileEnvSpec({ fields: { X: 'secret' as never }, fallback: 'plain' })).toThrow(
      /Invalid classification/
    );
  });
});

describe('commonSecretNameRules', () => {
  const compiled = compileEnvSpec({ rules: commonSecretNameRules, fallback: 'plain' });

  it.each([
    'PASSWORD',
    'DB_PASSWORD',
    'APP_SECRET',
    'CLIENT_SECRET',
    'JWT_SECRET',
    'GITHUB_TOKEN',
    'CSRF_TOKEN',
    'NPM_TOKEN',
    'SSH_PRIVATE_KEY',
    'API_KEY',
    'APIKEY',
    'STRIPE_API_KEY',
    'ENCRYPTION_KEY',
    'SIGNING_KEY',
    'MASTER_KEY',
    'DOCKER_CREDENTIALS',
    'SENTRY_DSN',
    'DATABASE_URL',
    'AZURE_CONNECTION_STRING',
  ])('classifies %s as a credential', (name) => {
    expect(compiled.classify(name)).toBe('credential');
  });

  /**
   * The shapes an earlier draft of this pack missed, each for a different
   * reason and each a name a real deployment sets. Asserted separately from the
   * list above, because they are why the patterns are shaped the way they are:
   * a keyword that has to end the name but does not have to be preceded by a
   * separator.
   */
  it.each([
    ['PGPASSWORD', 'the prefix runs into the keyword'],
    ['MYSQLPASSWORD', 'the same, for a different driver'],
    ['MYSQL_PWD', 'PWD is a keyword, but only after a separator'],
    ['AWS_SECRET_ACCESS_KEY', 'the qualifier is not the segment before KEY'],
    ['REDIS_AUTH', 'AUTH carries the credential itself'],
  ])('reaches %s, where %s', (name) => {
    expect(compiled.classify(name)).toBe('credential');
  });

  it.each([
    'PATH',
    'HOME',
    'NODE_ENV',
    'TZ',
    'PORT',
    'LOG_LEVEL',
    'HOSTNAME',
    'LANG',
    'SHLVL',
    'TERM',
  ])('leaves the shell variable %s plain', (name) => {
    expect(compiled.classify(name)).toBe('plain');
  });

  /**
   * The false positives that matter: names whose *shape* is secret and whose
   * *value* is not. Wrapping one of these does not fail loudly, it fails as the
   * truthiness bug. An instance is an object, so `if (authEnabled)` is
   * permanently true and `port === '3000'` is permanently false.
   */
  it.each([
    ['PWD', 'every shell sets it, and it holds the working directory'],
    ['OLDPWD', 'the same'],
    ['PASSWORD_POLICY', 'the keyword is not last'],
    ['PASSWORD_MIN_LENGTH', 'the keyword is not last'],
    ['SECRET_NAME', 'the name of a secret is not the secret'],
    ['SECRET_MANAGER_PROJECT', 'the keyword is not last'],
    ['TOKEN_URL', 'where to get one, not one'],
    ['TOKEN_TTL', 'a duration'],
    ['API_KEY_HEADER', 'the header name, not the key'],
    ['API_KEY_ID', 'the identifier, not the key'],
    ['AWS_ACCESS_KEY_ID', 'the identifier, which AWS pairs with the secret one'],
    ['AUTH_URL', 'an endpoint'],
    ['AUTH_ENABLED', 'a flag, and the one this bug is worst in'],
    ['PUBLIC_KEY', 'a key, and not a secret one'],
    ['PRIVATE_KEY_PATH', 'a path to a key'],
    ['KEY_ALGORITHM', 'a name'],
    ['KEYCLOAK_URL', 'an endpoint that happens to start with KEY'],
    ['DATABASE_URL_POOL_SIZE', 'a number'],
    ['CREDENTIALS_FILE', 'a path'],
    ['ENCRYPTION_ALGORITHM', 'a name'],
  ])('leaves %s plain, because it is %s', (name) => {
    expect(compiled.classify(name)).toBe('plain');
  });

  /**
   * Shapes the pack deliberately does not reach, pinned so that widening it
   * further is a deliberate act rather than a side effect. Nothing in either
   * name distinguishes it from an ordinary variable: `PRIVATE_KEY_PEM` has the
   * same shape as `PRIVATE_KEY_PATH`, which is a path.
   */
  it.each([['PRIVATE_KEY_PEM'], ['SSH_KEY']])(
    'does not reach %s, which the README says to name in `fields`',
    (name) => {
      expect(compiled.classify(name)).toBe('plain');
    }
  );

  /**
   * A whole-environment check rather than a name-at-a-time one. The pack is a
   * guess, and the number worth bounding is how much of an ordinary environment
   * it would take.
   */
  it('wraps nothing in a realistic environment of ordinary variables', () => {
    const ordinary = [
      'PATH',
      'HOME',
      'USER',
      'SHELL',
      'PWD',
      'OLDPWD',
      'SHLVL',
      'TERM',
      'LANG',
      'LC_ALL',
      'TZ',
      'TMPDIR',
      'EDITOR',
      'PAGER',
      'HOSTNAME',
      'NODE_ENV',
      'NODE_OPTIONS',
      'npm_config_registry',
      'PORT',
      'HOST',
      'LOG_LEVEL',
      'LOG_FORMAT',
      'DEBUG',
      'CI',
      'GITHUB_ACTIONS',
      'DB_HOST',
      'DB_PORT',
      'DB_NAME',
      'DB_USER',
      'REDIS_HOST',
      'REDIS_PORT',
      'AWS_REGION',
      'AWS_ACCESS_KEY_ID',
      'AWS_DEFAULT_OUTPUT',
      'KUBERNETES_SERVICE_HOST',
      'OTEL_EXPORTER_OTLP_ENDPOINT',
      'SENTRY_ENVIRONMENT',
      'SENTRY_RELEASE',
    ];

    expect(ordinary.filter((name) => compiled.classify(name) !== 'plain')).toEqual([]);
  });

  it('does not run unless the caller asks for it', () => {
    const withoutRules = compileEnvSpec({ fallback: 'plain' });

    expect(withoutRules.classify('DB_PASSWORD')).toBe('plain');
  });

  it('has no pattern that safe-regex2 rejects', () => {
    for (const rule of commonSecretNameRules) {
      expect(safeRegex(rule.pattern), String(rule.pattern)).toBe(true);
    }
  });

  it('is frozen, so one caller cannot edit the pack for every other', () => {
    expect(Object.isFrozen(commonSecretNameRules)).toBe(true);
  });
});

describe('envLabel', () => {
  it('defaults to the variable name', () => {
    expect(envLabel({ fallback: 'plain' }, 'DB_PASSWORD')).toBe('DB_PASSWORD');
  });

  it('uses the caller function when one is given', () => {
    expect(envLabel({ fallback: 'plain', label: (n) => n.toLowerCase() }, 'DB_PASSWORD')).toBe(
      'db_password'
    );
  });
});

describe('emptyCounts', () => {
  it('has a number for every class, so a report never reads undefined', () => {
    expect(emptyCounts()).toEqual({ credential: 0, sensitive: 0, plain: 0 });
  });
});
