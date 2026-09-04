import { describe, it, expect } from 'vitest';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import {
  SecretNotFoundError,
  SecretPayloadError,
  describeLabelDisclosure,
} from '@platform-sec/sensitive-string-secrets';

import {
  FakeTransport,
  PROJECT_ID,
  TEST_TOKEN,
  entry,
  secretsBody,
  source,
} from './__tests__/fake-transport.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

function transport(): FakeTransport {
  return FakeTransport.of({
    'prod/backend': {
      body: secretsBody(
        entry('LOG_LEVEL', 'info'),
        entry('STRIPE_SECRET_KEY', CANARY),
        entry('DATABASE_URL', CANARY)
      ),
    },
    'prod/': { body: secretsBody(entry('ROOT_KEY', CANARY)) },
    'staging/backend': { body: secretsBody(entry('API_KEY', CANARY)) },
    'prod/duplicated': {
      body: secretsBody(entry('API_KEY', CANARY), entry('API_KEY', 'from-an-import')),
    },
    'prod/keyless': { body: { secrets: [{ secretValue: CANARY }] } },
    'prod/shapeless': { body: { data: [] } },
    'prod/denied': { status: 403, messages: ['You do not have permission'] },
    'prod/broken': { status: 500, messages: ['Internal error'] },
  });
}

describe('InfisicalSecretSource.getAll', () => {
  it('turns the secrets array into a classified map', async () => {
    const config = await source(transport()).getAll('/backend', {
      rules: [{ pattern: /KEY|URL/i, klass: 'credential' }],
      fallback: 'plain',
    });

    expect(config.fields.get('STRIPE_SECRET_KEY')).toBeInstanceOf(SensitiveString);
    expect(config.fields.get('DATABASE_URL')?.klass).toBe('credential');
    expect(config.plain.get('LOG_LEVEL')).toBe('info');
  });

  it('labels by environment and path, and leaves the project id off', async () => {
    const config = await source(transport()).getAll('/backend', { fallback: 'credential' });
    const label = config.fields.get('STRIPE_SECRET_KEY')?.label ?? '';

    expect(label).toBe('prod/backend#STRIPE_SECRET_KEY');
    expect(label).not.toContain(PROJECT_ID);
    expect(describeLabelDisclosure(label)).toEqual([]);
  });

  it('puts the project id on metadata, where the load hook sees it', async () => {
    const config = await source(transport()).getAll('/backend', { fallback: 'credential' });

    expect(config.ref.metadata['projectId']).toBe(PROJECT_ID);
    expect(config.ref.metadata['environment']).toBe('prod');
    expect(config.ref.metadata['secretPath']).toBe('/backend');
  });

  it('scopes the request the way Infisical scopes a read', async () => {
    const fake = transport();
    await source(fake).getAll('/backend', { fallback: 'credential' });

    expect(fake.requests[0]?.query).toMatchObject({
      workspaceId: PROJECT_ID,
      environment: 'prod',
      secretPath: '/backend',
      include_imports: 'false',
    });
  });

  it('reads the root folder', async () => {
    const config = await source(transport()).getAll('/', { fallback: 'credential' });

    expect(config.fields.get('ROOT_KEY')?.reveal({ name: 'test' })).toBe(CANARY);
    expect(config.ref.path).toBe('prod');
  });

  it('takes an environment/path ref where none is configured', async () => {
    const fake = transport();
    const config = await source(fake, { environment: undefined }).getAll('staging/backend', {
      fallback: 'credential',
    });

    expect(fake.requests[0]?.query).toMatchObject({
      environment: 'staging',
      secretPath: '/backend',
    });
    expect(config.ref.path).toBe('staging/backend');
  });

  it('says what is missing when there is no environment at all', async () => {
    await expect(
      source(transport(), { environment: undefined }).getAll('', { fallback: 'credential' })
    ).rejects.toThrow();
  });

  it('says what is missing when there is no project id', async () => {
    await expect(
      source(transport(), { projectId: undefined }).getAll('/backend', {
        fallback: 'credential',
      })
    ).rejects.toThrow(/needs a projectId/);
  });

  it('can be told to include imported folders', async () => {
    const fake = transport();
    await source(fake, { includeImports: true }).getAll('/backend', { fallback: 'credential' });

    expect(fake.requests[0]?.query['include_imports']).toBe('true');
  });
});

describe('the secrets array', () => {
  it('refuses a duplicate key rather than picking one', async () => {
    // An import overlapping the folder. Picking one would mean reading a value
    // from a folder this classification never described.
    const failure = await source(transport())
      .getAll('/duplicated', { fallback: 'credential' })
      .catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(SecretPayloadError);
    expect((failure as Error).message).toContain('twice');
    expect((failure as Error).message).not.toContain(CANARY);
  });

  it('refuses an entry with no key', async () => {
    await expect(
      source(transport()).getAll('/keyless', { fallback: 'credential' })
    ).rejects.toThrow(/no secretKey/);
  });

  it('refuses a body with no secrets array', async () => {
    await expect(
      source(transport()).getAll('/shapeless', { fallback: 'credential' })
    ).rejects.toThrow(/no 'secrets' array/);
  });
});

describe('InfisicalSecretSource.getOptional', () => {
  it('returns null for an absent folder', async () => {
    expect(await source(transport()).getOptional('/missing')).toBeNull();
  });

  it('keeps throwing for a token without permission', async () => {
    await expect(source(transport()).getOptional('/denied')).rejects.toThrow(
      /do not have permission/
    );
  });

  it('reports absence through SecretNotFoundError on getAll', async () => {
    await expect(
      source(transport()).getAll('/missing', { fallback: 'credential' })
    ).rejects.toThrow(SecretNotFoundError);
  });
});

describe('the token', () => {
  it('must be a SensitiveString', () => {
    expect(() => source(transport(), { token: TEST_TOKEN as never })).toThrow(
      /needs the token as a SensitiveString/
    );
  });

  it('is sent as a bearer token', async () => {
    const fake = transport();
    await source(fake).getAll('/backend', { fallback: 'credential' });

    expect(fake.requests[0]?.headers['authorization']).toBe(`Bearer ${TEST_TOKEN}`);
  });
});
