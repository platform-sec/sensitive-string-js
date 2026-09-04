import { describe, it, expect } from 'vitest';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import {
  SecretNotFoundError,
  SecretPayloadError,
  describeLabelDisclosure,
} from '@platform-sec/sensitive-string-secrets';

import { crc32c } from './crc32c.js';
import {
  FakeSecretManager,
  PROJECT,
  gaxError,
  secretResource,
  source,
} from './__tests__/fake-client.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

function client(): FakeSecretManager {
  const base = `projects/${PROJECT}/secrets`;

  return FakeSecretManager.of({
    [`${base}/stripe-api-key/versions/latest`]: {
      value: CANARY,
      version: '7',
      secret: secretResource('stripe-api-key'),
    },
    [`${base}/stripe-api-key/versions/3`]: { value: CANARY, version: '3' },
    [`${base}/db-credentials/versions/latest`]: {
      value: JSON.stringify({ username: 'app', password: CANARY, port: 5432 }),
      version: '2',
    },
    [`${base}/expiring-key/versions/latest`]: {
      value: CANARY,
      secret: secretResource('expiring-key', {
        expireTime: { seconds: Math.floor(Date.now() / 1000) + 3600 },
      }),
    },
    [`${base}/rotating-key/versions/latest`]: {
      value: CANARY,
      secret: secretResource('rotating-key', {
        rotation: { nextRotationTime: { seconds: Math.floor(Date.now() / 1000) + 3600 } },
      }),
    },
    [`${base}/no-metadata-key/versions/latest`]: {
      value: CANARY,
      secret: gaxError(7, 'permission denied on resource'),
    },
    [`${base}/corrupt-key/versions/latest`]: {
      value: CANARY,
      crc: crc32c(Buffer.from('something else')),
    },
    [`${base}/unchecked-key/versions/latest`]: { value: CANARY, omitCrc: true },
    [`${base}/denied-key/versions/latest`]: { error: gaxError(7, 'permission denied') },
    [`${base}/destroyed-key/versions/latest`]: {
      error: gaxError(9, 'version is in DESTROYED state'),
    },
  });
}

describe('GcpSecretSource.get', () => {
  it('wraps a secret with the short name as its label', async () => {
    const record = await source(client()).get('stripe-api-key');

    expect(record.value).toBeInstanceOf(SensitiveString);
    expect(record.value.label).toBe('stripe-api-key');
    expect(record.value.reveal({ name: 'test' })).toBe(CANARY);
  });

  it('reports the version the server resolved rather than latest', async () => {
    const record = await source(client()).get('stripe-api-key');

    expect(record.ref.version).toBe('7');
  });

  it('puts the project on metadata rather than in the label', async () => {
    const record = await source(client()).get('stripe-api-key');

    expect(record.ref.metadata['project']).toBe(PROJECT);
    expect(describeLabelDisclosure(record.value.label ?? '')).toEqual([]);
  });

  it('requests the version a caller pinned', async () => {
    const fake = client();
    await source(fake).get({ path: 'stripe-api-key', version: '3' });

    expect(fake.requests[0]).toBe(`projects/${PROJECT}/secrets/stripe-api-key/versions/3`);
  });

  it('accepts a fully qualified resource name', async () => {
    const record = await source(client(), { project: undefined }).get(
      `projects/${PROJECT}/secrets/stripe-api-key`
    );

    expect(record.value.label).toBe('stripe-api-key');
  });
});

describe('the CRC32C check', () => {
  it('refuses a payload whose bytes do not match the checksum', async () => {
    const failure = await source(client())
      .get('corrupt-key')
      .catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(SecretPayloadError);
    expect((failure as Error).message).not.toContain(CANARY);
  });

  it('accepts a payload with no checksum by default', async () => {
    const record = await source(client()).get('unchecked-key');

    expect(record.value.reveal({ name: 'test' })).toBe(CANARY);
  });

  it('refuses a payload with no checksum when the deployment requires one', async () => {
    await expect(source(client(), { requireChecksum: true }).get('unchecked-key')).rejects.toThrow(
      /requires one/
    );
  });
});

describe('readExpiry', () => {
  it('is off by default, so a load costs one call', async () => {
    const fake = client();
    await source(fake).get('expiring-key');

    expect(fake.requests).toHaveLength(1);
  });

  it('binds expireTime as a deadline when asked for', async () => {
    const record = await source(client(), { readExpiry: true }).get('expiring-key');

    expect(record.value.expiresAt).toBeInstanceOf(Date);
    expect(record.value.ttlRemaining()).toBeGreaterThan(0);
  });

  it('records a rotation schedule and binds nothing from it', async () => {
    const record = await source(client(), { readExpiry: true }).get('rotating-key');

    expect(record.value.expiresAt).toBeUndefined();
    expect(record.ref.metadata['nextRotationAt']).toBeDefined();
  });

  it('loses the metadata rather than the secret when getSecret is denied', async () => {
    const record = await source(client(), { readExpiry: true }).get('no-metadata-key');

    expect(record.value.reveal({ name: 'test' })).toBe(CANARY);
    expect(record.ref.metadata['secretMetadata']).toBe('unavailable');
  });
});

describe('GcpSecretSource.getOptional', () => {
  it('returns null for an absent secret', async () => {
    expect(await source(client()).getOptional('missing-key')).toBeNull();
  });

  it('keeps throwing for an authorization failure', async () => {
    await expect(source(client()).getOptional('denied-key')).rejects.toThrow(/permission denied/);
  });

  it('keeps throwing for a destroyed version, which is not an absence', async () => {
    await expect(source(client()).getOptional('destroyed-key')).rejects.toThrow(/DESTROYED/);
  });

  it('reports absence through SecretNotFoundError on get', async () => {
    await expect(source(client()).get('missing-key')).rejects.toThrow(SecretNotFoundError);
  });
});

describe('GcpSecretSource.getJson', () => {
  it('wraps the declared fields of a JSON secret', async () => {
    const db = await source(client()).getJson('db-credentials', {
      fields: { username: 'sensitive', password: 'credential', port: 'plain' },
    });

    expect(db.fields.password.klass).toBe('credential');
    expect(db.fields.password.label).toBe('db-credentials#password');
    expect(db.fields.port).toBe(5432);
    expect(db.ref.version).toBe('2');
  });

  it('does not put the payload into an error when the secret is not JSON', async () => {
    const failure = await source(client())
      .getJson('stripe-api-key', { fields: { key: 'credential' } })
      .catch((error: unknown) => error);

    expect((failure as Error).message).not.toContain(CANARY);
  });
});

describe('the constructor', () => {
  it('refuses a client with no accessSecretVersion method', () => {
    expect(() => source({} as unknown as FakeSecretManager)).toThrow(/accessSecretVersion\(\)/);
  });
});
