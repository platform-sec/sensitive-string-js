import { describe, it, expect } from 'vitest';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import {
  SecretNotFoundError,
  SecretPayloadError,
  describeLabelDisclosure,
} from '@platform-sec/sensitive-string-secrets';

import { SecretNotYetValidError } from './wire.js';
import { FakeSecretClient, VAULT_URL, azureError, source } from './__tests__/fake-client.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';
const FUTURE = new Date(Date.now() + 86_400_000);
const PAST = new Date(Date.now() - 86_400_000);

function client(): FakeSecretClient {
  return FakeSecretClient.of({
    'payments-api-key': { value: CANARY },
    'db-credentials': {
      value: JSON.stringify({ username: 'app', password: CANARY, port: 5432 }),
      properties: { contentType: 'application/json' },
    },
    'expiring-key': { value: CANARY, properties: { expiresOn: FUTURE } },
    'expired-key': { value: CANARY, properties: { expiresOn: PAST } },
    'future-key': { value: CANARY, properties: { notBefore: FUTURE } },
    'valueless-key': {},
    'denied-key': { error: azureError(403, 'Forbidden', 'caller is not authorized') },
    'broken-key': { error: azureError(500, 'InternalServerError', 'an internal error') },
  });
}

describe('AzureSecretSource.get', () => {
  it('wraps a secret with the name as its label', async () => {
    const record = await source(client()).get('payments-api-key');

    expect(record.value).toBeInstanceOf(SensitiveString);
    expect(record.value.label).toBe('payments-api-key');
    expect(record.value.reveal({ name: 'test' })).toBe(CANARY);
  });

  it('reports the concrete version', async () => {
    const record = await source(client()).get('payments-api-key');

    expect(record.ref.version).toBe('c81f2a1e5b2c4d3e9f0a1b2c3d4e5f60');
  });

  it('accepts a full secret identifier and labels by the name alone', async () => {
    const record = await source(client()).get(`${VAULT_URL}/secrets/payments-api-key`);

    expect(record.value.label).toBe('payments-api-key');
    expect(describeLabelDisclosure(record.value.label ?? '')).toEqual([]);
  });

  it('honours a version pinned in the identifier', async () => {
    const fake = client();
    await source(fake).get(`${VAULT_URL}/secrets/payments-api-key/abc123`);

    expect(fake.calls[0]).toEqual({ name: 'payments-api-key', version: 'abc123' });
  });

  it('lets an explicit version win over one in the identifier', async () => {
    const fake = client();
    await source(fake).get({ path: `${VAULT_URL}/secrets/payments-api-key/abc123`, version: 'v2' });

    expect(fake.calls[0]).toEqual({ name: 'payments-api-key', version: 'v2' });
  });

  it('puts the vault URL on metadata rather than in the label', async () => {
    const record = await source(client()).get('payments-api-key');

    expect(record.ref.metadata['vaultUrl']).toBe(VAULT_URL);
    expect(String(record.value)).not.toContain('contoso');
  });
});

describe('expiresOn', () => {
  it('becomes the instance deadline', async () => {
    const record = await source(client()).get('expiring-key');

    expect(record.value.expiresAt).toEqual(FUTURE);
    expect(record.value.ttlRemaining()).toBeGreaterThan(0);
  });

  it('makes a secret past its expiry refuse to reveal, which the provider may not', async () => {
    const record = await source(client()).get('expired-key');

    expect(record.value.isExpired()).toBe(true);
    expect(() => record.value.reveal({ name: 'test' })).toThrow();
  });

  it('binds nothing under honorExpiresOn: false, and still records the date', async () => {
    const record = await source(client(), { honorExpiresOn: false }).get('expired-key');

    expect(record.value.expiresAt).toBeUndefined();
    expect(record.value.reveal({ name: 'test' })).toBe(CANARY);
    expect(record.ref.metadata['expiresAt']).toBe(PAST.toISOString());
  });
});

describe('notBefore', () => {
  it('refuses a future-dated secret rather than handing back a value that will not work', async () => {
    await expect(source(client()).get('future-key')).rejects.toThrow(SecretNotYetValidError);
  });

  it('can be turned off for a deployment that would rather have the value', async () => {
    const record = await source(client(), { honorNotBefore: false }).get('future-key');

    expect(record.value.reveal({ name: 'test' })).toBe(CANARY);
  });
});

describe('AzureSecretSource.getOptional', () => {
  it('returns null for an absent secret', async () => {
    expect(await source(client()).getOptional('missing-key')).toBeNull();
  });

  it('returns null for a successful response carrying no value', async () => {
    // A real state rather than an impossible one, so it is an absence rather
    // than a non-null assertion waiting to throw.
    expect(await source(client()).getOptional('valueless-key')).toBeNull();
  });

  it('keeps throwing for an authorization failure', async () => {
    await expect(source(client()).getOptional('denied-key')).rejects.toThrow(/not authorized/);
  });

  it('keeps throwing for a server failure', async () => {
    await expect(source(client()).getOptional('broken-key')).rejects.toThrow(/internal error/);
  });

  it('reports absence through SecretNotFoundError on get', async () => {
    await expect(source(client()).get('missing-key')).rejects.toThrow(SecretNotFoundError);
  });
});

describe('AzureSecretSource.getJson', () => {
  it('wraps the declared fields of a JSON secret', async () => {
    const db = await source(client()).getJson('db-credentials', {
      fields: { username: 'sensitive', password: 'credential', port: 'plain' },
    });

    expect(db.fields.password.klass).toBe('credential');
    expect(db.fields.password.label).toBe('db-credentials#password');
    expect(db.fields.port).toBe(5432);
  });

  it('does not act on contentType, so a portal edit cannot change what code does', async () => {
    // `application/json` on the secret is a convention that says getJson is the
    // right read. It stays a convention: `get` still returns the whole string.
    const record = await source(client()).get('db-credentials');

    expect(record.value.reveal({ name: 'test' })).toContain('"password"');
    expect(record.ref.metadata['contentType']).toBe('application/json');
  });

  it('does not put the payload into an error when the secret is not JSON', async () => {
    const failure = await source(client())
      .getJson('payments-api-key', { fields: { password: 'credential' } })
      .catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(SecretPayloadError);
    expect((failure as Error).message).not.toContain(CANARY);
  });
});

describe('the constructor', () => {
  it('refuses a client with no getSecret method', () => {
    expect(() => source({} as unknown as FakeSecretClient)).toThrow(/getSecret\(\)/);
  });
});
