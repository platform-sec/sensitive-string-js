import { describe, it, expect } from 'vitest';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import {
  SecretNotFoundError,
  SecretPayloadError,
  describeLabelDisclosure,
} from '@platform-sec/sensitive-string-secrets';

import {
  FakeSecretsClient,
  SECRET_OCID,
  VAULT_ID,
  ociError,
  source,
} from './__tests__/fake-client.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';
const FUTURE = new Date(Date.now() + 3_600_000);

function client(): FakeSecretsClient {
  return FakeSecretsClient.of({
    'prod-stripe-key': { value: CANARY },
    'prod-db': { value: JSON.stringify({ username: 'app', password: CANARY, port: 1521 }) },
    'expiring-key': { value: CANARY, timeOfExpiry: FUTURE },
    'deleting-key': { value: CANARY, timeOfDeletion: FUTURE },
    'plaintext-key': { value: CANARY, contentType: 'PLAINTEXT' },
    'denied-key': { error: ociError(401, 'NotAuthenticated') },
    'broken-key': { error: ociError(500, 'InternalServerError') },
    [SECRET_OCID]: { value: CANARY },
  });
}

describe('OciSecretSource.get', () => {
  it('wraps a secret with the name as its label', async () => {
    const record = await source(client()).get('prod-stripe-key');

    expect(record.value).toBeInstanceOf(SensitiveString);
    expect(record.value.label).toBe('prod-stripe-key');
    expect(record.value.reveal({ name: 'test' })).toBe(CANARY);
  });

  it('reports the concrete version number', async () => {
    const record = await source(client()).get('prod-stripe-key');

    expect(record.ref.version).toBe('4');
  });

  it('resolves a name against the configured vault', async () => {
    const fake = client();
    await source(fake).get('prod-stripe-key');

    expect(fake.requests[0]).toMatchObject({ secretName: 'prod-stripe-key', vaultId: VAULT_ID });
  });

  it('routes a stage, a number and a version name to their own request fields', async () => {
    const fake = client();
    const oci = source(fake);

    await oci.get({ path: 'prod-stripe-key', version: 'PREVIOUS' });
    await oci.get({ path: 'prod-stripe-key', version: '2' });
    await oci.get({ path: 'prod-stripe-key', version: 'release-2026-09' });

    expect(fake.requests[0]).toMatchObject({ stage: 'PREVIOUS' });
    expect(fake.requests[1]).toMatchObject({ versionNumber: 2 });
    expect(fake.requests[2]).toMatchObject({ secretVersionName: 'release-2026-09' });
  });

  it('says which client is the read path when the wrong one is passed', () => {
    expect(() => source({} as unknown as FakeSecretsClient)).toThrow(/VaultsClient manages/);
  });

  it('says what is missing when a name has no vault to resolve against', async () => {
    await expect(source(client(), { vaultId: undefined }).get('prod-stripe-key')).rejects.toThrow(
      /needs a vaultId/
    );
  });
});

describe('reading by OCID', () => {
  it('refuses to derive a label from an OCID', async () => {
    // A label appears in every log line the value reaches, and an OCID encodes
    // the tenancy, the region and the realm.
    await expect(source(client()).get(SECRET_OCID)).rejects.toThrow(/cannot become a label/);
  });

  it('works when the caller supplies a label of their own', async () => {
    const record = await source(client()).get(SECRET_OCID, { label: 'prod-stripe-key' });

    expect(record.value.reveal({ name: 'test' })).toBe(CANARY);
    expect(record.value.label).toBe('prod-stripe-key');
    expect(describeLabelDisclosure(record.value.label ?? '')).toEqual([]);
  });

  it('uses the data plane read by secret id', async () => {
    const fake = client();
    await source(fake).get(SECRET_OCID, { label: 'prod-stripe-key' });

    expect(fake.requests[0]).toMatchObject({ secretId: SECRET_OCID });
  });

  it('keeps the OCID out of the resolved path, where an error message would find it', async () => {
    const record = await source(client()).get(SECRET_OCID, { label: 'prod-stripe-key' });

    expect(record.ref.path).not.toContain('ocid1');
    expect(record.ref.metadata['secretId']).toBe(SECRET_OCID);
  });
});

describe('lifetime', () => {
  it('binds timeOfExpiry as a deadline', async () => {
    const record = await source(client()).get('expiring-key');

    expect(record.value.expiresAt).toEqual(FUTURE);
  });

  it('binds nothing from timeOfDeletion, since a secret pending deletion still works', async () => {
    const record = await source(client()).get('deleting-key');

    expect(record.value.expiresAt).toBeUndefined();
    expect(record.ref.metadata['deletionAt']).toBe(FUTURE.toISOString());
  });
});

describe('OciSecretSource.getOptional', () => {
  it('returns null for an absent secret', async () => {
    expect(await source(client()).getOptional('missing-key')).toBeNull();
  });

  it('keeps throwing for an authentication failure', async () => {
    await expect(source(client()).getOptional('denied-key')).rejects.toThrow(/NotAuthenticated/);
  });

  it('reports absence through SecretNotFoundError on get', async () => {
    await expect(source(client()).get('missing-key')).rejects.toThrow(SecretNotFoundError);
  });
});

describe('OciSecretSource.getJson', () => {
  it('wraps the declared fields of a JSON secret', async () => {
    const db = await source(client()).getJson('prod-db', {
      fields: { username: 'sensitive', password: 'credential', port: 'plain' },
    });

    expect(db.fields.password.klass).toBe('credential');
    expect(db.fields.password.label).toBe('prod-db#password');
    expect(db.fields.port).toBe(1521);
  });
});

describe('an unrecognized content type', () => {
  it('fails the read rather than decoding as base64', async () => {
    await expect(source(client()).get('plaintext-key')).rejects.toThrow(SecretPayloadError);
  });
});
