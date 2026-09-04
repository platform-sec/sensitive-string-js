import { describe, it, expect } from 'vitest';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import {
  SecretNotFoundError,
  SecretPayloadError,
  describeLabelDisclosure,
} from '@platform-sec/sensitive-string-secrets';
import type { SecretLoadEvent } from '@platform-sec/sensitive-string-secrets';

import {
  ACCOUNT,
  FakeSecretsManager,
  arnFor,
  awsError,
  describeResponse,
  getResponse,
  source,
} from './__tests__/fake-client.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

function client(): FakeSecretsManager {
  return FakeSecretsManager.of({
    'prod/db': {
      get: getResponse('prod/db', {
        SecretString: JSON.stringify({
          username: 'app',
          password: CANARY,
          host: 'db.internal',
          port: 5432,
        }),
      }),
      describe: describeResponse('prod/db'),
    },
    'prod/stripe': { get: getResponse('prod/stripe', { SecretString: CANARY }) },
    'prod/binary': {
      get: getResponse('prod/binary', { SecretBinary: new TextEncoder().encode(CANARY) }),
    },
    'prod/empty': { get: getResponse('prod/empty') },
    'prod/denied': { get: awsError('AccessDeniedException', 'not authorized') },
    'prod/deleting': {
      get: awsError('InvalidRequestException', 'marked for deletion'),
    },
    [arnFor('prod/db')]: {
      get: getResponse('prod/db', { SecretString: JSON.stringify({ password: CANARY }) }),
    },
  });
}

describe('AwsSecretSource.get', () => {
  it('wraps a single-value secret with the name as its label', async () => {
    const record = await source(client()).get('prod/stripe');

    expect(record.value).toBeInstanceOf(SensitiveString);
    expect(record.value.label).toBe('prod/stripe');
    expect(record.value.reveal({ name: 'test' })).toBe(CANARY);
  });

  it('reports the version id rather than the stage that was asked for', async () => {
    const record = await source(client()).get({ path: 'prod/stripe', version: 'AWSCURRENT' });

    expect(record.ref.version).toBe('b9b1f2c4-4a2f-4a6b-9a1d-0f6a3c2b7e11');
  });

  it('sends a staging label as VersionStage and a uuid as VersionId', async () => {
    const fake = client();
    const aws = source(fake);

    await aws.get({ path: 'prod/stripe', version: 'AWSPREVIOUS' });
    await aws.get({ path: 'prod/stripe', version: 'b9b1f2c4-4a2f-4a6b-9a1d-0f6a3c2b7e11' });

    expect(fake.commands[0]?.input).toMatchObject({ VersionStage: 'AWSPREVIOUS' });
    expect(fake.commands[1]?.input).toMatchObject({
      VersionId: 'b9b1f2c4-4a2f-4a6b-9a1d-0f6a3c2b7e11',
    });
  });

  it('decodes a SecretBinary secret', async () => {
    const record = await source(client()).get('prod/binary');

    expect(record.value.reveal({ name: 'test' })).toBe(CANARY);
  });

  it('refuses a response that carried neither field', async () => {
    await expect(source(client()).get('prod/empty')).rejects.toThrow(SecretPayloadError);
  });

  it('accepts an ARN and still labels by the name', async () => {
    const record = await source(client()).get(arnFor('prod/db'));

    expect(record.value.label).toBe('prod/db-AbCdEf');
    expect(record.value.label).not.toContain(ACCOUNT);
  });
});

describe('AwsSecretSource.getOptional', () => {
  it('returns null for an absent secret', async () => {
    expect(await source(client()).getOptional('prod/missing')).toBeNull();
  });

  it('keeps throwing for an authorization failure', async () => {
    await expect(source(client()).getOptional('prod/denied')).rejects.toThrow(/not authorized/);
  });

  it('keeps throwing for a secret scheduled for deletion', async () => {
    // The secret exists. Reporting it as absent would hide a deployment
    // mistake behind a null that looks like an ordinary missing secret.
    await expect(source(client()).getOptional('prod/deleting')).rejects.toThrow(
      /marked for deletion/
    );
  });

  it('reports absence through SecretNotFoundError on get', async () => {
    await expect(source(client()).get('prod/missing')).rejects.toThrow(SecretNotFoundError);
  });
});

describe('AwsSecretSource.getJson', () => {
  it('wraps the declared fields and leaves the plain ones alone', async () => {
    const db = await source(client()).getJson('prod/db', {
      fields: {
        username: 'sensitive',
        password: 'credential',
        host: 'plain',
        port: 'plain',
      },
    });

    expect(db.fields.password).toBeInstanceOf(SensitiveString);
    expect(db.fields.password.klass).toBe('credential');
    expect(db.fields.username.klass).toBe('sensitive');
    expect(db.fields.host).toBe('db.internal');
    expect(db.fields.port).toBe(5432);
  });

  it('labels each field under the secret name', async () => {
    const db = await source(client()).getJson('prod/db', { fields: { password: 'credential' } });

    expect(db.fields.password.label).toBe('prod/db#password');
    expect(describeLabelDisclosure(db.fields.password.label ?? '')).toEqual([]);
  });

  it('does not put the payload into an error when the secret is not JSON', async () => {
    const failure = await source(client())
      .getJson('prod/stripe', { fields: { password: 'credential' } })
      .catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(SecretPayloadError);
    expect((failure as Error).message).not.toContain(CANARY);
    expect((failure as { cause?: unknown }).cause).toBeUndefined();
  });
});

describe('AwsSecretSource.getAll', () => {
  it('classifies by rule over a discovered key set', async () => {
    const all = await source(client()).getAll('prod/db', {
      rules: [{ pattern: /password/i, klass: 'credential' }],
      fallback: 'plain',
    });

    expect(all.fields.get('password')?.klass).toBe('credential');
    expect(all.plain.get('host')).toBe('db.internal');
    expect(all.keys).toEqual(['username', 'password', 'host', 'port']);
  });
});

describe('rotation metadata', () => {
  it('is off by default, so a load costs one call', async () => {
    const fake = client();
    await source(fake).get('prod/stripe');

    expect(fake.commands.filter((command) => command.kind === 'describe')).toHaveLength(0);
  });

  it('is recorded on the resolved ref when asked for, and binds no deadline', async () => {
    const record = await source(client(), { readRotation: true }).getJson('prod/db', {
      fields: { password: 'credential' },
    });

    expect(record.ref.metadata['rotationEnabled']).toBe(true);
    expect(record.ref.metadata['nextRotationAt']).toBe('2026-10-01T00:00:00.000Z');
    expect(record.fields.password.expiresAt).toBeUndefined();
  });

  it('does not fail the read when DescribeSecret is denied', async () => {
    const fake = FakeSecretsManager.of({
      'prod/stripe': {
        get: getResponse('prod/stripe', { SecretString: CANARY }),
        describe: awsError('AccessDeniedException', 'not authorized'),
      },
    });

    const record = await source(fake, { readRotation: true }).get('prod/stripe');

    expect(record.value.reveal({ name: 'test' })).toBe(CANARY);
    expect(record.ref.metadata['rotationMetadata']).toBe('unavailable');
  });
});

describe('load events', () => {
  it('carry the resolved version and no secret material', async () => {
    const events: SecretLoadEvent[] = [];
    await source(client(), { onLoad: (event) => events.push(event) }).getAll('prod/db', {
      fallback: 'credential',
    });

    expect(events).toHaveLength(1);
    expect(events[0]?.ref.version).toBe('b9b1f2c4-4a2f-4a6b-9a1d-0f6a3c2b7e11');
    expect(JSON.stringify(events)).not.toContain(CANARY);
  });
});

describe('the constructor', () => {
  it('refuses a client with no send method', () => {
    expect(() => source({} as unknown as FakeSecretsManager)).toThrow(/send\(\)/);
  });
});
