import { describe, it, expect, beforeAll } from 'vitest';
import {
  CreateSecretCommand,
  PutSecretValueCommand,
  SecretsManagerClient,
} from '@aws-sdk/client-secrets-manager';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import {
  SecretNotFoundError,
  describeLabelDisclosure,
} from '@platform-sec/sensitive-string-secrets';
import { assertNoCanary } from '@platform-sec/sensitive-string-secrets/testing';

import { AwsSecretSource } from '../source.js';

/**
 * The second tier: a Secrets Manager API rather than a fixture.
 *
 * `AWS_SECRETS_ENDPOINT` points it at an emulator, which is what CI runs, and
 * an emulator is not AWS. What this tier is worth is the client-side half:
 * every assertion here goes through the real `@aws-sdk/client-secrets-manager`
 * request and response pipeline, so the command construction, the version
 * routing and the exception name are the SDK's rather than this package's
 * guesses about them. It is also what proved that a `VersionId` really is a
 * UUID, which is what the `version` slot routing depends on.
 *
 * Skipped unless `AWS_SECRETS_ENDPOINT` is set. CI runs it with
 * `continue-on-error: true`.
 */

const ENDPOINT = process.env['AWS_SECRETS_ENDPOINT'];
const CANARY = 'LEAKED_SECRET_abc123xyz';

let client: SecretsManagerClient;
let source: AwsSecretSource;
let previousVersionId: string;

describe.skipIf(ENDPOINT === undefined)('aws secrets manager, against a live API', () => {
  beforeAll(async () => {
    client = new SecretsManagerClient({
      region: process.env['AWS_REGION'] ?? 'us-east-1',
      endpoint: ENDPOINT ?? '',
      credentials: { accessKeyId: 'test', secretAccessKey: 'test' },
    });

    source = new AwsSecretSource({ client, cache: { ttl: 0 } });

    await create(
      'live/db',
      JSON.stringify({ username: 'app', password: CANARY, host: 'db.internal', port: 5432 })
    );
    await create('live/stripe', `${CANARY}-v1`);

    const rotated = await client.send(
      new PutSecretValueCommand({ SecretId: 'live/stripe', SecretString: `${CANARY}-v2` })
    );

    // The previous version is the one the rotation displaced, which is what
    // `AWSPREVIOUS` now points at.
    previousVersionId = rotated.VersionId ?? '';
  });

  async function create(name: string, value: string): Promise<void> {
    try {
      await client.send(new CreateSecretCommand({ Name: name, SecretString: value }));
    } catch (error) {
      if (!(error instanceof Error) || error.name !== 'ResourceExistsException') {
        throw error;
      }
    }
  }

  it('wraps a single-value secret with the name as its label', async () => {
    const record = await source.get('live/stripe');

    expect(record.value).toBeInstanceOf(SensitiveString);
    expect(record.value.label).toBe('live/stripe');
    expect(record.value.reveal({ name: 'live' })).toBe(`${CANARY}-v2`);
  });

  it('reports a version id that is a UUID, which is what the version routing rests on', async () => {
    const record = await source.get('live/stripe');

    expect(record.ref.version).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
    );
    expect(record.ref.version).toBe(previousVersionId);
  });

  it('resolves a staging label to a different concrete version', async () => {
    // The rule this row works to: an audit trail that records `AWSCURRENT` for
    // two reads cannot tell them apart.
    const current = await source.get({ path: 'live/stripe', version: 'AWSCURRENT' });
    const previous = await source.get({ path: 'live/stripe', version: 'AWSPREVIOUS' });

    expect(current.ref.version).not.toBe(previous.ref.version);
    expect(previous.value.reveal({ name: 'live' })).toBe(`${CANARY}-v1`);
  });

  it('records the staging labels on metadata', async () => {
    const record = await source.get('live/stripe');

    expect(record.ref.metadata['versionStages']).toContain('AWSCURRENT');
  });

  it('keeps the ARN off the label and on metadata', async () => {
    const record = await source.get('live/stripe');
    const arn = String(record.ref.metadata['arn'] ?? '');

    expect(arn).toMatch(/^arn:aws:secretsmanager:/);
    expect(record.value.label).not.toContain('arn:');
    expect(describeLabelDisclosure(record.value.label ?? '')).toEqual([]);
  });

  it('accepts a full ARN and still labels by the name', async () => {
    const first = await source.get('live/stripe');
    const arn = String(first.ref.metadata['arn'] ?? '');

    const byArn = await source.get(arn);

    expect(byArn.ref.path).toBe('live/stripe');
    expect(byArn.value.label).not.toContain('arn:');
  });

  it('wraps the declared fields of a JSON secret', async () => {
    const db = await source.getJson('live/db', {
      fields: { username: 'sensitive', password: 'credential', host: 'plain', port: 'plain' },
    });

    expect(db.fields.password.reveal({ name: 'live' })).toBe(CANARY);
    expect(db.fields.host).toBe('db.internal');
    expect(db.fields.port).toBe(5432);
  });

  it('reports an absent secret as absent and names the exception this package matches', async () => {
    expect(await source.getOptional('live/definitely-not-a-secret')).toBeNull();
    await expect(source.get('live/definitely-not-a-secret')).rejects.toThrow(SecretNotFoundError);
  });

  it('does not put the payload into an error when the secret is not JSON', async () => {
    const failure = await source
      .getJson('live/stripe', { fields: { password: 'credential' } })
      .catch((error: unknown) => error);

    expect((failure as Error).message).not.toContain(CANARY);
    expect((failure as { cause?: unknown }).cause).toBeUndefined();
  });

  it('leaks no secret material into a load event', async () => {
    const events: unknown[] = [];
    const audited = new AwsSecretSource({
      client,
      cache: { ttl: 0 },
      readRotation: true,
      onLoad: (event) => events.push(event),
    });

    await audited.getAll('live/db', { fallback: 'credential' });
    await audited.get('live/stripe');

    assertNoCanary(CANARY, events, 'the live aws load events');
  });
});
