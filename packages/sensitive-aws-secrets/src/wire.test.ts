import { describe, it, expect } from 'vitest';
import { SecretPayloadError } from '@platform-sec/sensitive-string-secrets';
import type { ResolvedSecretRef } from '@platform-sec/sensitive-string-secrets';

import {
  awsLabel,
  awsPayload,
  awsResolvedRef,
  parseArn,
  rotationMetadata,
  versionField,
} from './wire.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';
const ACCOUNT = '123456789012';
const ARN = `arn:aws:secretsmanager:us-east-1:${ACCOUNT}:secret:prod/db-AbCdEf`;
const REF: ResolvedSecretRef = { path: 'prod/db', version: 'v1', metadata: {} };

describe('parseArn', () => {
  it('splits a secret ARN into its parts', () => {
    expect(parseArn(ARN)).toEqual({
      partition: 'aws',
      region: 'us-east-1',
      account: ACCOUNT,
      name: 'prod/db-AbCdEf',
    });
  });

  it('returns undefined for a bare name', () => {
    expect(parseArn('prod/db')).toBeUndefined();
  });

  it('returns undefined for an ARN of a different service', () => {
    expect(parseArn(`arn:aws:kms:us-east-1:${ACCOUNT}:key/abcd`)).toBeUndefined();
  });

  it('handles a partition other than aws', () => {
    expect(
      parseArn(`arn:aws-us-gov:secretsmanager:us-gov-west-1:${ACCOUNT}:secret:x-AbCdEf`)?.partition
    ).toBe('aws-us-gov');
  });
});

describe('awsLabel', () => {
  it('keeps a bare name as it is', () => {
    expect(awsLabel('prod/db')).toBe('prod/db');
  });

  it('reduces an ARN to the name, so no label carries the account id', () => {
    expect(awsLabel(ARN)).toBe('prod/db-AbCdEf');
    expect(awsLabel(ARN)).not.toContain(ACCOUNT);
  });

  it('keeps the six-character suffix rather than guessing where a name ends', () => {
    // `prod/config-backup` and `prod/config` with suffix `backup` produce the
    // same string, so a strip would take a word off one of them.
    expect(awsLabel(`arn:aws:secretsmanager:us-east-1:${ACCOUNT}:secret:prod/config-backup`)).toBe(
      'prod/config-backup'
    );
  });
});

describe('versionField', () => {
  it('routes a staging label to VersionStage', () => {
    expect(versionField('AWSPREVIOUS', 'auto')).toEqual({ VersionStage: 'AWSPREVIOUS' });
  });

  it('routes a UUID to VersionId', () => {
    const id = 'b9b1f2c4-4a2f-4a6b-9a1d-0f6a3c2b7e11';

    expect(versionField(id, 'auto')).toEqual({ VersionId: id });
  });

  it('lets a caller force either slot', () => {
    const id = 'b9b1f2c4-4a2f-4a6b-9a1d-0f6a3c2b7e11';

    expect(versionField(id, 'stage')).toEqual({ VersionStage: id });
    expect(versionField('AWSCURRENT', 'id')).toEqual({ VersionId: 'AWSCURRENT' });
  });
});

describe('awsPayload', () => {
  it('takes SecretString when it is present', () => {
    expect(awsPayload({ SecretString: CANARY }, REF, 'utf8')).toEqual({
      kind: 'string',
      value: CANARY,
    });
  });

  it('decodes SecretBinary when that is the field that carried it', () => {
    const binary = new TextEncoder().encode(CANARY);

    expect(awsPayload({ SecretBinary: binary }, REF, 'utf8')).toEqual({
      kind: 'string',
      value: CANARY,
    });
  });

  it('decodes SecretBinary as base64 on request', () => {
    const binary = new TextEncoder().encode(CANARY);
    const payload = awsPayload({ SecretBinary: binary }, REF, 'base64');

    expect(payload.value).toBe(Buffer.from(CANARY).toString('base64'));
  });

  it('reads a view into a larger buffer without taking its neighbours', () => {
    // `Uint8Array` from an SDK stream is often a view over a pooled buffer, and
    // `Buffer.from(view.buffer)` would read the whole pool.
    const pool = new Uint8Array([...Buffer.from('BEFORE'), ...Buffer.from(CANARY), 1, 2, 3]);
    const view = pool.subarray(6, 6 + CANARY.length);

    expect(awsPayload({ SecretBinary: view }, REF, 'utf8').value).toBe(CANARY);
  });

  it('refuses a response carrying neither field rather than yielding an empty string', () => {
    expect(() => awsPayload({}, REF, 'utf8')).toThrow(SecretPayloadError);
  });
});

describe('awsResolvedRef', () => {
  const response = {
    $metadata: {},
    ARN,
    Name: 'prod/db',
    VersionId: 'b9b1f2c4-4a2f-4a6b-9a1d-0f6a3c2b7e11',
    VersionStages: ['AWSCURRENT', 'AWSPENDING'],
    CreatedDate: new Date('2026-09-01T00:00:00Z'),
  };

  it('reports the name as the path, so no error message carries the ARN', () => {
    const resolved = awsResolvedRef(response, { path: ARN });

    expect(resolved.path).toBe('prod/db');
    expect(resolved.path).not.toContain(ACCOUNT);
  });

  it('reports the concrete version rather than the stage that was asked for', () => {
    const resolved = awsResolvedRef(response, { path: 'prod/db', version: 'AWSCURRENT' });

    expect(resolved.version).toBe('b9b1f2c4-4a2f-4a6b-9a1d-0f6a3c2b7e11');
  });

  it('puts the ARN, the account and the region on metadata', () => {
    const resolved = awsResolvedRef(response, { path: 'prod/db' });

    expect(resolved.metadata['arn']).toBe(ARN);
    expect(resolved.metadata['account']).toBe(ACCOUNT);
    expect(resolved.metadata['region']).toBe('us-east-1');
  });

  it('records both stages during a rotation, which is a property of the protocol', () => {
    const resolved = awsResolvedRef(response, { path: 'prod/db' });

    expect(resolved.metadata['versionStages']).toBe('AWSCURRENT,AWSPENDING');
  });

  it('falls back to unknown when the response reports no version id', () => {
    const { VersionId: _omitted, ...withoutVersion } = response;

    expect(awsResolvedRef(withoutVersion, { path: 'prod/db' }).version).toBe('unknown');
  });
});

describe('rotationMetadata', () => {
  it('records the schedule and binds no deadline', () => {
    const metadata = rotationMetadata({
      $metadata: {},
      RotationEnabled: true,
      NextRotationDate: new Date('2026-10-01T00:00:00Z'),
      RotationRules: { AutomaticallyAfterDays: 30 },
    });

    expect(metadata['rotationEnabled']).toBe(true);
    expect(metadata['nextRotationAt']).toBe('2026-10-01T00:00:00.000Z');
    expect(metadata['rotationAfterDays']).toBe(30);
    // Nothing here is a lifetime. The current version of a rotated secret keeps
    // working past its next rotation date, so a deadline derived from one would
    // expire the live credential.
    expect(Object.keys(metadata)).not.toContain('expiresAt');
    expect(Object.keys(metadata)).not.toContain('ttl');
  });

  it('reports rotation as off when the secret is not rotated', () => {
    expect(rotationMetadata({ $metadata: {} })['rotationEnabled']).toBe(false);
  });
});
