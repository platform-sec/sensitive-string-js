import { describe, it, expect } from 'vitest';
import { SecretPayloadError } from '@platform-sec/sensitive-string-secrets';
import type { ResolvedSecretRef } from '@platform-sec/sensitive-string-secrets';

import {
  gcpLabel,
  gcpResolvedRef,
  gcpSecretMetadata,
  parseResource,
  resourceName,
  timestampToDate,
  verifiedPayload,
} from './wire.js';
import { crc32c } from './crc32c.js';
import { PROJECT, accessResponse, secretResource } from './__tests__/fake-client.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';
const REF: ResolvedSecretRef = { path: 'stripe-api-key', version: '7', metadata: {} };

describe('parseResource', () => {
  it('splits a fully qualified version name', () => {
    expect(parseResource(`projects/${PROJECT}/secrets/stripe-api-key/versions/7`)).toEqual({
      project: PROJECT,
      secret: 'stripe-api-key',
      version: '7',
    });
  });

  it('splits a secret name with no version', () => {
    expect(parseResource(`projects/${PROJECT}/secrets/stripe-api-key`)).toEqual({
      project: PROJECT,
      secret: 'stripe-api-key',
      version: undefined,
    });
  });

  it('returns undefined for a short name', () => {
    expect(parseResource('stripe-api-key')).toBeUndefined();
  });
});

describe('gcpLabel', () => {
  it('reduces a resource name to the short name, so no label carries the project number', () => {
    expect(gcpLabel(`projects/${PROJECT}/secrets/stripe-api-key/versions/7`)).toBe(
      'stripe-api-key'
    );
    expect(gcpLabel(`projects/${PROJECT}/secrets/stripe-api-key/versions/7`)).not.toContain(
      PROJECT
    );
  });

  it('keeps a short name as it is', () => {
    expect(gcpLabel('stripe-api-key')).toBe('stripe-api-key');
  });
});

describe('resourceName', () => {
  it('resolves a short name against the configured project, defaulting to latest', () => {
    expect(resourceName({ path: 'stripe-api-key' }, PROJECT)).toBe(
      `projects/${PROJECT}/secrets/stripe-api-key/versions/latest`
    );
  });

  it('uses a fully qualified name as given', () => {
    const name = `projects/other/secrets/stripe-api-key/versions/3`;

    expect(resourceName({ path: name }, PROJECT)).toBe(name);
  });

  it('lets an explicit version win over one on the path', () => {
    expect(
      resourceName({ path: `projects/other/secrets/k/versions/3`, version: '9' }, PROJECT)
    ).toBe('projects/other/secrets/k/versions/9');
  });

  it('says what is missing when a short name has no project to resolve against', () => {
    expect(() => resourceName({ path: 'stripe-api-key' }, undefined)).toThrow(/needs a project/);
  });
});

describe('verifiedPayload', () => {
  it('returns the decoded value when the checksum matches', () => {
    const response = accessResponse('projects/p/secrets/s/versions/1', { value: CANARY });

    expect(verifiedPayload(response.payload ?? {}, REF, false)).toBe(CANARY);
  });

  it('refuses a payload whose checksum does not match, and names no content', () => {
    const response = accessResponse('projects/p/secrets/s/versions/1', {
      value: CANARY,
      crc: crc32c(Buffer.from('something else')),
    });

    try {
      verifiedPayload(response.payload ?? {}, REF, false);
      expect.unreachable('the payload should have been refused');
    } catch (error) {
      expect(error).toBeInstanceOf(SecretPayloadError);
      expect((error as Error).message).toContain('CRC32C');
      expect((error as Error).message).not.toContain(CANARY);
    }
  });

  it('accepts a payload with no checksum by default', () => {
    const response = accessResponse('projects/p/secrets/s/versions/1', {
      value: CANARY,
      omitCrc: true,
    });

    expect(verifiedPayload(response.payload ?? {}, REF, false)).toBe(CANARY);
  });

  it('refuses a payload with no checksum when the deployment requires one', () => {
    const response = accessResponse('projects/p/secrets/s/versions/1', {
      value: CANARY,
      omitCrc: true,
    });

    expect(() => verifiedPayload(response.payload ?? {}, REF, true)).toThrow(/requires one/);
  });

  it('decodes base64 data, which is how a JSON transport delivers the bytes', () => {
    const encoded = Buffer.from(CANARY).toString('base64');

    expect(verifiedPayload({ data: encoded }, REF, false)).toBe(CANARY);
  });

  it('refuses a response carrying no data', () => {
    expect(() => verifiedPayload({}, REF, false)).toThrow(SecretPayloadError);
  });
});

describe('timestampToDate', () => {
  it('converts seconds and nanos', () => {
    expect(timestampToDate({ seconds: 1_756_684_800, nanos: 500_000_000 })?.toISOString()).toBe(
      '2025-09-01T00:00:00.500Z'
    );
  });

  it('handles an int64 delivered as a string', () => {
    expect(timestampToDate({ seconds: '1756684800' })?.toISOString()).toBe(
      '2025-09-01T00:00:00.000Z'
    );
  });

  it('reports an absent or unusable timestamp as undefined', () => {
    expect(timestampToDate(undefined)).toBeUndefined();
    expect(timestampToDate(null)).toBeUndefined();
    expect(timestampToDate({ seconds: 'not a number' })).toBeUndefined();
  });
});

describe('gcpSecretMetadata', () => {
  it('binds expireTime, which is a real deletion time', () => {
    const expireTime = { seconds: 1_800_000_000, nanos: 0 };
    const { lifetime } = gcpSecretMetadata(secretResource('k', { expireTime }));

    expect(lifetime?.expiresAt?.toISOString()).toBe(new Date(1_800_000_000_000).toISOString());
  });

  it('records the rotation schedule and binds nothing from it', () => {
    const { lifetime, metadata } = gcpSecretMetadata(
      secretResource('k', { rotation: { nextRotationTime: { seconds: 1_800_000_000 } } })
    );

    expect(lifetime).toBeUndefined();
    expect(metadata['nextRotationAt']).toBe(new Date(1_800_000_000_000).toISOString());
  });
});

describe('gcpResolvedRef', () => {
  it('reports the version the server resolved rather than the alias asked for', () => {
    const response = accessResponse(`projects/${PROJECT}/secrets/k/versions/latest`, {
      value: 'x',
      version: '12',
    });

    const resolved = gcpResolvedRef(response, { path: 'k', version: 'latest' });

    expect(resolved.version).toBe('12');
    expect(resolved.path).toBe('k');
    expect(resolved.metadata['project']).toBe(PROJECT);
  });
});
