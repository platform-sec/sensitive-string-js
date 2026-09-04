import { describe, it, expect } from 'vitest';
import { SecretPayloadError } from '@platform-sec/sensitive-string-secrets';
import type { ResolvedSecretRef } from '@platform-sec/sensitive-string-secrets';

import { isOcid, isStage, ociLifetime, ociPayload, ociResolvedRef, versionFields } from './wire.js';
import { SECRET_OCID, bundle } from './__tests__/fake-client.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';
const REF: ResolvedSecretRef = { path: 'prod-stripe-key', version: '4', metadata: {} };

describe('isOcid', () => {
  it('recognizes an OCID', () => {
    expect(isOcid(SECRET_OCID)).toBe(true);
  });

  it('does not mistake a secret name for one', () => {
    expect(isOcid('prod-stripe-key')).toBe(false);
    expect(isOcid('ocid-rotation-key')).toBe(false);
  });
});

describe('isStage', () => {
  it('recognizes the five stages, case-insensitively', () => {
    for (const stage of ['CURRENT', 'pending', 'Latest', 'PREVIOUS', 'deprecated']) {
      expect(isStage(stage)).toBe(true);
    }
  });

  it('does not treat a version name as a stage', () => {
    expect(isStage('release-2026-09')).toBe(false);
  });
});

describe('versionFields', () => {
  it('routes a number to versionNumber', () => {
    expect(versionFields('7')).toEqual({ versionNumber: 7 });
  });

  it('routes a stage to stage, normalized', () => {
    expect(versionFields('previous')).toEqual({ stage: 'PREVIOUS' });
  });

  it('routes anything else to secretVersionName', () => {
    expect(versionFields('release-2026-09')).toEqual({ secretVersionName: 'release-2026-09' });
  });

  it('sends nothing when no version was asked for', () => {
    expect(versionFields(undefined)).toEqual({});
  });
});

describe('ociPayload', () => {
  it('decodes a BASE64 bundle', () => {
    expect(ociPayload(bundle({ value: CANARY }), REF)).toBe(CANARY);
  });

  it('refuses a content type it does not decode, rather than assuming base64', () => {
    // A new content type decoded as base64 would produce garbage that looks
    // like a secret and fails as an authentication error somewhere else.
    try {
      ociPayload(bundle({ value: CANARY, contentType: 'PLAINTEXT' }), REF);
      expect.unreachable('the bundle should have been refused');
    } catch (error) {
      expect(error).toBeInstanceOf(SecretPayloadError);
      expect((error as Error).message).toContain('PLAINTEXT');
      expect((error as Error).message).not.toContain(CANARY);
    }
  });

  it('refuses content that is not valid base64, rather than decoding it leniently', () => {
    const failure = (): string => ociPayload(bundle({ rawContent: `${CANARY}!!!` }), REF);

    expect(failure).toThrow(SecretPayloadError);
    expect(failure).toThrow(/base64/);

    try {
      failure();
    } catch (error) {
      expect((error as Error).message).not.toContain(CANARY);
    }
  });

  it('refuses a bundle with no content', () => {
    expect(() => ociPayload(bundle({ omitContent: true }), REF)).toThrow(/no bundle content/);
  });
});

describe('ociLifetime', () => {
  it('binds timeOfExpiry', () => {
    const timeOfExpiry = new Date('2026-12-01T00:00:00Z');

    expect(ociLifetime(bundle({ value: 'x', timeOfExpiry }))).toEqual({ expiresAt: timeOfExpiry });
  });

  it('binds nothing from timeOfDeletion, which a live secret can have', () => {
    const timeOfDeletion = new Date('2026-12-01T00:00:00Z');

    expect(ociLifetime(bundle({ value: 'x', timeOfDeletion }))).toBeUndefined();
  });
});

describe('ociResolvedRef', () => {
  it('reports the concrete version number', () => {
    expect(
      ociResolvedRef(bundle({ value: 'x', versionNumber: 9 }), 'prod-stripe-key').version
    ).toBe('9');
  });

  it('puts the secret OCID on metadata and not in the path', () => {
    const resolved = ociResolvedRef(bundle({ value: 'x' }), 'prod-stripe-key');

    expect(resolved.path).toBe('prod-stripe-key');
    expect(resolved.metadata['secretId']).toBe(SECRET_OCID);
  });

  it('records the deletion time without binding it', () => {
    const resolved = ociResolvedRef(
      bundle({ value: 'x', timeOfDeletion: new Date('2026-12-01T00:00:00Z') }),
      'k'
    );

    expect(resolved.metadata['deletionAt']).toBe('2026-12-01T00:00:00.000Z');
  });
});
