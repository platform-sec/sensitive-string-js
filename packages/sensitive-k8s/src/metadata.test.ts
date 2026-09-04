import { describe, it, expect } from 'vitest';

import { LAST_APPLIED, hasDataBearingAnnotation, k8sMetadata } from './metadata.js';
import { NAMESPACE, b64, v1Secret } from './__tests__/fake-api.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

/** What `kubectl apply` writes: the whole manifest, `data` included. */
function lastApplied(name: string, data: Readonly<Record<string, string>>): string {
  return JSON.stringify({
    apiVersion: 'v1',
    kind: 'Secret',
    metadata: { name, namespace: NAMESPACE },
    type: 'Opaque',
    data: Object.fromEntries(Object.entries(data).map(([key, value]) => [key, b64(value)])),
  });
}

describe('k8sMetadata', () => {
  it('surfaces the identifiers an audit record wants', () => {
    const metadata = k8sMetadata(v1Secret('db-creds', { data: { password: CANARY } }));

    expect(metadata['name']).toBe('db-creds');
    expect(metadata['namespace']).toBe(NAMESPACE);
    expect(metadata['resourceVersion']).toBe('184213');
    expect(metadata['uid']).toBe('b1f2c4d5-4a2f-4a6b-9a1d-0f6a3c2b7e11');
    expect(metadata['type']).toBe('Opaque');
    expect(metadata['createdAt']).toBe('2026-09-01T00:00:00.000Z');
  });

  it('strips annotations entirely, including the one holding a second copy', () => {
    const secret = v1Secret('db-creds', {
      data: { password: CANARY },
      annotations: { [LAST_APPLIED]: lastApplied('db-creds', { password: CANARY }) },
    });

    // The annotation really does hold the secret. That is the point.
    expect(hasDataBearingAnnotation(secret)).toBe(true);
    expect(JSON.stringify(secret)).toContain(b64(CANARY));

    const metadata = k8sMetadata(secret);

    expect(JSON.stringify(metadata)).not.toContain(b64(CANARY));
    expect(JSON.stringify(metadata)).not.toContain(CANARY);
    expect(Object.keys(metadata)).not.toContain('annotations');
  });

  it('strips an annotation this package has never heard of, not only the known one', () => {
    // The strip is a whole-map removal rather than a denylist, because the
    // mechanism that put a copy of a Secret in an annotation is a convention
    // and other tools follow similar ones.
    const secret = v1Secret('db-creds', {
      data: { password: CANARY },
      annotations: { 'some-operator.example.com/previous': `{"data":{"password":"${CANARY}"}}` },
    });

    expect(hasDataBearingAnnotation(secret)).toBe(true);
    expect(JSON.stringify(k8sMetadata(secret))).not.toContain(CANARY);
  });

  it('surfaces no labels, since a copy of a Secret has been found in one', () => {
    const metadata = k8sMetadata(v1Secret('db-creds', { data: { password: CANARY } }));

    expect(Object.keys(metadata)).not.toContain('labels');
    expect(Object.keys(metadata)).not.toContain('managedFields');
  });
});

describe('hasDataBearingAnnotation', () => {
  it('is false for a Secret with no annotations', () => {
    expect(hasDataBearingAnnotation(v1Secret('db-creds', { data: {} }))).toBe(false);
  });

  it('is false for an annotation that holds no data block', () => {
    const secret = v1Secret('db-creds', {
      data: {},
      annotations: { 'example.com/owner': 'payments' },
    });

    expect(hasDataBearingAnnotation(secret)).toBe(false);
  });
});
