import { describe, it, expect } from 'vitest';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import {
  SecretNotFoundError,
  SecretPayloadError,
  describeLabelDisclosure,
} from '@platform-sec/sensitive-string-secrets';

import { k8sSecretTypeSpec } from './types.js';
import { LAST_APPLIED } from './metadata.js';
import { FakeCoreApi, NAMESPACE, jwt, k8sError, source } from './__tests__/fake-api.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';
const CERT = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----';
const EXP = Math.floor(Date.now() / 1000) + 3600;

function api(): FakeCoreApi {
  return FakeCoreApi.of({
    'db-creds': { data: { username: 'app', password: CANARY } },
    'ingress-tls': {
      type: 'kubernetes.io/tls',
      data: { 'tls.crt': CERT, 'tls.key': CANARY, 'ca.crt': CERT },
    },
    'basic-auth': {
      type: 'kubernetes.io/basic-auth',
      data: { username: 'app', password: CANARY },
    },
    regcred: {
      type: 'kubernetes.io/dockerconfigjson',
      data: {
        '.dockerconfigjson': JSON.stringify({
          auths: { 'index.docker.io': { username: 'app', password: CANARY, auth: CANARY } },
        }),
      },
    },
    'broken-regcred': {
      type: 'kubernetes.io/dockerconfigjson',
      data: { '.dockerconfigjson': CANARY },
    },
    'sa-token': {
      type: 'kubernetes.io/service-account-token',
      data: { token: jwt({ exp: EXP }), 'ca.crt': CERT, namespace: NAMESPACE },
    },
    'legacy-sa-token': {
      type: 'kubernetes.io/service-account-token',
      data: { token: jwt({ sub: 'system:serviceaccount:payments:api' }) },
    },
    'empty-secret': { data: {} },
    'write-only-secret': { stringData: { password: CANARY } },
    'not-base64': { rawData: { password: `${CANARY}!!!` } },
    'applied-secret': {
      data: { password: CANARY },
      annotations: {
        [LAST_APPLIED]: JSON.stringify({ kind: 'Secret', data: { password: 'x' } }),
      },
    },
    'denied-secret': { error: k8sError(403, 'secrets is forbidden') },
    'broken-api': { error: k8sError(500, 'an internal error') },
    'other/shared-secret': { data: { password: CANARY } },
  });
}

describe('K8sSecretSource.getAll', () => {
  it('decodes base64 and wraps under a namespace/name label', async () => {
    const record = await source(api()).getAll('db-creds', { fallback: 'credential' });

    expect(record.fields.get('password')).toBeInstanceOf(SensitiveString);
    expect(record.fields.get('password')?.label).toBe('payments/db-creds#password');
    expect(record.fields.get('password')?.reveal({ name: 'test' })).toBe(CANARY);
    expect(describeLabelDisclosure(record.fields.get('password')?.label ?? '')).toEqual([]);
  });

  it('reports resourceVersion as the concrete version', async () => {
    const record = await source(api()).getAll('db-creds', { fallback: 'credential' });

    expect(record.ref.version).toBe('184213');
  });

  it('reads a namespace/name path without the configured namespace', async () => {
    const fake = api();
    const record = await source(fake, { namespace: undefined }).getAll('other/shared-secret', {
      fallback: 'credential',
    });

    expect(fake.requests[0]).toEqual({ namespace: 'other', name: 'shared-secret' });
    expect(record.ref.path).toBe('other/shared-secret');
  });

  it('says what is missing when a bare name has no namespace', async () => {
    await expect(
      source(api(), { namespace: undefined }).getAll('db-creds', { fallback: 'credential' })
    ).rejects.toThrow(/needs a namespace/);
  });

  it('keeps a certificate plain under the tls spec', async () => {
    const tls = await source(api()).getAll('ingress-tls', k8sSecretTypeSpec('kubernetes.io/tls'));

    expect(tls.plain.get('tls.crt')).toBe(CERT);
    expect(tls.plain.get('ca.crt')).toBe(CERT);
    expect(tls.fields.get('tls.key')?.klass).toBe('credential');
  });

  it('wraps a dotted key, which a dot path config would have missed', async () => {
    const tls = await source(api()).getAll('ingress-tls', { fallback: 'credential' });

    expect(tls.fields.get('tls.key')).toBeInstanceOf(SensitiveString);
    expect(tls.plain.get('tls.key')).toBeUndefined();
  });

  it('classifies a basic-auth username as sensitive', async () => {
    const auth = await source(api()).getAll(
      'basic-auth',
      k8sSecretTypeSpec('kubernetes.io/basic-auth')
    );

    expect(auth.fields.get('username')?.klass).toBe('sensitive');
    expect(auth.fields.get('password')?.klass).toBe('credential');
  });

  it('reports an empty Secret as empty rather than as absent', async () => {
    const record = await source(api()).getAll('empty-secret', { fallback: 'credential' });

    expect(record.keys).toEqual([]);
  });

  it('names stringData when a fixture uses the write-only field', async () => {
    await expect(
      source(api()).getAll('write-only-secret', { fallback: 'credential' })
    ).rejects.toThrow(/write-only/);
  });

  it('refuses a value that is not valid base64 rather than decoding it leniently', async () => {
    const failure = await source(api())
      .getAll('not-base64', { fallback: 'credential' })
      .catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(SecretPayloadError);
    expect((failure as Error).message).not.toContain(CANARY);
  });

  it('strips the annotation holding a second copy of the data', async () => {
    const record = await source(api()).getAll('applied-secret', { fallback: 'credential' });

    expect(JSON.stringify(record.ref.metadata)).not.toContain('data');
    expect(Object.keys(record.ref.metadata)).not.toContain('annotations');
  });
});

describe('the docker config expansion', () => {
  it('is off by default, so the key set does not change under the caller', async () => {
    const record = await source(api()).getAll('regcred', { fallback: 'credential' });

    expect(record.keys).toEqual(['.dockerconfigjson']);
  });

  it('expands into leaf keys when asked, and classifies them by leaf name', async () => {
    const record = await source(api(), { expandDockerConfigJson: true }).getAll(
      'regcred',
      k8sSecretTypeSpec('kubernetes.io/dockerconfigjson')
    );

    expect(record.fields.get('auths.index.docker.io.auth')?.klass).toBe('credential');
    expect(record.fields.get('auths.index.docker.io.password')?.klass).toBe('credential');
    expect(record.fields.get('auths.index.docker.io.username')?.klass).toBe('sensitive');
    // Replaced rather than kept alongside, so one copy is classified.
    expect(record.keys).not.toContain('.dockerconfigjson');
  });

  it('routes a malformed pull secret through the decode guard', async () => {
    const failure = await source(api(), { expandDockerConfigJson: true })
      .getAll('broken-regcred', { fallback: 'credential' })
      .catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(SecretPayloadError);
    expect((failure as Error).message).not.toContain(CANARY);
  });
});

describe('readTokenExpiry', () => {
  it('is off by default', async () => {
    const record = await source(api()).getAll('sa-token', { fallback: 'credential' });

    expect(record.fields.get('token')?.expiresAt).toBeUndefined();
  });

  it('binds the exp claim when asked', async () => {
    const record = await source(api(), { readTokenExpiry: true }).getAll(
      'sa-token',
      k8sSecretTypeSpec('kubernetes.io/service-account-token')
    );

    expect(record.fields.get('token')?.expiresAt).toEqual(new Date(EXP * 1000));
    expect(record.plain.get('namespace')).toBe(NAMESPACE);
  });

  it('binds nothing for a legacy token that never expires', async () => {
    const record = await source(api(), { readTokenExpiry: true }).getAll('legacy-sa-token', {
      fallback: 'credential',
    });

    expect(record.fields.get('token')?.expiresAt).toBeUndefined();
  });
});

describe('K8sSecretSource.getOptional', () => {
  it('returns null for an absent Secret', async () => {
    expect(await source(api()).getOptional('missing-secret')).toBeNull();
  });

  it('keeps throwing for a forbidden read', async () => {
    await expect(source(api()).getOptional('denied-secret')).rejects.toThrow(/forbidden/);
  });

  it('reports absence through SecretNotFoundError on getAll', async () => {
    await expect(
      source(api()).getAll('missing-secret', { fallback: 'credential' })
    ).rejects.toThrow(SecretNotFoundError);
  });
});

describe('the constructor', () => {
  it('refuses an api client with no readNamespacedSecret method', () => {
    expect(() => source({} as unknown as FakeCoreApi)).toThrow(/readNamespacedSecret\(\)/);
  });
});
