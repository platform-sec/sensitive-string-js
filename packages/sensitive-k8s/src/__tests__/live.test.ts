import { describe, it, expect, beforeAll } from 'vitest';

import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { describeLabelDisclosure } from '@platform-sec/sensitive-string-secrets';
import { assertNoCanary } from '@platform-sec/sensitive-string-secrets/testing';

import { K8sSecretSource } from '../source.js';
import type { K8sCoreApi } from '../source.js';
import { k8sSecretTypeSpec } from '../types.js';
import { LAST_APPLIED, hasDataBearingAnnotation, k8sMetadata } from '../metadata.js';

/**
 * The second tier: a real API server.
 *
 * The unit suite runs against typed fixtures, and a fixture is only as good as
 * the recording behind it. This file talks to a cluster, so the wire facts this
 * package depends on come from Kubernetes rather than from a design document.
 *
 * Skipped unless `K8S_KUBECONFIG` names a kubeconfig. CI runs it as a matrix
 * job against a k3s container with `continue-on-error: true`. The suite expects
 * the namespace and Secrets that `.github/workflows/ci.yml` creates.
 */

const KUBECONFIG = process.env['K8S_KUBECONFIG'];
const NAMESPACE = process.env['K8S_NAMESPACE'] ?? 'payments';
const CANARY = 'LEAKED_SECRET_abc123xyz';

let api: K8sCoreApi;
let source: K8sSecretSource;

describe.skipIf(KUBECONFIG === undefined)('kubernetes, against a real API server', () => {
  beforeAll(async () => {
    const { CoreV1Api, KubeConfig } = await import('@kubernetes/client-node');
    const config = new KubeConfig();
    config.loadFromFile(KUBECONFIG ?? '');

    api = config.makeApiClient(CoreV1Api);
    source = new K8sSecretSource({ api, namespace: NAMESPACE, cache: { ttl: 0 } });
  });

  it('reads an Opaque Secret and wraps every key', async () => {
    const record = await source.getAll('opaque-creds', { fallback: 'credential' });

    expect(record.fields.get('password')).toBeInstanceOf(SensitiveString);
    expect(record.fields.get('password')?.reveal({ name: 'live' })).toBe(CANARY);
    expect(record.fields.get('username')?.reveal({ name: 'live' })).toBe('app');
  });

  it('reports resourceVersion as the concrete version', async () => {
    const record = await source.getAll('opaque-creds', { fallback: 'credential' });

    expect(record.ref.version).toMatch(/^\d+$/);
  });

  it('labels under namespace/name, which names no cluster', async () => {
    const record = await source.getAll('opaque-creds', { fallback: 'credential' });
    const label = record.fields.get('password')?.label ?? '';

    expect(label).toBe(`${NAMESPACE}/opaque-creds#password`);
    expect(describeLabelDisclosure(label)).toEqual([]);
  });

  it('keeps a real certificate plain and wraps the private key', async () => {
    // The case the built-in specs exist for, against a certificate openssl
    // actually produced. A real `kubernetes.io/tls` Secret has exactly
    // `tls.crt` and `tls.key`; the spec also names `ca.crt`, which this cluster
    // does not mount, and a spec naming a key the payload lacks must not fail
    // the load.
    const tls = await source.getAll('ingress-tls', k8sSecretTypeSpec('kubernetes.io/tls'));

    expect(tls.plain.get('tls.crt')).toContain('BEGIN CERTIFICATE');
    expect(tls.fields.get('tls.key')?.klass).toBe('credential');
    expect(tls.plain.get('tls.key')).toBeUndefined();
  });

  it('wraps a dotted key, which a dot path config would have missed', async () => {
    const tls = await source.getAll('ingress-tls', { fallback: 'credential' });

    expect(tls.fields.get('tls.key')).toBeInstanceOf(SensitiveString);
    expect(tls.fields.get('tls.crt')).toBeInstanceOf(SensitiveString);
  });

  it('classifies a basic-auth username as sensitive', async () => {
    const auth = await source.getAll('basic-auth', k8sSecretTypeSpec('kubernetes.io/basic-auth'));

    expect(auth.fields.get('username')?.klass).toBe('sensitive');
    expect(auth.fields.get('password')?.klass).toBe('credential');
  });

  it('expands a real pull secret into leaf keys', async () => {
    const expanding = new K8sSecretSource({
      api,
      namespace: NAMESPACE,
      cache: { ttl: 0 },
      expandDockerConfigJson: true,
    });

    const record = await expanding.getAll(
      'regcred',
      k8sSecretTypeSpec('kubernetes.io/dockerconfigjson')
    );

    expect(record.fields.get('auths.index.docker.io.password')?.reveal({ name: 'live' })).toBe(
      CANARY
    );
    expect(record.fields.get('auths.index.docker.io.auth')?.klass).toBe('credential');
    expect(record.fields.get('auths.index.docker.io.username')?.klass).toBe('sensitive');
  });

  it('strips the annotation kubectl apply leaves behind', async () => {
    // Measured on Kubernetes v1.34.1: applying a manifest written with
    // `stringData` puts the secret into `last-applied-configuration`
    // **unencoded**, so the annotation is worse than the Secret's own `data`,
    // which is at least base64. Nothing about that is obvious from the name of
    // the field, which is why the strip is unconditional and whole-map.
    const secret = await api.readNamespacedSecret({ name: 'db-creds', namespace: NAMESPACE });

    expect(secret.metadata?.annotations?.[LAST_APPLIED]).toContain(CANARY);
    expect(hasDataBearingAnnotation(secret)).toBe(true);

    const metadata = k8sMetadata(secret);

    expect(JSON.stringify(metadata)).not.toContain(CANARY);
    expect(Object.keys(metadata)).not.toContain('annotations');

    const record = await source.getAll('db-creds', { fallback: 'credential' });

    assertNoCanary(CANARY, record.ref, 'the resolved ref of an applied Secret');
  });

  it('reports an absent Secret as absent', async () => {
    expect(await source.getOptional('definitely-not-a-secret')).toBeNull();
  });

  it('reports an absent namespace as absent rather than as a failure', async () => {
    expect(await source.getOptional('not-a-namespace/db-creds')).toBeNull();
  });

  it('leaks no secret material into a load event', async () => {
    const events: unknown[] = [];
    const audited = new K8sSecretSource({
      api,
      namespace: NAMESPACE,
      cache: { ttl: 0 },
      onLoad: (event) => events.push(event),
    });

    await audited.getAll('db-creds', { fallback: 'credential' });
    await audited.getAll('opaque-creds', { fallback: 'credential' });

    assertNoCanary(CANARY, events, 'the live k8s load events');
  });
});
