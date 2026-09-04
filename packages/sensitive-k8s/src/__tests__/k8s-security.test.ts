import { describe, it, expect, afterAll } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describeLabelDisclosure } from '@platform-sec/sensitive-string-secrets';
import type { SecretLoadEvent } from '@platform-sec/sensitive-string-secrets';
import {
  assertEverySourceSwept,
  assertNoCanary,
  sweep,
} from '@platform-sec/sensitive-string-secrets/testing';
import type { SweepCase } from '@platform-sec/sensitive-string-secrets/testing';

import * as k8sPackage from '../index.js';
import { LAST_APPLIED, hasDataBearingAnnotation } from '../metadata.js';
import { k8sSecretTypeSpec } from '../types.js';
import { K8sMountedSource } from '../mounted.js';
import { FakeCoreApi, NAMESPACE, b64, jwt, k8sError, source, v1Secret } from './fake-api.js';

/** Exactly 20 characters, the length V8 echoes whole into a SyntaxError. */
const SHORT_CANARY = 'LEAKED_SECRET_abc123';
const CANARY = 'LEAKED_SECRET_abc123xyz';
const CERT = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----';

/**
 * A mount for the mounted-source half of the sweep.
 *
 * `K8sMountedSource` is a source like any other and the registration test would
 * flag it if it had no cases, so it gets its own fixtures rather than an
 * exemption.
 */
const MOUNT = mkdtempSync(join(tmpdir(), 'sensitive-k8s-sweep-'));

writeFileSync(join(MOUNT, 'password'), CANARY);
writeFileSync(join(MOUNT, 'short'), SHORT_CANARY);
writeFileSync(join(MOUNT, 'token'), CANARY);

afterAll(() => {
  rmSync(MOUNT, { recursive: true, force: true });
});

function mounted(options: Record<string, unknown> = {}): K8sMountedSource {
  return new K8sMountedSource({ cache: { ttl: 0 }, ...options });
}

function api(): FakeCoreApi {
  return FakeCoreApi.of({
    'db-creds': { data: { username: 'app', password: CANARY } },
    'short-creds': { data: { password: SHORT_CANARY } },
    'ingress-tls': {
      type: 'kubernetes.io/tls',
      data: { 'tls.crt': CERT, 'tls.key': CANARY, 'ca.crt': CERT },
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
    'short-regcred': {
      type: 'kubernetes.io/dockerconfigjson',
      data: { '.dockerconfigjson': SHORT_CANARY },
    },
    'sa-token': {
      type: 'kubernetes.io/service-account-token',
      data: { token: jwt({ exp: Math.floor(Date.now() / 1000) + 60 }), namespace: NAMESPACE },
    },
    'bad-token': { type: 'kubernetes.io/service-account-token', data: { token: CANARY } },
    'not-base64': { rawData: { password: `${CANARY}!!!` } },
    'write-only-secret': { stringData: { password: CANARY } },
    'applied-secret': {
      data: { password: CANARY },
      annotations: {
        [LAST_APPLIED]: JSON.stringify({
          kind: 'Secret',
          data: { password: b64(CANARY) },
        }),
      },
    },
    'denied-secret': { error: k8sError(403, 'secrets is forbidden') },
    'broken-api': { error: k8sError(500, 'an internal error') },
  });
}

const CASES: readonly SweepCase[] = [
  {
    name: 'getAll on an Opaque secret',
    run: () => source(api()).getAll('db-creds', { fallback: 'credential' }),
  },
  {
    name: 'getAll under the tls spec',
    run: () => source(api()).getAll('ingress-tls', k8sSecretTypeSpec('kubernetes.io/tls')),
  },
  {
    name: 'getAll on a secret carrying a last-applied annotation',
    run: () => source(api()).getAll('applied-secret', { fallback: 'credential' }),
  },
  {
    name: 'getAll on a value that is not base64',
    run: () => source(api()).getAll('not-base64', { fallback: 'credential' }),
  },
  {
    name: 'getAll on a secret that only has stringData',
    run: () => source(api()).getAll('write-only-secret', { fallback: 'credential' }),
  },
  {
    name: 'getJson with a declared field the secret lacks',
    run: () => source(api()).getJson('db-creds', { fields: { missing: 'credential' } }),
  },
  {
    name: 'get on a secret that holds named fields',
    run: () => source(api()).get('db-creds'),
  },
  {
    name: 'an expanded pull secret',
    run: () =>
      source(api(), { expandDockerConfigJson: true }).getAll(
        'regcred',
        k8sSecretTypeSpec('kubernetes.io/dockerconfigjson')
      ),
  },
  {
    name: 'a malformed pull secret',
    run: () =>
      source(api(), { expandDockerConfigJson: true }).getAll('broken-regcred', {
        fallback: 'credential',
      }),
  },
  {
    name: 'a malformed 20-character pull secret',
    run: () =>
      source(api(), { expandDockerConfigJson: true }).getAll('short-regcred', {
        fallback: 'credential',
      }),
  },
  {
    name: 'a projected token whose expiry is read',
    run: () =>
      source(api(), { readTokenExpiry: true }).getAll(
        'sa-token',
        k8sSecretTypeSpec('kubernetes.io/service-account-token')
      ),
  },
  {
    name: 'a token field that is not a JWT',
    run: () =>
      source(api(), { readTokenExpiry: true }).getAll('bad-token', { fallback: 'credential' }),
  },
  { name: 'an absent secret', run: () => source(api()).get('missing-secret') },
  {
    name: 'a forbidden read',
    run: () => source(api()).getAll('denied-secret', { fallback: 'credential' }),
  },
  {
    name: 'an api failure',
    run: () => source(api()).getAll('broken-api', { fallback: 'credential' }),
  },
  {
    name: 'a bare name with no namespace',
    run: () =>
      source(api(), { namespace: undefined }).getAll('db-creds', { fallback: 'credential' }),
  },
  {
    name: 'getAll on a mounted volume',
    run: () => mounted().getAll(MOUNT, { fallback: 'credential' }),
  },
  {
    name: 'getJson on a mounted volume with a declared field it lacks',
    run: () => mounted().getJson(MOUNT, { fields: { missing: 'credential' } }),
  },
  {
    name: 'a mounted token file that is not a JWT',
    run: () => mounted({ readTokenExpiry: true }).getAll(MOUNT, { fallback: 'credential' }),
  },
  {
    name: 'a mount that is not there',
    run: () => mounted().getAll('/definitely/not/a/mount', { fallback: 'credential' }),
  },
  {
    name: 'a relative mount ref with no base directory',
    run: () => mounted().getAll('db-creds', { fallback: 'credential' }),
  },
];

describe('the k8s sweep', () => {
  it('leaks the canary in no result and no error', async () => {
    const results = await sweep(CANARY, CASES);

    expect(results).toHaveLength(CASES.length);
  });

  it('leaks the 20-character canary either', async () => {
    await sweep(SHORT_CANARY, CASES);
  });

  it('leaks the base64 form of the canary either', async () => {
    // The wire form. A code path that reports an undecoded value leaks just as
    // much as one that reports the decoded one.
    await sweep(b64(CANARY), CASES);
  });

  it('forces failures rather than sweeping only happy paths', async () => {
    const results = await sweep(CANARY, CASES);

    expect(results.filter((result) => result.threw).length).toBeGreaterThan(5);
  });
});

describe('the fixtures', () => {
  it('carry a canary, so a fixture that leaks is caught like a real one', () => {
    expect(JSON.stringify(v1Secret('x', { data: { password: CANARY } }))).toContain(b64(CANARY));
  });

  it('include one whose annotation holds a second copy of the data', () => {
    const secret = v1Secret('applied-secret', {
      data: { password: CANARY },
      annotations: { [LAST_APPLIED]: JSON.stringify({ data: { password: b64(CANARY) } }) },
    });

    expect(hasDataBearingAnnotation(secret)).toBe(true);
  });
});

describe('load events', () => {
  it('carry no secret material, including from the annotation', async () => {
    const events: SecretLoadEvent[] = [];
    const k8s = source(api(), { onLoad: (event) => events.push(event) });

    await k8s.getAll('db-creds', { fallback: 'credential' });
    await k8s.getAll('applied-secret', { fallback: 'credential' });

    assertNoCanary(CANARY, events, 'the k8s load events');
    assertNoCanary(b64(CANARY), events, 'the k8s load events');
  });
});

describe('labels', () => {
  it('disclose nothing under the rule, for every field of every fixture', async () => {
    const k8s = source(api());

    for (const path of ['db-creds', 'ingress-tls', 'applied-secret']) {
      const record = await k8s.getAll(path, { fallback: 'credential' });

      for (const value of record.fields.values()) {
        expect(describeLabelDisclosure(value.label ?? '')).toEqual([]);
      }
    }
  });

  it('keep the namespace, which names no cluster', async () => {
    const record = await source(api()).getAll('db-creds', { fallback: 'credential' });

    expect(record.fields.get('password')?.label).toBe(`${NAMESPACE}/db-creds#password`);
  });
});

describe('the registration test', () => {
  it('fails if a source implementation has no sweep entry', () => {
    expect(() => assertEverySourceSwept(k8sPackage, [])).toThrow(/no sweep entry/);
  });

  it('names both sources this package exports', () => {
    expect(() => assertEverySourceSwept(k8sPackage, ['K8sSecretSource'])).toThrow(
      /K8sMountedSource/
    );
    expect(() =>
      assertEverySourceSwept(k8sPackage, ['K8sSecretSource', 'K8sMountedSource'])
    ).not.toThrow();
  });
});
