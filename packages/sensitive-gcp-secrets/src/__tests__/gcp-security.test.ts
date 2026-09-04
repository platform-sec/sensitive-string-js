import { describe, it, expect } from 'vitest';
import { describeLabelDisclosure } from '@platform-sec/sensitive-string-secrets';
import type { SecretLoadEvent } from '@platform-sec/sensitive-string-secrets';
import {
  assertEverySourceSwept,
  assertNoCanary,
  sweep,
} from '@platform-sec/sensitive-string-secrets/testing';
import type { SweepCase } from '@platform-sec/sensitive-string-secrets/testing';

import * as gcpPackage from '../index.js';
import { crc32c } from '../crc32c.js';
import {
  FakeSecretManager,
  PROJECT,
  accessResponse,
  gaxError,
  secretResource,
  source,
} from './fake-client.js';

/** Exactly 20 characters, the length V8 echoes whole into a SyntaxError. */
const SHORT_CANARY = 'LEAKED_SECRET_abc123';
const CANARY = 'LEAKED_SECRET_abc123xyz';

function client(): FakeSecretManager {
  const base = `projects/${PROJECT}/secrets`;

  return FakeSecretManager.of({
    [`${base}/stripe-api-key/versions/latest`]: {
      value: CANARY,
      secret: secretResource('stripe-api-key'),
    },
    [`${base}/short-key/versions/latest`]: { value: SHORT_CANARY },
    [`${base}/db-credentials/versions/latest`]: {
      value: JSON.stringify({ username: 'app', password: CANARY }),
    },
    [`${base}/nested-credentials/versions/latest`]: {
      value: JSON.stringify({ db: { password: CANARY } }),
    },
    [`${base}/dotted-credentials/versions/latest`]: {
      value: JSON.stringify({ 'tls.key': CANARY }),
    },
    [`${base}/array-credentials/versions/latest`]: { value: JSON.stringify([CANARY]) },
    [`${base}/corrupt-key/versions/latest`]: {
      value: CANARY,
      crc: crc32c(Buffer.from('something else')),
    },
    [`${base}/unchecked-key/versions/latest`]: { value: CANARY, omitCrc: true },
    [`${base}/denied-key/versions/latest`]: { error: gaxError(7, 'permission denied') },
    [`${base}/broken-key/versions/latest`]: { error: gaxError(13, 'an internal error') },
  });
}

const CASES: readonly SweepCase[] = [
  { name: 'get on a single-value secret', run: () => source(client()).get('stripe-api-key') },
  {
    name: 'get on a secret with a corrupt payload',
    run: () => source(client()).get('corrupt-key'),
  },
  {
    name: 'get on a secret with no checksum, where one is required',
    run: () => source(client(), { requireChecksum: true }).get('unchecked-key'),
  },
  {
    name: 'getJson on a JSON secret',
    run: () => source(client()).getJson('db-credentials', { fields: { password: 'credential' } }),
  },
  {
    name: 'getJson with a declared field the payload lacks',
    run: () => source(client()).getJson('db-credentials', { fields: { missing: 'credential' } }),
  },
  {
    name: 'getJson on a secret that is not JSON',
    run: () => source(client()).getJson('stripe-api-key', { fields: { key: 'credential' } }),
  },
  {
    name: 'getJson on a 20-character secret that is not JSON',
    run: () => source(client()).getJson('short-key', { fields: { key: 'credential' } }),
  },
  {
    name: 'getJson on a payload that decodes to an array',
    run: () => source(client()).getJson('array-credentials', { fields: { key: 'credential' } }),
  },
  {
    name: 'getAll on a JSON secret',
    run: () => source(client()).getAll('db-credentials', { fallback: 'credential' }),
  },
  {
    name: 'getAll on a nested payload',
    run: () => source(client()).getAll('nested-credentials', { fallback: 'credential' }),
  },
  {
    name: 'getAll on a payload with a dotted key',
    run: () => source(client()).getAll('dotted-credentials', { fallback: 'credential' }),
  },
  { name: 'an absent secret', run: () => source(client()).get('missing-key') },
  { name: 'an authorization failure', run: () => source(client()).get('denied-key') },
  { name: 'a service failure', run: () => source(client()).get('broken-key') },
  {
    name: 'a read that also reads the secret resource',
    run: () => source(client(), { readExpiry: true }).get('stripe-api-key'),
  },
  {
    name: 'a short name with no project to resolve it against',
    run: () => source(client(), { project: undefined }).get('stripe-api-key'),
  },
];

describe('the gcp sweep', () => {
  it('leaks the canary in no result and no error', async () => {
    const results = await sweep(CANARY, CASES);

    expect(results).toHaveLength(CASES.length);
  });

  it('leaks the 20-character canary either', async () => {
    await sweep(SHORT_CANARY, CASES);
  });

  it('forces failures rather than sweeping only happy paths', async () => {
    const results = await sweep(CANARY, CASES);

    expect(results.filter((result) => result.threw).length).toBeGreaterThan(5);
  });
});

describe('the fixtures', () => {
  it('carry a canary, so a fixture that leaks is caught like a real one', () => {
    const response = accessResponse('projects/p/secrets/s/versions/1', { value: CANARY });

    expect(Buffer.from(response.payload?.data as Uint8Array).toString('utf8')).toBe(CANARY);
  });
});

describe('load events', () => {
  it('carry no secret material for any read this package makes', async () => {
    const events: SecretLoadEvent[] = [];
    const gcp = source(client(), { onLoad: (event) => events.push(event), readExpiry: true });

    await gcp.getAll('db-credentials', { fallback: 'credential' });
    await gcp.getAll('nested-credentials', { fallback: 'credential' });
    await gcp.get('stripe-api-key');

    assertNoCanary(CANARY, events, 'the gcp load events');
  });
});

describe('labels', () => {
  it('disclose nothing under the rule, and never the project number', async () => {
    const gcp = source(client());

    for (const path of [
      'db-credentials',
      'nested-credentials',
      'dotted-credentials',
      `projects/${PROJECT}/secrets/db-credentials`,
    ]) {
      const record = await gcp.getAll(path, { fallback: 'credential' });

      for (const value of record.fields.values()) {
        expect(describeLabelDisclosure(value.label ?? '')).toEqual([]);
        expect(value.label).not.toContain(PROJECT);
      }
    }
  });
});

describe('the registration test', () => {
  it('fails if a source implementation has no sweep entry', () => {
    expect(() => assertEverySourceSwept(gcpPackage, [])).toThrow(/no sweep entry: GcpSecretSource/);
  });

  it('passes now that GcpSecretSource is swept', () => {
    expect(() => assertEverySourceSwept(gcpPackage, ['GcpSecretSource'])).not.toThrow();
  });
});
