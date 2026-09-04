import { describe, it, expect } from 'vitest';
import { describeLabelDisclosure } from '@platform-sec/sensitive-string-secrets';
import type { SecretLoadEvent } from '@platform-sec/sensitive-string-secrets';
import {
  assertEverySourceSwept,
  assertNoCanary,
  sweep,
} from '@platform-sec/sensitive-string-secrets/testing';
import type { SweepCase } from '@platform-sec/sensitive-string-secrets/testing';

import * as ociPackage from '../index.js';
import { FakeSecretsClient, SECRET_OCID, bundle, ociError, source } from './fake-client.js';

/** Exactly 20 characters, the length V8 echoes whole into a SyntaxError. */
const SHORT_CANARY = 'LEAKED_SECRET_abc123';
const CANARY = 'LEAKED_SECRET_abc123xyz';

function client(): FakeSecretsClient {
  return FakeSecretsClient.of({
    'prod-stripe-key': { value: CANARY },
    'short-key': { value: SHORT_CANARY },
    'prod-db': { value: JSON.stringify({ username: 'app', password: CANARY }) },
    'nested-db': { value: JSON.stringify({ db: { password: CANARY } }) },
    'dotted-db': { value: JSON.stringify({ 'tls.key': CANARY }) },
    'array-db': { value: JSON.stringify([CANARY]) },
    'plaintext-key': { value: CANARY, contentType: 'PLAINTEXT' },
    'not-base64': { rawContent: `${CANARY}!!!` },
    'empty-bundle': { omitContent: true },
    'denied-key': { error: ociError(401, 'NotAuthenticated') },
    'broken-key': { error: ociError(500, 'InternalServerError') },
    [SECRET_OCID]: { value: CANARY },
  });
}

const CASES: readonly SweepCase[] = [
  { name: 'get on a single-value secret', run: () => source(client()).get('prod-stripe-key') },
  {
    name: 'get on a bundle with an unrecognized content type',
    run: () => source(client()).get('plaintext-key'),
  },
  {
    name: 'get on a bundle whose content is not base64',
    run: () => source(client()).get('not-base64'),
  },
  { name: 'get on a bundle with no content', run: () => source(client()).get('empty-bundle') },
  {
    name: 'getJson on a JSON secret',
    run: () => source(client()).getJson('prod-db', { fields: { password: 'credential' } }),
  },
  {
    name: 'getJson with a declared field the payload lacks',
    run: () => source(client()).getJson('prod-db', { fields: { missing: 'credential' } }),
  },
  {
    name: 'getJson on a secret that is not JSON',
    run: () => source(client()).getJson('prod-stripe-key', { fields: { key: 'credential' } }),
  },
  {
    name: 'getJson on a 20-character secret that is not JSON',
    run: () => source(client()).getJson('short-key', { fields: { key: 'credential' } }),
  },
  {
    name: 'getJson on a payload that decodes to an array',
    run: () => source(client()).getJson('array-db', { fields: { key: 'credential' } }),
  },
  {
    name: 'getAll on a JSON secret',
    run: () => source(client()).getAll('prod-db', { fallback: 'credential' }),
  },
  {
    name: 'getAll on a nested payload',
    run: () => source(client()).getAll('nested-db', { fallback: 'credential' }),
  },
  {
    name: 'getAll on a payload with a dotted key',
    run: () => source(client()).getAll('dotted-db', { fallback: 'credential' }),
  },
  { name: 'an absent secret', run: () => source(client()).get('missing-key') },
  { name: 'an authentication failure', run: () => source(client()).get('denied-key') },
  { name: 'a service failure', run: () => source(client()).get('broken-key') },
  { name: 'a read by OCID with no label', run: () => source(client()).get(SECRET_OCID) },
  {
    name: 'a read by OCID with a label',
    run: () => source(client()).get(SECRET_OCID, { label: 'prod-stripe-key' }),
  },
  {
    name: 'a URL pasted into the path',
    run: () => source(client()).get('https://vault.internal:8200/prod-stripe-key'),
  },
  {
    name: 'a read by name with no vault configured',
    run: () => source(client(), { vaultId: undefined }).get('prod-stripe-key'),
  },
];

describe('the oci sweep', () => {
  it('leaks the canary in no result and no error', async () => {
    const results = await sweep(CANARY, CASES);

    expect(results).toHaveLength(CASES.length);
  });

  it('leaks the 20-character canary either', async () => {
    await sweep(SHORT_CANARY, CASES);
  });

  it('forces failures rather than sweeping only happy paths', async () => {
    const results = await sweep(CANARY, CASES);

    expect(results.filter((result) => result.threw).length).toBeGreaterThan(6);
  });
});

describe('the fixtures', () => {
  it('carry a canary, so a fixture that leaks is caught like a real one', () => {
    const content = bundle({ value: CANARY }).secretBundleContent?.content ?? '';

    expect(Buffer.from(content, 'base64').toString('utf8')).toBe(CANARY);
  });
});

describe('load events', () => {
  it('carry no secret material for any read this package makes', async () => {
    const events: SecretLoadEvent[] = [];
    const oci = source(client(), { onLoad: (event) => events.push(event) });

    await oci.getAll('prod-db', { fallback: 'credential' });
    await oci.getAll('nested-db', { fallback: 'credential' });
    await oci.get(SECRET_OCID, { label: 'prod-stripe-key' });

    assertNoCanary(CANARY, events, 'the oci load events');
  });
});

describe('labels', () => {
  it('disclose nothing under the rule, and never an OCID', async () => {
    const oci = source(client());

    for (const path of ['prod-db', 'nested-db', 'dotted-db']) {
      const record = await oci.getAll(path, { fallback: 'credential' });

      for (const value of record.fields.values()) {
        expect(describeLabelDisclosure(value.label ?? '')).toEqual([]);
        expect(value.label).not.toContain('ocid1');
      }
    }
  });

  it('are refused rather than derived from an OCID', () => {
    // `describeLabelDisclosure` would flag it, and this package does not get
    // that far: an OCID never becomes a label in the first place.
    expect(describeLabelDisclosure(SECRET_OCID)).toContain('OCID');
  });
});

describe('the registration test', () => {
  it('fails if a source implementation has no sweep entry', () => {
    expect(() => assertEverySourceSwept(ociPackage, [])).toThrow(/no sweep entry: OciSecretSource/);
  });

  it('passes now that OciSecretSource is swept', () => {
    expect(() => assertEverySourceSwept(ociPackage, ['OciSecretSource'])).not.toThrow();
  });
});
