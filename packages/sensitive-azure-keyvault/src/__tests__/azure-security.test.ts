import { describe, it, expect } from 'vitest';
import { describeLabelDisclosure } from '@platform-sec/sensitive-string-secrets';
import type { SecretLoadEvent } from '@platform-sec/sensitive-string-secrets';
import {
  assertEverySourceSwept,
  assertNoCanary,
  sweep,
} from '@platform-sec/sensitive-string-secrets/testing';
import type { SweepCase } from '@platform-sec/sensitive-string-secrets/testing';

import * as azurePackage from '../index.js';
import { FakeSecretClient, VAULT_URL, azureError, keyVaultSecret, source } from './fake-client.js';

/** Exactly 20 characters, the length V8 echoes whole into a SyntaxError. */
const SHORT_CANARY = 'LEAKED_SECRET_abc123';
const CANARY = 'LEAKED_SECRET_abc123xyz';
const FUTURE = new Date(Date.now() + 86_400_000);
const PAST = new Date(Date.now() - 86_400_000);

function client(): FakeSecretClient {
  return FakeSecretClient.of({
    'payments-api-key': { value: CANARY },
    'short-key': { value: SHORT_CANARY },
    'db-credentials': { value: JSON.stringify({ username: 'app', password: CANARY }) },
    'nested-credentials': { value: JSON.stringify({ db: { password: CANARY } }) },
    'dotted-credentials': { value: JSON.stringify({ 'tls.key': CANARY }) },
    'array-credentials': { value: JSON.stringify([CANARY]) },
    'expired-key': { value: CANARY, properties: { expiresOn: PAST } },
    'future-key': { value: CANARY, properties: { notBefore: FUTURE } },
    'valueless-key': {},
    'tagged-key': { value: CANARY, properties: { tags: { owner: 'payments' } } },
    'denied-key': { error: azureError(403, 'Forbidden', 'caller is not authorized') },
    'broken-key': { error: azureError(500, 'InternalServerError', 'an internal error') },
  });
}

const CASES: readonly SweepCase[] = [
  { name: 'get on a single-value secret', run: () => source(client()).get('payments-api-key') },
  { name: 'get on a secret with no value', run: () => source(client()).get('valueless-key') },
  { name: 'get on an expired secret', run: () => source(client()).get('expired-key') },
  {
    name: 'reveal of an expired secret',
    run: async () => {
      const record = await source(client()).get('expired-key');

      return record.value.reveal({ name: 'sweep' });
    },
  },
  { name: 'get on a future-dated secret', run: () => source(client()).get('future-key') },
  { name: 'get on a tagged secret', run: () => source(client()).get('tagged-key') },
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
    run: () => source(client()).getJson('payments-api-key', { fields: { key: 'credential' } }),
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
  { name: 'a server failure', run: () => source(client()).get('broken-key') },
  {
    name: 'a read by full secret identifier',
    run: () => source(client()).get(`${VAULT_URL}/secrets/payments-api-key/abc123`),
  },
];

describe('the azure sweep', () => {
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
    expect(JSON.stringify(keyVaultSecret('x', { value: CANARY }))).toContain(CANARY);
  });
});

describe('load events', () => {
  it('carry no secret material for any read this package makes', async () => {
    const events: SecretLoadEvent[] = [];
    const azure = source(client(), { onLoad: (event) => events.push(event) });

    await azure.getAll('db-credentials', { fallback: 'credential' });
    await azure.getAll('nested-credentials', { fallback: 'credential' });
    await azure.get('tagged-key');

    assertNoCanary(CANARY, events, 'the azure load events');
  });
});

describe('labels', () => {
  it('disclose nothing under the rule, and never the vault URL', async () => {
    const azure = source(client());

    for (const path of [
      'db-credentials',
      'nested-credentials',
      'dotted-credentials',
      `${VAULT_URL}/secrets/db-credentials`,
    ]) {
      const record = await azure.getAll(path, { fallback: 'credential' });

      for (const value of record.fields.values()) {
        expect(describeLabelDisclosure(value.label ?? '')).toEqual([]);
        expect(value.label).not.toContain('vault.azure.net');
      }
    }
  });
});

describe('the registration test', () => {
  it('fails if a source implementation has no sweep entry', () => {
    expect(() => assertEverySourceSwept(azurePackage, [])).toThrow(
      /no sweep entry: AzureSecretSource/
    );
  });

  it('passes now that AzureSecretSource is swept', () => {
    expect(() => assertEverySourceSwept(azurePackage, ['AzureSecretSource'])).not.toThrow();
  });
});
