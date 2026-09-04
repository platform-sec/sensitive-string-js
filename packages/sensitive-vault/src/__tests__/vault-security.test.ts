import { describe, it, expect } from 'vitest';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { describeLabelDisclosure } from '@platform-sec/sensitive-string-secrets';
import type { SecretLoadEvent } from '@platform-sec/sensitive-string-secrets';
import {
  assertEverySourceSwept,
  assertNoCanary,
  sweep,
} from '@platform-sec/sensitive-string-secrets/testing';
import type { SweepCase } from '@platform-sec/sensitive-string-secrets/testing';
import { put, putJson } from '@platform-sec/sensitive-string-secrets/write';

import * as vaultPackage from '../index.js';
import { fetchTransport } from '../transport.js';
import {
  FakeTransport,
  TEST_TOKEN,
  dynamicBody,
  kvV1Body,
  kvV2Body,
  source,
  vaultToken,
} from './fake-transport.js';

/**
 * The provider sweep, against this package's own fixtures.
 *
 * Every secret-bearing field in a fixture carries a canary, so a fixture that
 * leaks through a code path is caught by the same sweep that would catch a real
 * leak. Nothing here calls a live Vault.
 */

/** Exactly 20 characters, the length V8 echoes whole into a SyntaxError. */
const SHORT_CANARY = 'LEAKED_SECRET_abc123';
const CANARY = 'LEAKED_SECRET_abc123xyz';
const CONTEXT = { name: 'sweep', reason: 'test' };

function transport(): FakeTransport {
  return FakeTransport.of({
    'kv/data/prod/db': { body: kvV2Body({ username: 'app', password: CANARY }) },
    'kv/data/prod/short': { body: kvV2Body({ password: SHORT_CANARY }) },
    // A KV v1 response arriving where v2 was configured, which is the wire
    // shape mistake this package has a diagnostic for.
    'kv/data/prod/mismatch': { body: kvV1Body({ password: CANARY }) },
    'kv/data/prod/denied': { status: 403, errors: ['permission denied'] },
    'kv/data/prod/broken': { status: 500 },
    'kv/data/prod/nested': { body: kvV2Body({ db: { password: CANARY } }) },
    'database/creds/app': { body: dynamicBody({ password: CANARY }) },
    'database/creds/empty': { body: { lease_id: 'x', lease_duration: 60 } },
    'sys/leases/renew': { body: { lease_duration: 60 } },
    'sys/leases/revoke': { status: 204 },
    'sys/wrapping/unwrap': { body: { data: { password: CANARY } } },
    'POST kv/data/prod/db': { body: { data: { version: 8 } } },
    'auth/token/renew-self': { status: 403, errors: ['permission denied'] },
  });
}

const CASES: readonly SweepCase[] = [
  {
    name: 'getJson on a KV v2 path',
    run: () => source(transport()).getJson('kv/prod/db', { fields: { password: 'credential' } }),
  },
  {
    name: 'getJson with a declared field the payload lacks',
    run: () => source(transport()).getJson('kv/prod/db', { fields: { missing: 'credential' } }),
  },
  {
    name: 'getAll on a KV v2 path',
    run: () => source(transport()).getAll('kv/prod/db', { fallback: 'credential' }),
  },
  {
    name: 'getAll on a nested payload',
    run: () => source(transport()).getAll('kv/prod/nested', { fallback: 'credential' }),
  },
  {
    name: 'get on a path that holds named fields',
    run: () => source(transport()).get('kv/prod/db'),
  },
  {
    name: 'a KV v1 response where v2 was configured',
    run: () => source(transport()).getAll('kv/prod/mismatch', { fallback: 'credential' }),
  },
  {
    name: 'a KV v2 response where v1 was configured',
    run: () =>
      source(transport(), { mounts: [{ path: 'kv', kv: 1 }] }).getAll('kv/prod/db', {
        fallback: 'credential',
      }),
  },
  {
    name: 'an authorization failure',
    run: () => source(transport()).getAll('kv/prod/denied', { fallback: 'credential' }),
  },
  {
    name: 'a server failure',
    run: () => source(transport()).getAll('kv/prod/broken', { fallback: 'credential' }),
  },
  {
    name: 'an absent secret',
    run: () => source(transport()).get('kv/prod/missing'),
  },
  {
    name: 'a URL pasted into the path',
    run: () =>
      source(transport()).getAll('https://vault.internal:8200/v1/kv/data/prod/db', {
        fallback: 'credential',
      }),
  },
  {
    name: 'a dynamic secret',
    run: () => source(transport()).dynamic('database/creds/app'),
  },
  {
    name: 'a dynamic secret with no fields',
    run: () => source(transport()).dynamic('database/creds/empty'),
  },
  {
    name: 'a dynamic lease renewal',
    run: async () => {
      const lease = await source(transport()).dynamic('database/creds/app');

      return await lease.renew();
    },
  },
  {
    name: 'a dynamic lease revocation',
    run: async () => {
      const lease = await source(transport()).dynamic('database/creds/app');

      return await lease.revoke();
    },
  },
  {
    name: 'an unwrap',
    run: () =>
      source(transport()).unwrap(new SensitiveString(CANARY, 'credential'), {
        fallback: 'credential',
      }),
  },
  {
    name: 'a wrap where the response came back unwrapped',
    run: () => source(transport()).getWrapped('kv/prod/db', 60),
  },
  {
    name: 'a token renewal that is denied',
    run: () => source(transport()).renewToken(),
  },
  {
    name: 'a write of a stringified instance',
    run: () =>
      putJson(
        source(transport()),
        'kv/prod/db',
        // eslint-disable-next-line @typescript-eslint/restrict-template-expressions -- the implicit coercion is the subject of this case
        { password: `${new SensitiveString(CANARY, 'credential')}` },
        { context: CONTEXT }
      ),
  },
  {
    name: 'a single-value write of a path that holds named fields',
    run: () => put(source(transport()), 'kv/prod/db', CANARY, { context: CONTEXT }),
  },
];

describe('the vault sweep', () => {
  it('leaks the canary in no result and no error', async () => {
    const results = await sweep(CANARY, CASES);

    expect(results).toHaveLength(CASES.length);
  });

  it('leaks the 20-character canary either', async () => {
    await sweep(SHORT_CANARY, CASES);
  });

  it('leaks the client token in no result and no error', async () => {
    await sweep(TEST_TOKEN, CASES);
  });

  it('forces failures rather than sweeping only happy paths', async () => {
    const results = await sweep(CANARY, CASES);

    expect(results.filter((result) => result.threw).length).toBeGreaterThan(7);
  });
});

describe('the fixtures', () => {
  it('carry a canary, so a fixture that leaks is caught like a real one', () => {
    const body = JSON.stringify(kvV2Body({ password: CANARY }));

    expect(body).toContain(CANARY);
  });
});

describe('load events', () => {
  it('carry no secret material for any read this package makes', async () => {
    const events: SecretLoadEvent[] = [];
    const vault = source(transport(), { onLoad: (event) => events.push(event) });

    await vault.getAll('kv/prod/db', { fallback: 'credential' });
    await vault.getAll('kv/prod/nested', { fallback: 'credential' });

    assertNoCanary(CANARY, events, 'the vault load events');
    assertNoCanary(TEST_TOKEN, events, 'the vault load events');
  });
});

describe('labels', () => {
  it('disclose nothing under the rule, for every field of every fixture', async () => {
    const vault = source(transport());

    for (const path of ['kv/prod/db', 'kv/prod/nested']) {
      const record = await vault.getAll(path, { fallback: 'credential' });

      for (const value of record.fields.values()) {
        expect(describeLabelDisclosure(value.label ?? '')).toEqual([]);
      }
    }
  });

  it('disclose nothing for a dynamic secret either', async () => {
    const lease = await source(transport()).dynamic('database/creds/app');

    for (const value of lease.fields.values()) {
      expect(describeLabelDisclosure(value.label ?? '')).toEqual([]);
    }
  });
});

describe('the transport', () => {
  it('does not put a response body into an error when the body is not JSON', async () => {
    const notJson = fetchTransport({
      endpoint: 'https://vault.test',
      fetch: () =>
        Promise.resolve(
          new Response(CANARY, { status: 500, headers: { 'content-type': 'text/plain' } })
        ),
    });

    try {
      await notJson.request({ method: 'GET', path: 'kv/data/prod/db', headers: {} });
      expect.unreachable('the request should have failed');
    } catch (error) {
      expect((error as Error).message).not.toContain(CANARY);
      expect((error as { cause?: unknown }).cause).toBeUndefined();
    }
  });

  it('carries Vault own errors array, which describes policy rather than values', async () => {
    const denied = fetchTransport({
      endpoint: 'https://vault.test',
      fetch: () =>
        Promise.resolve(
          new Response(JSON.stringify({ errors: ['permission denied'] }), { status: 403 })
        ),
    });

    await expect(
      denied.request({ method: 'GET', path: 'kv/data/prod/db', headers: {} })
    ).rejects.toThrow(/permission denied/);
  });

  it('can be told to leave the server errors out', async () => {
    const quiet = fetchTransport({
      endpoint: 'https://vault.test',
      includeServerErrors: false,
      fetch: () =>
        Promise.resolve(
          new Response(JSON.stringify({ errors: ['permission denied'] }), { status: 403 })
        ),
    });

    await expect(
      quiet.request({ method: 'GET', path: 'kv/data/prod/db', headers: {} })
    ).rejects.toThrow(/failed with status 403\.$/);
  });

  it('never returns the Response object, so no caller can reach a body twice', async () => {
    const ok = fetchTransport({
      endpoint: 'https://vault.test',
      fetch: () => Promise.resolve(new Response(JSON.stringify({ data: { a: 'b' } }))),
    });

    const response = await ok.request({ method: 'GET', path: 'kv/data/a', headers: {} });

    expect(Object.keys(response).sort()).toEqual(['body', 'status']);
  });
});

describe('the registration test', () => {
  it('fails if a source implementation has no sweep entry', () => {
    expect(() => assertEverySourceSwept(vaultPackage, [])).toThrow(
      /no sweep entry: VaultSecretSource/
    );
  });

  it('passes now that VaultSecretSource is swept', () => {
    expect(() => assertEverySourceSwept(vaultPackage, ['VaultSecretSource'])).not.toThrow();
  });
});

describe('the client token', () => {
  it('is a SensitiveString, so it renders as a marker wherever it is logged', () => {
    expect(String(vaultToken())).not.toContain(TEST_TOKEN);
  });
});
