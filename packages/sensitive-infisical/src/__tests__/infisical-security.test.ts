import { describe, it, expect } from 'vitest';
import { describeLabelDisclosure } from '@platform-sec/sensitive-string-secrets';
import type { SecretLoadEvent } from '@platform-sec/sensitive-string-secrets';
import {
  assertEverySourceSwept,
  assertNoCanary,
  sweep,
} from '@platform-sec/sensitive-string-secrets/testing';
import type { SweepCase } from '@platform-sec/sensitive-string-secrets/testing';

import * as infisicalPackage from '../index.js';
import { fetchTransport, InfisicalRequestError } from '../transport.js';
import {
  FakeTransport,
  PROJECT_ID,
  TEST_TOKEN,
  entry,
  secretsBody,
  source,
} from './fake-transport.js';

/** Exactly 20 characters, the length V8 echoes whole into a SyntaxError. */
const SHORT_CANARY = 'LEAKED_SECRET_abc123';
const CANARY = 'LEAKED_SECRET_abc123xyz';

function transport(): FakeTransport {
  return FakeTransport.of({
    'prod/backend': {
      body: secretsBody(entry('LOG_LEVEL', 'info'), entry('STRIPE_SECRET_KEY', CANARY)),
    },
    'prod/short': { body: secretsBody(entry('API_KEY', SHORT_CANARY)) },
    'prod/dotted': { body: secretsBody(entry('tls.key', CANARY)) },
    'prod/duplicated': {
      body: secretsBody(entry('API_KEY', CANARY), entry('API_KEY', 'from-an-import')),
    },
    'prod/keyless': { body: { secrets: [{ secretValue: CANARY }] } },
    'prod/shapeless': { body: { data: [] } },
    'prod/denied': { status: 403, messages: ['You do not have permission'] },
    'prod/broken': { status: 500, messages: ['Internal error'] },
  });
}

const CASES: readonly SweepCase[] = [
  {
    name: 'getAll on a mixed folder',
    run: () =>
      source(transport()).getAll('/backend', {
        rules: [{ pattern: /KEY/i, klass: 'credential' }],
        fallback: 'plain',
      }),
  },
  {
    name: 'getAll with everything closed',
    run: () => source(transport()).getAll('/backend', { fallback: 'credential' }),
  },
  {
    name: 'getAll on a folder with a dotted key',
    run: () => source(transport()).getAll('/dotted', { fallback: 'credential' }),
  },
  {
    name: 'getAll on a folder with a duplicate key',
    run: () => source(transport()).getAll('/duplicated', { fallback: 'credential' }),
  },
  {
    name: 'getAll on an entry with no key',
    run: () => source(transport()).getAll('/keyless', { fallback: 'credential' }),
  },
  {
    name: 'getAll on a body with no secrets array',
    run: () => source(transport()).getAll('/shapeless', { fallback: 'credential' }),
  },
  {
    name: 'getJson with a declared field the folder lacks',
    run: () => source(transport()).getJson('/backend', { fields: { MISSING: 'credential' } }),
  },
  {
    name: 'getJson on a 20-character secret',
    run: () => source(transport()).getJson('/short', { fields: { API_KEY: 'credential' } }),
  },
  {
    name: 'get on a folder that holds named fields',
    run: () => source(transport()).get('/backend'),
  },
  { name: 'an absent folder', run: () => source(transport()).get('/missing') },
  {
    name: 'a token without permission',
    run: () => source(transport()).getAll('/denied', { fallback: 'credential' }),
  },
  {
    name: 'a service failure',
    run: () => source(transport()).getAll('/broken', { fallback: 'credential' }),
  },
  {
    name: 'a read with no project id',
    run: () =>
      source(transport(), { projectId: undefined }).getAll('/backend', {
        fallback: 'credential',
      }),
  },
];

describe('the infisical sweep', () => {
  it('leaks the canary in no result and no error', async () => {
    const results = await sweep(CANARY, CASES);

    expect(results).toHaveLength(CASES.length);
  });

  it('leaks the 20-character canary either', async () => {
    await sweep(SHORT_CANARY, CASES);
  });

  it('leaks the token in no result and no error', async () => {
    await sweep(TEST_TOKEN, CASES);
  });

  it('forces failures rather than sweeping only happy paths', async () => {
    const results = await sweep(CANARY, CASES);

    expect(results.filter((result) => result.threw).length).toBeGreaterThan(5);
  });
});

describe('load events', () => {
  it('carry no secret material and no token', async () => {
    const events: SecretLoadEvent[] = [];
    const infisical = source(transport(), { onLoad: (event) => events.push(event) });

    await infisical.getAll('/backend', { fallback: 'credential' });

    assertNoCanary(CANARY, events, 'the infisical load events');
    assertNoCanary(TEST_TOKEN, events, 'the infisical load events');
  });

  it('carry the project id, which is metadata rather than a label', async () => {
    const events: SecretLoadEvent[] = [];
    const infisical = source(transport(), { onLoad: (event) => events.push(event) });

    await infisical.getAll('/backend', { fallback: 'credential' });

    expect(events[0]?.ref.metadata['projectId']).toBe(PROJECT_ID);
  });
});

describe('labels', () => {
  it('disclose nothing under the rule, and never the project id', async () => {
    const config = await source(transport()).getAll('/backend', { fallback: 'credential' });

    for (const value of config.fields.values()) {
      expect(describeLabelDisclosure(value.label ?? '')).toEqual([]);
      expect(value.label).not.toContain(PROJECT_ID);
    }
  });
});

describe('the transport', () => {
  it('does not put a response body into an error when the body is not JSON', async () => {
    const notJson = fetchTransport({
      fetch: () => Promise.resolve(new Response(CANARY, { status: 500 })),
    });

    const failure = await notJson
      .request({ path: 'api/v3/secrets/raw', query: {}, headers: {} })
      .catch((error: unknown) => error);

    expect((failure as Error).message).not.toContain(CANARY);
    expect((failure as { cause?: unknown }).cause).toBeUndefined();
  });

  it('carries Infisical own message, which describes scope rather than values', async () => {
    const denied = fetchTransport({
      fetch: () =>
        Promise.resolve(
          new Response(JSON.stringify({ message: 'You do not have permission' }), { status: 403 })
        ),
    });

    await expect(
      denied.request({ path: 'api/v3/secrets/raw', query: {}, headers: {} })
    ).rejects.toThrow(/do not have permission/);
  });

  it('reports a timeout as this package own error', async () => {
    const slow = fetchTransport({
      timeoutMs: 10,
      fetch: (_url, init) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => {
            reject(new DOMException('This operation was aborted', 'AbortError'));
          });
        }),
    });

    const failure = await slow
      .request({ path: 'api/v3/secrets/raw', query: {}, headers: {} })
      .catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(InfisicalRequestError);
    expect((failure as InfisicalRequestError).status).toBe(0);
  });
});

describe('the registration test', () => {
  it('fails if a source implementation has no sweep entry', () => {
    expect(() => assertEverySourceSwept(infisicalPackage, [])).toThrow(
      /no sweep entry: InfisicalSecretSource/
    );
  });

  it('passes now that InfisicalSecretSource is swept', () => {
    expect(() => assertEverySourceSwept(infisicalPackage, ['InfisicalSecretSource'])).not.toThrow();
  });
});
