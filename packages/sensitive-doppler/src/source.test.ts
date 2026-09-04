import { describe, it, expect } from 'vitest';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import {
  SecretNotFoundError,
  SecretPayloadError,
  describeLabelDisclosure,
} from '@platform-sec/sensitive-string-secrets';

import { DOPPLER_RESERVED_KEYS } from './source.js';
import { DopplerRequestError, fetchTransport } from './transport.js';
import { FakeTransport, TEST_TOKEN, dopplerToken, source } from './__tests__/fake-transport.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

function transport(): FakeTransport {
  return FakeTransport.of({
    'payments/prod': {
      body: {
        DOPPLER_PROJECT: 'payments',
        DOPPLER_CONFIG: 'prod',
        DOPPLER_ENVIRONMENT: 'prod',
        LOG_LEVEL: 'info',
        PORT: '8080',
        STRIPE_SECRET_KEY: CANARY,
        DATABASE_URL: CANARY,
      },
    },
    'payments/denied': { status: 403, messages: ['You do not have access to this config'] },
    'payments/broken': { status: 500, messages: ['Internal error'] },
    'payments/array': { body: [CANARY] },
    'other/prod': { body: { API_KEY: CANARY } },
  });
}

describe('DopplerSecretSource.getAll', () => {
  it('classifies a mixed config by rule', () => {
    return source(transport())
      .getAll('prod', {
        rules: [{ pattern: /KEY|SECRET|URL/i, klass: 'credential' }],
        fallback: 'plain',
      })
      .then((config) => {
        expect(config.fields.get('STRIPE_SECRET_KEY')).toBeInstanceOf(SensitiveString);
        expect(config.fields.get('DATABASE_URL')?.klass).toBe('credential');
        expect(config.plain.get('LOG_LEVEL')).toBe('info');
        expect(config.plain.get('PORT')).toBe('8080');
      });
  });

  it('labels each key under the project and config', async () => {
    const config = await source(transport()).getAll('prod', { fallback: 'credential' });
    const label = config.fields.get('STRIPE_SECRET_KEY')?.label ?? '';

    expect(label).toBe('payments/prod#STRIPE_SECRET_KEY');
    expect(describeLabelDisclosure(label)).toEqual([]);
  });

  it('sends the project and config as query parameters', async () => {
    const fake = transport();
    await source(fake).getAll('prod', { fallback: 'credential' });

    expect(fake.requests[0]?.query).toMatchObject({
      project: 'payments',
      config: 'prod',
      format: 'json',
    });
  });

  it('takes a project/config path over the configured project', async () => {
    const fake = transport();
    const config = await source(fake).getAll('other/prod', { fallback: 'credential' });

    expect(fake.requests[0]?.query).toMatchObject({ project: 'other', config: 'prod' });
    expect(config.ref.path).toBe('other/prod');
  });

  it('reports no version, rather than inventing one', async () => {
    const config = await source(transport()).getAll('prod', { fallback: 'credential' });

    expect(config.ref.version).toBe('unknown');
  });

  it('refuses a response that is not a map', async () => {
    await expect(source(transport()).getAll('array', { fallback: 'credential' })).rejects.toThrow(
      SecretPayloadError
    );
  });
});

describe('the reserved keys', () => {
  it('are the ones an application reads as configuration', async () => {
    const config = await source(transport()).getAll('prod', {
      fields: Object.fromEntries(DOPPLER_RESERVED_KEYS.map((key) => [key, 'plain' as const])),
      fallback: 'credential',
    });

    for (const key of DOPPLER_RESERVED_KEYS) {
      expect(config.plain.get(key)).toBeDefined();
    }
  });
});

describe('DopplerSecretSource.getOptional', () => {
  it('returns null for an absent config', async () => {
    expect(await source(transport()).getOptional('missing')).toBeNull();
  });

  it('keeps throwing for a token whose scope does not cover the config', async () => {
    await expect(source(transport()).getOptional('denied')).rejects.toThrow(/do not have access/);
  });

  it('reports absence through SecretNotFoundError on getAll', async () => {
    await expect(source(transport()).getAll('missing', { fallback: 'credential' })).rejects.toThrow(
      SecretNotFoundError
    );
  });
});

describe('the token', () => {
  it('must be a SensitiveString', () => {
    expect(() => source(transport(), { token: TEST_TOKEN as never })).toThrow(
      /needs the token as a SensitiveString/
    );
  });

  it('renders as a marker wherever it is logged', () => {
    expect(String(dopplerToken())).not.toContain(TEST_TOKEN);
  });

  it('is sent as a bearer token', async () => {
    const fake = transport();
    await source(fake).getAll('prod', { fallback: 'credential' });

    expect(fake.requests[0]?.headers['authorization']).toBe(`Bearer ${TEST_TOKEN}`);
  });
});

describe('the transport', () => {
  it('does not put a response body into an error when the body is not JSON', async () => {
    const notJson = fetchTransport({
      fetch: () => Promise.resolve(new Response(CANARY, { status: 500 })),
    });

    const failure = await notJson
      .request({ path: 'v3/configs/config/secrets/download', query: {}, headers: {} })
      .catch((error: unknown) => error);

    expect((failure as Error).message).not.toContain(CANARY);
    expect((failure as { cause?: unknown }).cause).toBeUndefined();
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
      .request({ path: 'v3/configs/config/secrets/download', query: {}, headers: {} })
      .catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(DopplerRequestError);
    expect((failure as DopplerRequestError).status).toBe(0);
    expect((failure as Error).message).toMatch(/timed out after 10ms/);
  });

  it('can be told to leave the server messages out', async () => {
    const quiet = fetchTransport({
      includeServerErrors: false,
      fetch: () =>
        Promise.resolve(
          new Response(JSON.stringify({ messages: ['You do not have access'] }), { status: 403 })
        ),
    });

    await expect(
      quiet.request({ path: 'v3/configs/config/secrets/download', query: {}, headers: {} })
    ).rejects.toThrow(/failed with status 403\.$/);
  });

  it('never returns the Response object', async () => {
    const ok = fetchTransport({
      fetch: () => Promise.resolve(new Response(JSON.stringify({ A: 'b' }))),
    });

    const response = await ok.request({ path: 'x', query: {}, headers: {} });

    expect(Object.keys(response).sort()).toEqual(['body', 'status']);
  });
});
