import { inspect } from 'node:util';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ResponseDecodeError, bearer } from '@platform-sec/sensitive-string-http';
import { findRawValue } from '@platform-sec/sensitive-string-testing';
import type { AxiosError } from 'axios';

import { createSensitiveAxios } from '../client.js';
import { CANARY, instance, startRecordingServer, token } from './fixtures.js';
import type { RecordingServer } from './fixtures.js';

/**
 * The section 2.3 and 2.6 regression suites.
 *
 * Every assertion here fails against a bare axios today, which is what makes
 * them regression tests rather than aspiration. The bare-client half is
 * asserted first in each case, so the suite records the behaviour it is
 * compensating for and fails if axios ever fixes it.
 */

let server: RecordingServer;

beforeEach(async () => {
  server = await startRecordingServer();
});

afterEach(async () => {
  await server.close();
});

function everywhere(value: unknown): string {
  const error = value as AxiosError;
  const parts = [
    error.message,
    JSON.stringify(value),
    inspect(value, { depth: 8 }),
    typeof error.toJSON === 'function' ? JSON.stringify(error.toJSON()) : '',
  ];

  return parts.join('\n');
}

describe('the error is a second wire', () => {
  beforeEach(() => {
    server.reply({ status: 401, body: '{"error":"unauthorized"}' });
  });

  it('a bare axios discloses the credential in config, in inspect and in toJSON', async () => {
    const client = instance(server);

    await expect(
      client.get('/x', { headers: { Authorization: `Bearer ${CANARY}` } })
    ).rejects.toSatisfy((error: unknown) => everywhere(error).includes(CANARY));
  });

  it('the wrapper leaves nothing in message, JSON, inspect or toJSON', async () => {
    const api = createSensitiveAxios(instance(server), { allowInsecureTransport: true });

    const error = await api
      .get('/x', { headers: { Authorization: bearer(token()) } })
      .then(() => undefined)
      .catch((caught: unknown) => caught);

    expect(error).toBeDefined();
    expect(everywhere(error)).not.toContain(CANARY);
    expect((error as AxiosError).config?.headers?.['Authorization']).toBe('[REDACTED:credential]');

    // Stronger than `util.inspect`, which stops at a depth and skips symbols:
    // this walks every reachable own property and reports the path of a hit.
    expect(findRawValue(error, CANARY)).toBeUndefined();
  });

  it('drops error.request, the ClientRequest no supported API can rewrite', async () => {
    const api = createSensitiveAxios(instance(server), { allowInsecureTransport: true });

    const error = await api
      .get('/x', { headers: { Authorization: bearer(token()) } })
      .catch((caught: unknown) => caught);

    expect((error as { request?: unknown }).request).toBeUndefined();
  });

  it('scrubs a body field and a query value the same way', async () => {
    const api = createSensitiveAxios(instance(server), { allowInsecureTransport: true });

    const error = await api
      .post('/x', { card: { number: token() } }, { params: { trace: token() } })
      .catch((caught: unknown) => caught);

    expect(everywhere(error)).not.toContain(CANARY);
    expect(findRawValue(error, CANARY)).toBeUndefined();
  });

  it('returns the client error untouched when the request carried nothing sensitive', async () => {
    const api = createSensitiveAxios(instance(server), { allowInsecureTransport: true });

    const error = (await api.get('/x').catch((caught: unknown) => caught)) as AxiosError;

    expect(error.request).toBeDefined();
    expect(error.config?.headers).toBeDefined();
  });
});

describe('the success path retains it too', () => {
  it('a bare axios discloses the credential from a 200 response object', async () => {
    const client = instance(server);
    const response = await client.get('/x', { headers: { Authorization: `Bearer ${CANARY}` } });

    expect(inspect(response, { depth: 8 })).toContain(CANARY);
  });

  it('the wrapper scrubs config and drops response.request', async () => {
    const api = createSensitiveAxios(instance(server), { allowInsecureTransport: true });

    const response = await api.get('/x', { headers: { Authorization: bearer(token()) } });

    expect(inspect(response, { depth: 8 })).not.toContain(CANARY);
    expect(response.config.headers['Authorization']).toBe('[REDACTED:credential]');
    expect(response.request).toBeUndefined();
    expect(findRawValue(response, CANARY)).toBeUndefined();
  });

  it('hands back the client response untouched, request included, for an empty plan', async () => {
    const api = createSensitiveAxios(instance(server), { allowInsecureTransport: true });

    const response = await api.get('/x', { headers: { 'x-trace': 'abc' } });

    expect(response.request).toBeDefined();
  });
});

describe('the response decoder', () => {
  it('a bare axios hands back a raw secret as a plain string and never throws', async () => {
    server.reply({
      status: 200,
      headers: { 'content-type': 'application/json' },
      body: 'sk_live_abc123',
    });

    const response = await instance(server).get('/keys');

    expect(response.data).toBe('sk_live_abc123');
  });

  it('the wrapper throws instead, naming the request and quoting no bytes', async () => {
    server.reply({
      status: 200,
      headers: { 'content-type': 'application/json' },
      body: 'sk_live_abc123',
    });

    const api = createSensitiveAxios(instance(server), {
      allowInsecureTransport: true,
      responseFields: { token: 'credential' },
    });

    const error = await api.get('/keys').catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(ResponseDecodeError);
    expect(everywhere(error)).not.toContain('sk_live_abc123');
    expect((error as Error).cause).toBeUndefined();
    expect((error as Error).message).toContain('application/json');
  });

  it('wraps the configured response paths before the await resolves', async () => {
    server.reply({
      status: 200,
      body: JSON.stringify({
        token: 'sk_live_abc123',
        customer: { email: 'a@example.com', id: 7 },
      }),
    });

    const api = createSensitiveAxios(instance(server), {
      allowInsecureTransport: true,
      responseFields: { token: 'credential', 'customer.email': 'sensitive' },
    });

    const response = await api.get<{ token: unknown; customer: { email: unknown; id: number } }>(
      '/keys'
    );

    expect(String(response.data.token)).toBe('[REDACTED:credential]');
    expect(String(response.data.customer.email)).toBe('[REDACTED:sensitive]');
    expect(response.data.customer.id).toBe(7);
  });
});
