import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import got from 'got';
import { UnserializableBodyError, apiKey } from '@platform-sec/sensitive-string-http';
import { startRecordingServer } from '@platform-sec/sensitive-string-http/testing';
import type { RecordingServer } from '@platform-sec/sensitive-string-http/testing';

import { createSensitiveGot } from './client.js';
import { CANARY, token } from './__tests__/fixtures.js';

let server: RecordingServer;

beforeEach(async () => {
  server = await startRecordingServer();
});

afterEach(async () => {
  await server.close();
});

function api() {
  return createSensitiveGot(got.extend({ prefixUrl: server.origin, retry: { limit: 0 } }), {
    allowInsecureTransport: true,
  });
}

describe('createSensitiveGot', () => {
  it('exposes the six verbs and a generic request', async () => {
    const client = api();

    await client.get('/a');
    await client.delete('/b');
    await client.head('/c');
    await client.post('/d', { x: 1 });
    await client.put('/e', { x: 1 });
    await client.patch('/f', { x: 1 });
    await client.request('/g', { method: 'OPTIONS' });

    expect(server.requests.map((request) => `${request.method} ${request.target}`)).toEqual([
      'GET /a',
      'DELETE /b',
      'HEAD /c',
      'POST /d',
      'PUT /e',
      'PATCH /f',
      'OPTIONS /g',
    ]);
  });

  it('resolves a relative URL against prefixUrl and takes an absolute one as given', async () => {
    await api().get('/relative');
    await api().get(`${server.origin}/absolute`);

    expect(server.requests.map((request) => request.target)).toEqual(['/relative', '/absolute']);
  });

  it('explains itself when there is no prefixUrl and the URL is relative', async () => {
    const client = createSensitiveGot(got.extend({ retry: { limit: 0 } }));

    await expect(client.get('/relative')).rejects.toThrow(/has no prefixUrl/);
  });

  it('hands the caller back their own instance', () => {
    const instance = got.extend({});

    expect(createSensitiveGot(instance).client).toBe(instance);
  });

  it('refuses a Map in the body rather than letting got send {}', async () => {
    await expect(api().post('/x', { m: new Map([['a', 1]]) })).rejects.toThrow(
      UnserializableBodyError
    );
  });

  it('retries the configured number of times and no more', async () => {
    server.reply({ status: 500, body: '{"e":1}' });

    const client = createSensitiveGot(
      got.extend({ prefixUrl: server.origin, retry: { limit: 0 } }),
      {
        allowInsecureTransport: true,
        retries: 3,
      }
    );

    await expect(client.get('/x')).rejects.toThrow();
    expect(server.requests).toHaveLength(4);
  });

  it('does not retry a refusal this package raised', async () => {
    const client = createSensitiveGot(got.extend({ prefixUrl: server.origin }), {
      allowInsecureTransport: true,
      retries: 3,
    });

    await expect(client.post('/x', { m: new Map() })).rejects.toThrow(UnserializableBodyError);
    expect(server.requests).toHaveLength(0);
  });
});

describe('the headers option', () => {
  it("sits over got's own defaults and under the call", async () => {
    // got types its defaults as strings, so a wrapped value in
    // `got.extend({ headers })` does not compile; this is the typed place for
    // it. The plain-string defaults got does accept still pass underneath.
    const client = createSensitiveGot(
      got.extend({
        prefixUrl: server.origin,
        retry: { limit: 0 },
        headers: { 'x-tenant': 'from-got', 'x-region': 'eu' },
      }),
      {
        allowInsecureTransport: true,
        headers: { 'x-api-key': apiKey(token()), 'x-tenant': 'from-wrapper' },
      }
    );

    await client.get('/a');
    await client.get('/b', { headers: { 'x-tenant': 'from-call' } });

    expect(server.requests[0]?.headers['x-api-key']).toBe(CANARY);
    expect(server.requests[0]?.headers['x-tenant']).toBe('from-wrapper');
    expect(server.requests[0]?.headers['x-region']).toBe('eu');
    expect(server.requests[1]?.headers['x-api-key']).toBe(CANARY);
    expect(server.requests[1]?.headers['x-tenant']).toBe('from-call');
    expect(server.transcript).not.toContain('[REDACTED');
    expect(server.transcript).not.toContain('[object Object]');
  });
});
