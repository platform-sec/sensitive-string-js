import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import axios from 'axios';
import { UnserializableBodyError, apiKey } from '@platform-sec/sensitive-string-http';
import { startRecordingServer } from '@platform-sec/sensitive-string-http/testing';
import type { RecordingServer } from '@platform-sec/sensitive-string-http/testing';

import { createSensitiveAxios } from './client.js';
import { token } from './__tests__/fixtures.js';

let server: RecordingServer;

beforeEach(async () => {
  server = await startRecordingServer();
});

afterEach(async () => {
  await server.close();
});

function api() {
  return createSensitiveAxios(axios.create({ baseURL: server.origin }), {
    allowInsecureTransport: true,
  });
}

describe('createSensitiveAxios', () => {
  it('exposes the six verbs and a generic request', async () => {
    const client = api();

    await client.get('/a');
    await client.delete('/b');
    await client.head('/c');
    await client.post('/d', { x: 1 });
    await client.put('/e', { x: 1 });
    await client.patch('/f', { x: 1 });
    await client.request({ url: '/g', method: 'options' });

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

  it('resolves a relative URL against baseURL and takes an absolute one as given', async () => {
    await api().get('/relative');
    await api().get(`${server.origin}/absolute`);

    expect(server.requests.map((request) => request.target)).toEqual(['/relative', '/absolute']);
  });

  it('explains itself when there is no baseURL and the URL is relative', async () => {
    const client = createSensitiveAxios(axios.create());

    await expect(client.get('/relative')).rejects.toThrow(/has no baseURL/);
  });

  it('hands the caller back their own instance for what this surface does not expose', () => {
    const instance = axios.create();

    expect(createSensitiveAxios(instance).client).toBe(instance);
  });

  it('passes the caller options it does not own straight through', async () => {
    await api().get('/x', { headers: { 'x-trace': 'abc' }, params: { page: 2 } });

    expect(server.requests[0]?.headers['x-trace']).toBe('abc');
    expect(server.requests[0]?.target).toBe('/x?page=2');
  });

  it('refuses a Map in the body rather than letting axios send {}', async () => {
    await expect(api().post('/x', { m: new Map([['a', 1]]) })).rejects.toThrow(
      UnserializableBodyError
    );
  });

  it('leaves a 4xx the caller chose not to treat as an error as a response', async () => {
    server.reply({ status: 404, body: '{"e":1}' });

    const response = await api().get('/x', { validateStatus: () => true });

    expect(response.status).toBe(404);
  });

  it("honours validateStatus: null, axios's way of saying accept everything", async () => {
    server.reply({ status: 404, body: '{"e":1}' });

    // Also while the wrapper is following hops, which is where it broke: the
    // wrapper read the caller's predicate with `??`, and `null` is nullish, so
    // it fell through to the 2xx-only default and turned the 404 back into an
    // error the caller had explicitly asked not to have.
    const client = createSensitiveAxios(axios.create({ baseURL: server.origin }), {
      allowInsecureTransport: true,
      allowedHosts: [server.host],
    });

    const response = await client.get('/x', {
      validateStatus: null,
      headers: { 'x-api-key': apiKey(token()) },
    });

    expect(response.status).toBe(404);
  });
});
