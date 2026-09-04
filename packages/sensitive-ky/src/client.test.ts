import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import ky from 'ky';
import { UnserializableBodyError } from '@platform-sec/sensitive-string-http';
import { startRecordingServer } from '@platform-sec/sensitive-string-http/testing';
import type { RecordingServer } from '@platform-sec/sensitive-string-http/testing';

import { createSensitiveKy } from './client.js';

let server: RecordingServer;

beforeEach(async () => {
  server = await startRecordingServer();
});

afterEach(async () => {
  await server.close();
});

function api(extra = {}) {
  return createSensitiveKy(ky.create({ retry: 0 }), {
    prefix: server.origin,
    allowInsecureTransport: true,
    ...extra,
  });
}

describe('createSensitiveKy', () => {
  it('exposes the six verbs and a generic request', async () => {
    const client = api();

    await client.get('/a');
    await client.delete('/b');
    await client.head('/c');
    await client.post('/d', { x: 1 });
    await client.put('/e', { x: 1 });
    await client.patch('/f', { x: 1 });
    await client.request('/g', { method: 'options' });

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

  it('resolves a relative URL against the prefix and takes an absolute one as given', async () => {
    await api().get('/relative');
    await api().get(`${server.origin}/absolute`);

    expect(server.requests.map((request) => request.target)).toEqual(['/relative', '/absolute']);
  });

  it('explains itself when no prefix was configured and the URL is relative', async () => {
    await expect(createSensitiveKy(ky.create({ retry: 0 })).get('/relative')).rejects.toThrow(
      /no prefix was configured/
    );
  });

  it('resolves to the Response and offers the body accessors beside it', async () => {
    server.reply({ status: 200, body: '{"ok":true}' });

    const call = api().get<{ ok: boolean }>('/x');
    const response = await call;

    expect(response).toBeInstanceOf(Response);
    expect(await api().get<{ ok: boolean }>('/x').json()).toEqual({ ok: true });
    expect(await api().get('/x').text()).toBe('{"ok":true}');
  });

  it('refuses a Map in the body rather than letting ky send {}', async () => {
    await expect(api().post('/x', { m: new Map([['a', 1]]) })).rejects.toThrow(
      UnserializableBodyError
    );
  });

  it('retries the configured number of times and no more', async () => {
    server.reply({ status: 500, body: '{"e":1}' });

    await expect(api({ retries: 3 }).get('/x')).rejects.toThrow();
    expect(server.requests).toHaveLength(4);
  });

  it('hands the caller back their own instance', () => {
    const instance = ky.create({});

    expect(createSensitiveKy(instance).client).toBe(instance);
  });
});
