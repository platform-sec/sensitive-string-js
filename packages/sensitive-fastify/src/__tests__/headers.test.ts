import { SensitiveString } from '@platform-sec/sensitive-string-core';
import http from 'node:http';
import { describe, expect, test } from 'vitest';
import { sensitivePlugin } from '../plugin.js';
import { buildPlainApp, CANARY, capture, OTHER_CANARY } from './fixtures.js';
import type { SensitiveRequest } from '../types.js';

const HEADER_FIELDS = {
  authorization: 'credential',
  'x-api-key': { klass: 'credential', label: 'api_key' },
  'x-optional': 'sensitive',
} as const;

describe('header extraction', () => {
  // TEST-FST-007
  test('wraps configured headers onto request.sensitive.headers', async () => {
    const app = buildPlainApp();
    const seen = capture<{ container: SensitiveRequest; raw: unknown }>();

    await app.register(sensitivePlugin, { headers: HEADER_FIELDS });

    app.get('/data', async (request) => {
      seen.set({ container: request.sensitive, raw: request.headers['authorization'] });

      return { ok: true };
    });

    const response = await app.inject({
      url: '/data',
      headers: { Authorization: CANARY, 'X-API-Key': OTHER_CANARY },
    });

    expect(response.statusCode).toBe(200);

    const { container, raw } = seen.get();
    const auth = container.headers['authorization'];
    const apiKey = container.headers['x-api-key'];

    expect(auth).toBeInstanceOf(SensitiveString);
    expect(auth?.klass).toBe('credential');
    expect(auth?.label).toBe('authorization');
    expect(auth?.reveal()).toBe(CANARY);

    // Names are matched case-insensitively and read back in lower case.
    expect(apiKey).toBeInstanceOf(SensitiveString);
    expect(apiKey?.label).toBe('api_key');
    expect(apiKey?.reveal()).toBe(OTHER_CANARY);

    // An absent header is a present key holding null, not a missing key.
    expect('x-optional' in container.headers).toBe(true);
    expect(container.headers['x-optional']).toBeNull();

    // TEST-FST-SEC-005: the container Fastify and every other plugin reads is
    // untouched.
    expect(raw).toBe(CANARY);
  });

  test('an empty header is null rather than a credential of length zero', async () => {
    const app = buildPlainApp();
    const seen = capture<SensitiveRequest>();

    await app.register(sensitivePlugin, { headers: { 'x-api-key': 'credential' } });

    app.get('/empty', async (request) => {
      seen.set(request.sensitive);

      return { ok: true };
    });

    await app.inject({ url: '/empty', headers: { 'x-api-key': '' } });

    expect(seen.get().headers['x-api-key']).toBeNull();
  });

  test('a route outside a headers scope sees an empty frozen container', async () => {
    const app = buildPlainApp();
    const outside = capture<SensitiveRequest>();

    await app.register(async function scoped(instance) {
      await instance.register(sensitivePlugin, { headers: HEADER_FIELDS });
      instance.get('/inside', async () => ({ ok: true }));
    });

    await app.register(sensitivePlugin, {});

    app.get('/outside', async (request) => {
      outside.set(request.sensitive);

      return { ok: true };
    });

    await app.inject({ url: '/outside', headers: { authorization: CANARY } });

    const container = outside.get();

    expect(container.headers).toEqual({});
    expect(Object.isFrozen(container)).toBe(true);
    expect(Object.isFrozen(container.headers)).toBe(true);
  });

  // TEST-FST-EDGE-008
  test('a repeated header arrives as an array and contributes its first element', async () => {
    const app = buildPlainApp();
    const seen = capture<SensitiveRequest>();

    // `set-cookie` is the one header Node keeps as an array rather than joining,
    // and only over a real socket: `inject` joins it like any other. The test
    // therefore listens, which also exercises the plugin off the inject path.
    await app.register(sensitivePlugin, { headers: { 'set-cookie': 'credential' } });

    app.get('/repeated', async (request) => {
      seen.set(request.sensitive);

      return { ok: true };
    });

    await app.listen({ port: 0, host: '127.0.0.1' });

    try {
      const address = app.server.address();

      if (address === null || typeof address === 'string') {
        throw new Error('expected a TCP address after listen()');
      }

      await request(address.port, '/repeated', { 'set-cookie': [CANARY, OTHER_CANARY] });
    } finally {
      await app.close();
    }

    expect(seen.get().headers['set-cookie']?.reveal()).toBe(CANARY);
  });

  test('a root registration and a child registration both contribute', async () => {
    const app = buildPlainApp();
    const seen = capture<SensitiveRequest>();

    await app.register(sensitivePlugin, { headers: { authorization: 'credential' } });

    await app.register(async function child(instance) {
      await instance.register(sensitivePlugin, { headers: { 'x-api-key': 'credential' } });

      instance.get('/both', async (request) => {
        seen.set(request.sensitive);

        return { ok: true };
      });
    });

    await app.inject({
      url: '/both',
      headers: { authorization: CANARY, 'x-api-key': OTHER_CANARY },
    });

    const container = seen.get();

    expect(container.headers['authorization']?.reveal()).toBe(CANARY);
    expect(container.headers['x-api-key']?.reveal()).toBe(OTHER_CANARY);
  });

  test('a header named like an Object property is an ordinary key', async () => {
    const app = buildPlainApp();
    const seen = capture<SensitiveRequest>();

    await app.register(sensitivePlugin, { headers: { constructor: 'credential' } });

    app.get('/proto', async (request) => {
      seen.set(request.sensitive);

      return { ok: true };
    });

    await app.inject({ url: '/proto', headers: { constructor: CANARY } });

    expect(seen.get().headers['constructor']).toBeInstanceOf(SensitiveString);
  });

  test('rejects a malformed header map at registration', async () => {
    const app = buildPlainApp();

    await expect(
      app.register(sensitivePlugin, { headers: { authorization: 'nope' } as never })
    ).rejects.toThrow(/sensitivePlugin\.headers\['authorization'\]/);
  });

  test('rejects two names that differ only in case', async () => {
    const app = buildPlainApp();

    await expect(
      app.register(sensitivePlugin, {
        headers: { 'X-Api-Key': 'credential', 'x-api-key': 'sensitive' },
      })
    ).rejects.toThrow(/more than once/);
  });
});

describe('keyword in a headers schema', () => {
  // TEST-FST-SEC-006
  test('is refused at route registration, naming the route', async () => {
    const app = buildPlainApp();

    await app.register(sensitivePlugin, {});

    expect(() =>
      app.get('/guarded', {
        schema: {
          headers: {
            type: 'object',
            properties: { 'x-api-key': { type: 'string', sensitive: { klass: 'credential' } } },
          },
        },
        handler: async () => ({ ok: true }),
      })
    ).toThrow(/headers schema.*\/guarded/s);
  });

  test('is refused when the keyword hides behind an added $ref', async () => {
    const app = buildPlainApp();

    await app.register(sensitivePlugin, {});

    app.addSchema({
      $id: 'authHeaders',
      type: 'object',
      properties: { authorization: { type: 'string', sensitive: { klass: 'credential' } } },
    });

    expect(() =>
      app.get('/ref-guarded', {
        schema: { headers: { $ref: 'authHeaders#' } },
        handler: async () => ({ ok: true }),
      })
    ).toThrow(/headers schema/);
  });

  test('leaves a headers schema without the keyword alone', async () => {
    const app = buildPlainApp();

    await app.register(sensitivePlugin, {});

    app.get('/plain-headers', {
      schema: {
        headers: {
          type: 'object',
          required: ['x-api-key'],
          properties: { 'x-api-key': { type: 'string' } },
        },
      },
      handler: async () => ({ ok: true }),
    });

    const ok = await app.inject({ url: '/plain-headers', headers: { 'x-api-key': 'k' } });
    const missing = await app.inject('/plain-headers');

    expect(ok.statusCode).toBe(200);
    expect(missing.statusCode).toBe(400);
  });

  test('would otherwise replace the value in the raw Node headers object', async () => {
    // What the guard prevents, measured without it: the keyword modifies the
    // object Fastify itself reads, so `request.headers['x-api-key']` stops
    // being a string. This is why the plugin refuses the route rather than
    // documenting a caveat.
    const { default: Fastify } = await import('fastify');
    const { sensitiveKeyword } = await import('../keyword.js');

    const app = Fastify({ ajv: { customOptions: { keywords: [sensitiveKeyword] } } });

    app.get(
      '/unguarded',
      {
        schema: {
          headers: {
            type: 'object',
            properties: { 'x-api-key': { type: 'string', sensitive: { klass: 'credential' } } },
          },
        },
      },
      async (request) => ({
        headers: typeof request.headers['x-api-key'],
        raw: typeof request.raw.headers['x-api-key'],
      })
    );

    const response = await app.inject({ url: '/unguarded', headers: { 'x-api-key': CANARY } });

    expect(response.json()).toEqual({ headers: 'object', raw: 'object' });
  });
});

/**
 * One GET over a real socket, so a repeated header reaches Node as an array.
 *
 * `inject` joins repeated headers with a comma, which is what Node itself does
 * for every header but `set-cookie`. Reproducing the array case needs the
 * server actually listening.
 */
function request(port: number, path: string, headers: http.OutgoingHttpHeaders): Promise<string> {
  return new Promise((resolve, reject) => {
    const outgoing = http.request({ host: '127.0.0.1', port, path, headers }, (response) => {
      let body = '';

      response.setEncoding('utf8');
      response.on('data', (chunk: string) => {
        body += chunk;
      });
      response.on('end', () => resolve(body));
    });

    outgoing.on('error', reject);
    outgoing.end();
  });
}
