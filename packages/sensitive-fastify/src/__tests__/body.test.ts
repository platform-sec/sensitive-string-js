import { SensitiveString } from '@platform-sec/sensitive-string-core';
import type { FastifyInstance } from 'fastify';
import { describe, expect, test } from 'vitest';
import { sensitivePlugin } from '../plugin.js';
import { bodyOf, buildApp, buildPlainApp, CANARY, capture, OTHER_CANARY } from './fixtures.js';

const AUTH_FIELDS = {
  password: 'credential',
  email: { klass: 'sensitive', label: 'email' },
  'creditCard.number': 'credential',
  'creditCard.cvv': 'credential',
} as const;

/** Records the body a route saw, so a suite can assert after the request. */
function echo(app: FastifyInstance, url: string, seen: { set(value: unknown): void }): void {
  app.post(url, async (request) => {
    seen.set(request.body);

    return { ok: true };
  });
}

describe('field map', () => {
  // TEST-FST-003
  test('is scoped by encapsulation: a child registration leaves the root alone', async () => {
    const app = buildPlainApp();
    const inScope = capture<unknown>();
    const outOfScope = capture<unknown>();

    await app.register(
      async function authRoutes(instance) {
        await instance.register(sensitivePlugin, { body: AUTH_FIELDS });
        echo(instance, '/login', inScope);
      },
      { prefix: '/api/auth' }
    );

    echo(app, '/public/echo', outOfScope);

    const wrapped = await app.inject({
      method: 'POST',
      url: '/api/auth/login',
      payload: { email: 'a@b.co', password: CANARY },
    });
    const untouched = await app.inject({
      method: 'POST',
      url: '/public/echo',
      payload: { email: 'a@b.co', password: CANARY },
    });

    expect(wrapped.statusCode).toBe(200);
    expect(untouched.statusCode).toBe(200);

    const inside = bodyOf(inScope.get());

    expect(inside['password']).toBeInstanceOf(SensitiveString);
    expect((inside['password'] as SensitiveString<'credential'>).label).toBe('password');
    expect(inside['email']).toBeInstanceOf(SensitiveString);

    const outside = bodyOf(outOfScope.get());

    expect(outside['password']).toBe(CANARY);
    expect(outside['email']).toBe('a@b.co');
  });

  // TEST-FST-004
  test('reads a route config with the plugin registered and no body option', async () => {
    const app = buildPlainApp();
    const configured = capture<unknown>();
    const neighbour = capture<unknown>();

    await app.register(sensitivePlugin, {});

    app.post(
      '/api/keys',
      { config: { sensitive: { body: { apiKey: 'credential' } } } },
      async (request) => {
        configured.set(request.body);

        return { ok: true };
      }
    );

    echo(app, '/api/other', neighbour);

    await app.inject({ method: 'POST', url: '/api/keys', payload: { apiKey: CANARY } });
    await app.inject({ method: 'POST', url: '/api/other', payload: { apiKey: CANARY } });

    expect(bodyOf(configured.get())['apiKey']).toBeInstanceOf(SensitiveString);
    expect(bodyOf(neighbour.get())['apiKey']).toBe(CANARY);
  });

  test('merges a route config over the scope map, the route winning', async () => {
    const app = buildPlainApp();
    const seen = capture<unknown>();

    await app.register(sensitivePlugin, { body: { token: 'sensitive', other: 'sensitive' } });

    app.post(
      '/merge',
      { config: { sensitive: { body: { token: { klass: 'credential', label: 'renamed' } } } } },
      async (request) => {
        seen.set(request.body);

        return { ok: true };
      }
    );

    await app.inject({
      method: 'POST',
      url: '/merge',
      payload: { token: CANARY, other: OTHER_CANARY },
    });

    const record = bodyOf(seen.get());
    const token = record['token'] as SensitiveString<'credential'>;

    expect(token.klass).toBe('credential');
    expect(token.label).toBe('renamed');
    expect((record['other'] as SensitiveString<'sensitive'>).klass).toBe('sensitive');
  });

  // TEST-FST-005
  test('defaults a label to the path last segment, and honours an explicit one', async () => {
    const app = buildPlainApp();
    const seen = capture<unknown>();

    await app.register(sensitivePlugin, {
      body: { 'creditCard.number': 'credential', ssn: { klass: 'sensitive', label: 'ssn' } },
    });

    echo(app, '/labels', seen);

    await app.inject({
      method: 'POST',
      url: '/labels',
      payload: { creditCard: { number: CANARY }, ssn: OTHER_CANARY },
    });

    const record = bodyOf(seen.get());
    const card = bodyOf(record['creditCard']);

    expect((card['number'] as SensitiveString<'credential'>).label).toBe('number');
    expect((record['ssn'] as SensitiveString<'sensitive'>).label).toBe('ssn');
  });

  // TEST-FST-EDGE-001
  test('a configured field absent from the body creates nothing', async () => {
    const app = buildPlainApp();
    const seen = capture<unknown>();

    await app.register(sensitivePlugin, { body: { password: 'credential', 'a.b.c': 'sensitive' } });
    echo(app, '/absent', seen);

    const response = await app.inject({ method: 'POST', url: '/absent', payload: { name: 'x' } });

    expect(response.statusCode).toBe(200);
    expect(seen.get()).toEqual({ name: 'x' });
  });

  // TEST-FST-EDGE-002
  test('a non-string value at a configured path is left as is', async () => {
    const app = buildPlainApp();
    const seen = capture<unknown>();

    await app.register(sensitivePlugin, {
      body: { num: 'credential', bool: 'credential', obj: 'credential', nil: 'credential' },
    });
    echo(app, '/types', seen);

    await app.inject({
      method: 'POST',
      url: '/types',
      payload: { num: 7, bool: false, obj: { a: 1 }, nil: null },
    });

    expect(seen.get()).toEqual({ num: 7, bool: false, obj: { a: 1 }, nil: null });
  });

  // TEST-FST-EDGE-003
  test('an absent or non-object body passes through', async () => {
    const app = buildPlainApp();
    const posted = capture<unknown>();
    const got = capture<unknown>();

    await app.register(sensitivePlugin, { body: { password: 'credential' } });

    app.post('/empty', async (request) => {
      posted.set(request.body);

      return { ok: true };
    });
    app.get('/none', async (request) => {
      got.set(request.body);

      return { ok: true };
    });

    const empty = await app.inject({ method: 'POST', url: '/empty' });
    const none = await app.inject('/none');

    expect(empty.statusCode).toBe(200);
    expect(none.statusCode).toBe(200);
    expect(posted.get()).toBeUndefined();
    expect(got.get()).toBeUndefined();
  });

  // TEST-FST-EDGE-004
  test('a root registration plus a child registration wraps once and clones once', async () => {
    const app = buildPlainApp();
    const seen = capture<unknown>();
    const identities = capture<{ outer: unknown; inner: unknown }>();

    await app.register(sensitivePlugin, { body: { password: 'credential' } });

    await app.register(async function child(instance) {
      await instance.register(sensitivePlugin, { body: { password: 'credential' } });

      // Two hooks with a body to wrap would clone twice. The second sees the
      // path already holding an instance and returns without cloning, which is
      // observable as one body object reaching both the hook after it and the
      // handler.
      let outer: unknown;

      instance.addHook('preHandler', async (request) => {
        outer = request.body;
      });

      instance.post('/nested', async (request) => {
        seen.set(request.body);
        identities.set({ outer, inner: request.body });

        return { ok: true };
      });
    });

    await app.inject({ method: 'POST', url: '/nested', payload: { password: CANARY } });

    const record = bodyOf(seen.get());
    const password = record['password'] as SensitiveString<'credential'>;

    expect(password).toBeInstanceOf(SensitiveString);
    // A double wrap would produce an instance whose reveal() returns an
    // instance rather than the string.
    expect(password.reveal()).toBe(CANARY);

    const { outer, inner } = identities.get();

    expect(outer).toBe(inner);
  });

  // TEST-FST-EDGE-005
  test('the keyword and the field map naming the same property wrap once', async () => {
    const app = buildApp();
    const seen = capture<unknown>();

    await app.register(sensitivePlugin, { body: { password: 'credential' } });

    app.post(
      '/both',
      {
        schema: {
          body: {
            type: 'object',
            properties: {
              password: { type: 'string', minLength: 8, sensitive: { klass: 'credential' } },
            },
          },
        },
      },
      async (request) => {
        seen.set(request.body);

        return { ok: true };
      }
    );

    const response = await app.inject({
      method: 'POST',
      url: '/both',
      payload: { password: CANARY },
    });

    expect(response.statusCode).toBe(200);

    const password = bodyOf(seen.get())['password'] as SensitiveString<'credential'>;

    expect(password.reveal()).toBe(CANARY);
  });

  // TEST-FST-EDGE-006
  test('reaches routes declared before a non-awaited registration and in a sibling plugin', async () => {
    const app = buildPlainApp();
    const before = capture<unknown>();
    const sibling = capture<unknown>();
    const after = capture<unknown>();

    // Declared before the plugin is registered at all.
    echo(app, '/before', before);

    // A sibling plugin registered before the plugin, whose routes an `onRoute`
    // hook installed later would never see.
    await app.register(async function siblingPlugin(instance) {
      echo(instance, '/sibling', sibling);
    });

    // Not awaited: Fastify loads it after the synchronous route declarations
    // that follow.
    void app.register(sensitivePlugin, { body: { password: 'credential' } });

    echo(app, '/after', after);

    for (const url of ['/before', '/sibling', '/after']) {
      const response = await app.inject({ method: 'POST', url, payload: { password: CANARY } });

      expect(response.statusCode).toBe(200);
    }

    for (const seen of [before, sibling, after]) {
      expect(bodyOf(seen.get())['password']).toBeInstanceOf(SensitiveString);
    }
  });

  // TEST-FST-EDGE-009
  test('registered twice in one scope: no decorator error, a single wrap', async () => {
    const app = buildPlainApp();
    const seen = capture<unknown>();

    await app.register(sensitivePlugin, { body: { password: 'credential' } });
    await app.register(sensitivePlugin, { body: { password: 'credential' } });

    echo(app, '/twice', seen);

    const response = await app.inject({
      method: 'POST',
      url: '/twice',
      payload: { password: CANARY },
    });

    expect(response.statusCode).toBe(200);

    const password = bodyOf(seen.get())['password'] as SensitiveString<'credential'>;

    expect(password.reveal()).toBe(CANARY);
  });

  // TEST-FST-EDGE-007
  test('under a custom validator compiler the keyword is inert and the field map still wraps', async () => {
    const app = buildPlainApp();
    const seen = capture<unknown>();

    // A compiler that validates nothing, standing in for TypeBox or Zod: the
    // keyword never runs, because Ajv never sees the schema.
    app.setValidatorCompiler(() => () => true);

    await app.register(sensitivePlugin, { body: { password: 'credential' } });

    app.post(
      '/custom',
      {
        schema: {
          body: {
            type: 'object',
            properties: {
              password: { type: 'string', sensitive: { klass: 'credential' } },
            },
          },
        },
      },
      async (request) => {
        seen.set(request.body);

        return { ok: true };
      }
    );

    const response = await app.inject({
      method: 'POST',
      url: '/custom',
      payload: { password: CANARY },
    });

    expect(response.statusCode).toBe(200);

    const password = bodyOf(seen.get())['password'] as SensitiveString<'credential'>;

    expect(password).toBeInstanceOf(SensitiveString);
    expect(password.reveal()).toBe(CANARY);
  });

  test('a POST to no route is a plain 404, with the scope map still applied', async () => {
    const app = buildPlainApp();
    const seen = capture<unknown>();

    await app.register(sensitivePlugin, { body: { password: 'credential' } });

    // A 404 runs the instance-level hooks with a route config Fastify fills in
    // for the not-found handler, so this exercises the branch that has no route
    // of its own to cache against.
    app.setNotFoundHandler(async (request, reply) => {
      seen.set(request.body);

      return reply.code(404).send({ error: 'not found' });
    });

    const response = await app.inject({
      method: 'POST',
      url: '/nowhere',
      payload: { password: CANARY },
    });

    expect(response.statusCode).toBe(404);
    expect(response.body).not.toContain(CANARY);
    expect(bodyOf(seen.get())['password']).toBeInstanceOf(SensitiveString);
  });

  test('does not touch a field the map does not name', async () => {
    const app = buildPlainApp();
    const seen = capture<unknown>();

    await app.register(sensitivePlugin, { body: { password: 'credential' } });
    echo(app, '/partial', seen);

    await app.inject({
      method: 'POST',
      url: '/partial',
      payload: { password: CANARY, note: 'keep me', tags: ['a', 'b'] },
    });

    const record = bodyOf(seen.get());

    expect(record['note']).toBe('keep me');
    expect(record['tags']).toEqual(['a', 'b']);
  });
});

describe('content types', () => {
  /** A parser standing in for multipart: plain data next to a Buffer and a Set. */
  function withCustomParser(app: FastifyInstance): void {
    app.addContentTypeParser(
      'application/vnd.custom',
      { parseAs: 'string' },
      (_request, _body, done) => {
        done(null, {
          password: CANARY,
          avatar: Buffer.from('image-bytes'),
          tags: new Set(['a', 'b']),
        });
      }
    );
  }

  test('a body outside the default types is left untouched, Buffers included', async () => {
    const app = buildPlainApp();
    const seen = capture<unknown>();

    withCustomParser(app);
    await app.register(sensitivePlugin, { body: { password: 'credential' } });
    echo(app, '/custom', seen);

    const response = await app.inject({
      method: 'POST',
      url: '/custom',
      payload: 'ignored',
      headers: { 'content-type': 'application/vnd.custom' },
    });

    expect(response.statusCode).toBe(200);

    const record = bodyOf(seen.get());

    // Wrapping clones through core's `wrapSensitiveByPath`, whose clone turns a
    // Buffer into a numeric-keyed object and a Set into `{}`. Not wrapping is
    // what keeps them intact.
    expect(Buffer.isBuffer(record['avatar'])).toBe(true);
    expect(record['tags']).toBeInstanceOf(Set);
    expect(record['password']).toBe(CANARY);
  });

  test('contentTypes widens the gate to a custom parser', async () => {
    const app = buildPlainApp();
    const seen = capture<unknown>();

    withCustomParser(app);
    await app.register(sensitivePlugin, {
      body: { password: 'credential' },
      contentTypes: ['application/vnd.custom'],
    });
    echo(app, '/custom', seen);

    await app.inject({
      method: 'POST',
      url: '/custom',
      payload: 'ignored',
      headers: { 'content-type': 'application/vnd.custom' },
    });

    expect(bodyOf(seen.get())['password']).toBeInstanceOf(SensitiveString);
  });

  test('matches ignoring parameters and case', async () => {
    const app = buildPlainApp();
    const seen = capture<unknown>();

    await app.register(sensitivePlugin, { body: { password: 'credential' } });
    echo(app, '/charset', seen);

    await app.inject({
      method: 'POST',
      url: '/charset',
      payload: `{"password":"${CANARY}"}`,
      headers: { 'content-type': 'Application/JSON; charset=utf-8' },
    });

    expect(bodyOf(seen.get())['password']).toBeInstanceOf(SensitiveString);
  });

  test('urlencoded bodies are wrapped by default', async () => {
    const app = buildPlainApp();
    const seen = capture<unknown>();

    // Fastify ships no urlencoded parser, so this stands in for @fastify/formbody
    // while still arriving under the default media type.
    app.addContentTypeParser(
      'application/x-www-form-urlencoded',
      { parseAs: 'string' },
      (_request, body, done) => {
        done(null, Object.fromEntries(new URLSearchParams(body as string)));
      }
    );

    await app.register(sensitivePlugin, { body: { password: 'credential' } });
    echo(app, '/form', seen);

    await app.inject({
      method: 'POST',
      url: '/form',
      payload: `password=${CANARY}`,
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
    });

    expect(bodyOf(seen.get())['password']).toBeInstanceOf(SensitiveString);
  });

  test('rejects a malformed contentTypes option at registration', async () => {
    // One app per assertion: a failed registration leaves Fastify's boot in an
    // error state, so a second `register` on the same instance reports the
    // first failure again rather than its own.
    await expect(
      buildPlainApp().register(sensitivePlugin, { contentTypes: 'application/json' as never })
    ).rejects.toThrow(/sensitivePlugin\.contentTypes must be an array/);

    await expect(
      buildPlainApp().register(sensitivePlugin, { contentTypes: ['application/json', ''] })
    ).rejects.toThrow(/sensitivePlugin\.contentTypes\[1\]/);
  });
});

describe('field map validation', () => {
  test('rejects a malformed scope map at registration', async () => {
    const app = buildPlainApp();

    await expect(
      app.register(sensitivePlugin, { body: { password: 'nonsense' } as never })
    ).rejects.toThrow(/sensitivePlugin\.body\['password'\]/);
  });

  test('rejects a reserved path segment at registration', async () => {
    const app = buildPlainApp();

    await expect(
      app.register(sensitivePlugin, { body: { '__proto__.x': 'credential' } })
    ).rejects.toThrow(/reserved segment/);
  });

  test('rejects a malformed route config on the first request to that route', async () => {
    const app = buildPlainApp();
    const errors: unknown[] = [];

    await app.register(sensitivePlugin, {});

    app.setErrorHandler(async (error, _request, reply) => {
      errors.push(error);

      return reply.code(500).send({ error: 'handled' });
    });

    app.post(
      '/bad-config',
      { config: { sensitive: { body: { token: 'nope' as never } } } },
      async () => ({ ok: true })
    );

    const response = await app.inject({
      method: 'POST',
      url: '/bad-config',
      payload: { token: CANARY },
    });

    expect(response.statusCode).toBe(500);
    expect(String(errors[0])).toMatch(/route config\.sensitive\.body\['token'\]/);
  });
});
