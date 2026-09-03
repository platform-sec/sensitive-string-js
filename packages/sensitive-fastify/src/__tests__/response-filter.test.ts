import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { describe, expect, test } from 'vitest';
import { sensitivePlugin } from '../plugin.js';
import { buildPlainApp, CANARY, capture, ProfileEntity, UserEntity } from './fixtures.js';

const EMAIL = () => new SensitiveString('user@example.com', 'sensitive', 'email');
const API_KEY = () => new SensitiveString(CANARY, 'credential', 'api_key');

describe('response filter', () => {
  // TEST-FST-008
  test('redacts instances and serialized values, with no response schema', async () => {
    const app = buildPlainApp();

    await app.register(sensitivePlugin, { responseFilter: true });

    app.get('/profile', async () => ({
      apiKey: API_KEY(),
      token: API_KEY().serialize(),
    }));

    const response = await app.inject('/profile');

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      apiKey: '[REDACTED:credential]',
      token: '[REDACTED:credential]',
    });
    expect(response.body).not.toContain(CANARY);
  });

  test('redacts a serialized value under a response schema too', async () => {
    const app = buildPlainApp();

    await app.register(sensitivePlugin, { responseFilter: true });

    app.get(
      '/typed',
      {
        schema: {
          response: {
            200: {
              type: 'object',
              properties: { apiKey: { type: 'string' }, token: { type: 'string' } },
            },
          },
        },
      },
      async () => ({ apiKey: API_KEY(), token: API_KEY().serialize() })
    );

    const response = await app.inject('/typed');

    expect(response.json()).toEqual({
      apiKey: '[REDACTED:credential]',
      token: '[REDACTED:credential]',
    });
  });

  test('a serialized value leaks without the filter, which is why the filter exists', async () => {
    const app = buildPlainApp();

    await app.register(sensitivePlugin, {});

    app.get('/unfiltered', async () => ({ token: API_KEY().serialize() }));

    const response = await app.inject('/unfiltered');

    // Both serializers emit the marker object faithfully: `toJSON()` cannot
    // help, because there is no instance left to ask.
    expect(response.body).toContain(CANARY);
  });

  // TEST-FST-009
  test('keeps an entity prototype, so its own toJSON still runs', async () => {
    const app = buildPlainApp();
    const filtered = capture<unknown>();

    await app.register(sensitivePlugin, { responseFilter: true });

    // Registered after the plugin, so it observes what the filter produced.
    app.addHook('preSerialization', async (_request, _reply, payload: unknown) => {
      filtered.set(payload);

      return payload;
    });

    app.get('/entity', async () => new ProfileEntity(1, EMAIL()));

    const response = await app.inject('/entity');

    expect(filtered.get()).toBeInstanceOf(ProfileEntity);
    expect(response.json()).toEqual({
      kind: 'profile',
      id: 1,
      email: '[REDACTED:sensitive]',
    });
  });

  test('keeps a shared reference shared', async () => {
    const app = buildPlainApp();
    const filtered = capture<{ a: unknown; b: unknown }>();

    await app.register(sensitivePlugin, { responseFilter: true });

    app.addHook('preSerialization', async (_request, _reply, payload: unknown) => {
      filtered.set(payload as { a: unknown; b: unknown });

      return payload;
    });

    app.get('/shared', async () => {
      const user = new UserEntity(1, EMAIL(), API_KEY());

      return { a: user, b: user };
    });

    await app.inject('/shared');

    const { a, b } = filtered.get();

    expect(a).toBe(b);
  });

  test('a cycle fails at serialization as it would without the filter', async () => {
    const app = buildPlainApp();

    await app.register(sensitivePlugin, { responseFilter: true });

    app.get('/cycle', async () => {
      const node: Record<string, unknown> = { apiKey: API_KEY() };

      node['self'] = node;

      return node;
    });

    const response = await app.inject('/cycle');

    expect(response.statusCode).toBe(500);
    expect(response.body).not.toContain(CANARY);
  });

  // TEST-FST-INT-003
  test('an instance at an object-typed schema property serializes to an empty object', async () => {
    const app = buildPlainApp();

    await app.register(sensitivePlugin, { responseFilter: true });

    app.get(
      '/object-typed',
      {
        schema: {
          response: {
            200: {
              type: 'object',
              properties: {
                token: { type: 'object', properties: { value: { type: 'string' } } },
              },
            },
          },
        },
      },
      async () => ({ token: API_KEY().serialize() })
    );

    const response = await app.inject('/object-typed');

    // The redaction is a string at a property the schema types as an object, so
    // fast-json-stringify emits `{}`. That loses the marker and leaks nothing.
    expect(response.json()).toEqual({ token: {} });
    expect(response.body).not.toContain(CANARY);
  });

  test('does not run for a string, a buffer, or an error reply', async () => {
    const app = buildPlainApp();
    const ran: string[] = [];

    await app.register(sensitivePlugin, { responseFilter: true });

    app.addHook('preSerialization', async (request, _reply, payload: unknown) => {
      ran.push(request.url);

      return payload;
    });

    app.get('/text', async (_request, reply) => {
      await reply.type('text/plain').send('plain text');
    });
    app.get('/buffer', async (_request, reply) => {
      await reply.type('application/octet-stream').send(Buffer.from('bytes'));
    });
    app.get('/thrown', async () => {
      throw new Error('nope');
    });
    app.get('/object', async () => ({ a: 1 }));

    for (const url of ['/text', '/buffer', '/thrown', '/object']) {
      await app.inject(url);
    }

    expect(ran).toEqual(['/object']);
  });

  test('is off by default', async () => {
    const app = buildPlainApp();

    await app.register(sensitivePlugin, {});

    app.get('/default', async () => ({ token: API_KEY().serialize() }));

    const response = await app.inject('/default');

    expect(response.body).toContain(CANARY);
  });

  test('rejects a non-boolean responseFilter at registration', async () => {
    const app = buildPlainApp();

    await expect(app.register(sensitivePlugin, { responseFilter: 'yes' as never })).rejects.toThrow(
      /sensitivePlugin\.responseFilter must be a boolean/
    );
  });

  test('leaves a revealed value alone, by design', async () => {
    const app = buildPlainApp();

    await app.register(sensitivePlugin, { responseFilter: true });

    app.get('/revealed', async () => ({ email: EMAIL().reveal() }));

    const response = await app.inject('/revealed');

    expect(response.json()).toEqual({ email: 'user@example.com' });
  });
});
