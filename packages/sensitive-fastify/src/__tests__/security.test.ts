import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { expectNotLeaked, findRawValue } from '@platform-sec/sensitive-string-testing';
import { describe, expect, test } from 'vitest';
import { sensitivePlugin } from '../plugin.js';
import {
  buildLoggingApp,
  buildPlainApp,
  CANARY,
  capture,
  LOGIN_SCHEMA,
  OTHER_CANARY,
  ProfileEntity,
  UserEntity,
  type LoginBody,
} from './fixtures.js';

describe('canary: request logging', () => {
  // TEST-FST-SEC-001
  test('request.log does not leak a keyword-wrapped field', async () => {
    const { app, lines } = buildLoggingApp();

    app.post<{ Body: LoginBody }>('/login', { schema: LOGIN_SCHEMA }, async (request) => {
      request.log.info({ body: request.body }, 'login');
      request.log.info('password %s', request.body.password);

      return { ok: true };
    });

    const response = await app.inject({
      method: 'POST',
      url: '/login',
      payload: { email: 'a@b.co', password: CANARY },
    });

    expect(response.statusCode).toBe(200);

    const output = lines.join('');

    expect(output).not.toContain(CANARY);
    expect(output).toContain('[REDACTED:credential]');
  });

  test('request.log does not leak a field-map-wrapped field', async () => {
    const { app, lines } = buildLoggingApp();

    await app.register(sensitivePlugin, { body: { password: 'credential' } });

    app.post('/webhook', async (request) => {
      request.log.info({ body: request.body }, 'webhook');

      return { ok: true };
    });

    await app.inject({ method: 'POST', url: '/webhook', payload: { password: CANARY } });

    const output = lines.join('');

    expect(output).not.toContain(CANARY);
    expect(output).toContain('[REDACTED:credential]');
  });

  test('the request log line carries no headers, wrapped or not', async () => {
    const { app, lines } = buildLoggingApp();

    await app.register(sensitivePlugin, { headers: { authorization: 'credential' } });

    app.get('/data', async () => ({ ok: true }));

    await app.inject({ url: '/data', headers: { authorization: CANARY } });

    expect(lines.join('')).not.toContain(CANARY);
  });
});

describe('canary: responses', () => {
  // TEST-FST-SEC-002
  test('a nested array of entities and a serialized value leak nothing', async () => {
    for (const withSchema of [false, true]) {
      const app = buildPlainApp();
      const apiKey = new SensitiveString(CANARY, 'credential', 'api_key');
      const email = new SensitiveString(OTHER_CANARY, 'sensitive', 'email');

      await app.register(sensitivePlugin, { responseFilter: true });

      const schema = withSchema
        ? {
            response: {
              200: {
                type: 'object',
                properties: {
                  users: {
                    type: 'array',
                    items: {
                      type: 'object',
                      properties: {
                        id: { type: 'integer' },
                        email: { type: 'string' },
                        apiKey: { type: 'string' },
                      },
                    },
                  },
                  profiles: { type: 'array', items: { type: 'object' } },
                  transported: { type: 'string' },
                },
              },
            },
          }
        : {};

      app.get('/report', { schema }, async () => ({
        users: [new UserEntity(1, email, apiKey), new UserEntity(2, email, apiKey)],
        profiles: [new ProfileEntity(3, email)],
        transported: apiKey.serialize(),
      }));

      const response = await app.inject('/report');

      expect(response.statusCode).toBe(200);
      expectNotLeaked(apiKey, response.body, response.json());
      expectNotLeaked(email, response.body, response.json());
    }
  });
});

describe('canary: the error path', () => {
  // TEST-FST-SEC-003
  test('an error message interpolating an instance carries the marker, not the value', async () => {
    const { app, lines } = buildLoggingApp();

    app.post<{ Body: LoginBody }>('/login', { schema: LOGIN_SCHEMA }, async (request) => {
      throw new Error(`authentication failed for ${String(request.body.password)}`);
    });

    const response = await app.inject({
      method: 'POST',
      url: '/login',
      payload: { email: 'a@b.co', password: CANARY },
    });

    expect(response.statusCode).toBe(500);
    expect(response.body).not.toContain(CANARY);
    expect(lines.join('')).not.toContain(CANARY);
  });

  test('a custom error handler that logs the body sees wrapped fields redacted', async () => {
    const { app, lines } = buildLoggingApp();

    app.setErrorHandler(async (error, request, reply) => {
      request.log.error({ body: request.body, err: error.message }, 'failed');

      return reply.code(500).send({ error: 'handled' });
    });

    app.post('/login', { schema: LOGIN_SCHEMA }, async () => {
      throw new Error('downstream refused');
    });

    await app.inject({
      method: 'POST',
      url: '/login',
      payload: { email: 'a@b.co', password: CANARY },
    });

    const output = lines.join('');

    expect(output).not.toContain(CANARY);
    expect(output).toContain('[REDACTED:credential]');
  });

  test('a validation failure echoes no value on a keyword route', async () => {
    const { app, lines } = buildLoggingApp();

    app.post('/login', { schema: LOGIN_SCHEMA }, async () => ({ ok: true }));

    const response = await app.inject({
      method: 'POST',
      url: '/login',
      payload: { email: 'a@b.co', password: CANARY.slice(0, 4) },
    });

    expect(response.statusCode).toBe(400);
    expect(response.body).not.toContain(CANARY.slice(0, 4));
    expect(lines.join('')).not.toContain(CANARY.slice(0, 4));
  });

  // TEST-FST-EDGE, parse errors: nothing to scrub, unlike Express
  test('a JSON parse failure carries no body in the response or the log', async () => {
    for (const payload of [
      `{"password":"${CANARY}",}`,
      `{"password":${CANARY}}`,
      `{"password":"${CANARY}"`,
    ]) {
      const { app, lines } = buildLoggingApp();
      const errors: unknown[] = [];

      app.setErrorHandler(async (error, _request, reply) => {
        errors.push(error);

        return reply.code(400).send({ error: 'bad json' });
      });

      app.post('/login', async () => ({ ok: true }));

      const response = await app.inject({
        method: 'POST',
        url: '/login',
        payload,
        headers: { 'content-type': 'application/json' },
      });

      expect(response.statusCode).toBe(400);
      expect(response.body).not.toContain(CANARY);
      expect(lines.join('')).not.toContain(CANARY);
      // Express's body-parser attaches the unparsed body to its 400. Fastify's
      // parse error carries code, name, statusCode, and message only, which is
      // why this package ships no scrubber.
      expect(findRawValue(errors[0], CANARY)).toBeUndefined();
    }
  });
});

describe('canary: the request container', () => {
  // TEST-FST-SEC-005
  test('extraction leaves request.headers and request.raw.headers untouched', async () => {
    const app = buildPlainApp();
    const seen = capture<{ headers: unknown; raw: unknown; wrapped: unknown }>();

    await app.register(sensitivePlugin, { headers: { authorization: 'credential' } });

    app.get('/data', async (request) => {
      seen.set({
        headers: request.headers['authorization'],
        raw: request.raw.headers['authorization'],
        wrapped: request.sensitive.headers['authorization'],
      });

      return { ok: true };
    });

    await app.inject({ url: '/data', headers: { authorization: `Bearer ${CANARY}` } });

    const { headers, raw, wrapped } = seen.get();

    expect(headers).toBe(`Bearer ${CANARY}`);
    expect(raw).toBe(`Bearer ${CANARY}`);
    expect(wrapped).toBeInstanceOf(SensitiveString);
  });
});

describe('canary: the whole stack', () => {
  test('one request through keyword, field map, headers, context and filter leaks nothing', async () => {
    const { app, lines } = buildLoggingApp();
    const token = new SensitiveString(OTHER_CANARY, 'credential', 'downstream');

    await app.register(sensitivePlugin, {
      context: (request) => ({ name: `${request.method} ${request.routeOptions.url ?? ''}` }),
      headers: { authorization: 'credential' },
      responseFilter: true,
      body: { note: 'sensitive' },
    });

    app.post<{ Body: LoginBody & { note: string } }>(
      '/login',
      {
        schema: {
          body: {
            type: 'object',
            required: ['email', 'password'],
            properties: {
              email: { type: 'string', format: 'email', sensitive: { klass: 'sensitive' } },
              password: { type: 'string', minLength: 8, sensitive: { klass: 'credential' } },
              note: { type: 'string' },
            },
          },
        },
      },
      async (request) => {
        request.log.info({ body: request.body, headers: request.sensitive.headers }, 'login');

        return {
          user: new UserEntity(1, new SensitiveString('e@x.co', 'sensitive'), token),
          transported: token.serialize(),
        };
      }
    );

    const response = await app.inject({
      method: 'POST',
      url: '/login',
      payload: { email: 'a@b.co', password: CANARY, note: CANARY },
      headers: { authorization: `Bearer ${CANARY}` },
    });

    expect(response.statusCode).toBe(200);
    expect(response.body).not.toContain(CANARY);
    expect(response.body).not.toContain(OTHER_CANARY);
    expect(lines.join('')).not.toContain(CANARY);
    expectNotLeaked(token, response.body, response.json(), lines.join(''));
  });
});
