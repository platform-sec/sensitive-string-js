import { SensitiveString } from '@platform-sec/sensitive-string-core';
import type { KeywordDefinition, Vocabulary } from 'ajv';
import { describe, expect, test } from 'vitest';
import { sensitiveKeyword, schemaUsesKeyword } from '../keyword.js';
import { bodyOf, buildApp, CANARY, capture, LOGIN_SCHEMA, type LoginBody } from './fixtures.js';

describe('sensitiveKeyword', () => {
  test('is assignable to Ajv keyword types without importing them in the public shape', () => {
    // The published declaration restates the keyword structurally so a consumer
    // needs no Ajv types of its own. This assertion is what keeps that
    // restatement honest against the real ones.
    const asKeyword: KeywordDefinition = sensitiveKeyword;
    const asVocabulary: Vocabulary = [sensitiveKeyword];

    expect(asKeyword.keyword).toBe('sensitive');
    expect(asVocabulary).toHaveLength(1);
  });

  // TEST-FST-001
  test('wraps a body property after that property own checks ran', async () => {
    const app = buildApp();
    const seen = capture<unknown>();

    app.post<{ Body: LoginBody }>('/login', { schema: LOGIN_SCHEMA }, async (request) => {
      seen.set(request.body);

      return { ok: true };
    });

    const valid = await app.inject({
      method: 'POST',
      url: '/login',
      payload: { email: 'a@b.co', password: CANARY },
    });

    expect(valid.statusCode).toBe(200);

    const body = seen.get() as LoginBody;

    expect(body.password).toBeInstanceOf(SensitiveString);
    expect(body.password.klass).toBe('credential');
    expect(body.password.label).toBe('password');
    expect(body.email).toBeInstanceOf(SensitiveString);
    expect(body.email.klass).toBe('sensitive');
    expect(body.email.label).toBe('email');
  });

  // TEST-FST-001, the rejection half: the raw string is validated, not the instance
  test('leaves a failing property to its own keywords, and echoes no value', async () => {
    const app = buildApp();

    app.post('/login', { schema: LOGIN_SCHEMA }, async () => ({ ok: true }));

    const short = await app.inject({
      method: 'POST',
      url: '/login',
      payload: { email: 'a@b.co', password: 'short' },
    });

    expect(short.statusCode).toBe(400);
    expect(short.body).not.toContain('short');

    const malformed = await app.inject({
      method: 'POST',
      url: '/login',
      payload: { email: 'not-an-email', password: CANARY },
    });

    expect(malformed.statusCode).toBe(400);
    expect(malformed.body).not.toContain('not-an-email');
    expect(malformed.body).not.toContain(CANARY);
  });

  // TEST-FST-002
  test('reaches nested objects, array items, $ref schemas, querystring and params', async () => {
    const app = buildApp();
    const seen = capture<{ body: unknown; query: unknown; params: unknown }>();

    app.addSchema({
      $id: 'credentials',
      type: 'object',
      properties: {
        secret: { type: 'string', sensitive: { klass: 'credential' } },
      },
    });

    app.post(
      '/reach/:token',
      {
        schema: {
          body: {
            type: 'object',
            properties: {
              nested: {
                type: 'object',
                properties: {
                  ssn: { type: 'string', sensitive: { klass: 'sensitive' } },
                },
              },
              keys: {
                type: 'array',
                items: { type: 'string', sensitive: { klass: 'credential', label: 'key' } },
              },
              unlabelled: {
                type: 'array',
                items: { type: 'string', sensitive: { klass: 'credential' } },
              },
              creds: { $ref: 'credentials#' },
            },
          },
          querystring: {
            type: 'object',
            properties: { q: { type: 'string', sensitive: { klass: 'sensitive' } } },
          },
          params: {
            type: 'object',
            properties: { token: { type: 'string', sensitive: { klass: 'credential' } } },
          },
        },
      },
      async (request) => {
        seen.set({ body: request.body, query: request.query, params: request.params });

        return { ok: true };
      }
    );

    const response = await app.inject({
      method: 'POST',
      url: '/reach/tok-1?q=searched',
      payload: {
        nested: { ssn: '111-22-3333' },
        keys: ['k1', 'k2'],
        unlabelled: ['u1'],
        creds: { secret: CANARY },
      },
    });

    expect(response.statusCode).toBe(200);

    const { body, query, params } = seen.get();
    const record = bodyOf(body);
    const nested = bodyOf(record['nested']);
    const keys = record['keys'] as SensitiveString<'credential'>[];
    const unlabelled = record['unlabelled'] as SensitiveString<'credential'>[];
    const creds = bodyOf(record['creds']);

    expect(nested['ssn']).toBeInstanceOf(SensitiveString);
    expect((nested['ssn'] as SensitiveString<'sensitive'>).label).toBe('ssn');

    expect(keys[0]).toBeInstanceOf(SensitiveString);
    expect(keys[1]).toBeInstanceOf(SensitiveString);
    // An array item is addressed by index, so it takes the schema label, or none.
    expect(keys[0]?.label).toBe('key');
    expect(unlabelled[0]).toBeInstanceOf(SensitiveString);
    expect(unlabelled[0]?.label).toBeUndefined();

    expect(creds['secret']).toBeInstanceOf(SensitiveString);
    expect((creds['secret'] as SensitiveString<'credential'>).klass).toBe('credential');

    expect(bodyOf(query)['q']).toBeInstanceOf(SensitiveString);
    expect(bodyOf(params)['token']).toBeInstanceOf(SensitiveString);
  });

  // TEST-FST-EDGE-002, the keyword half
  test('does not apply to a non-string property', async () => {
    const app = buildApp();
    const seen = capture<unknown>();

    app.post(
      '/mixed',
      {
        schema: {
          body: {
            type: 'object',
            properties: {
              count: { type: 'integer' },
              flag: { type: 'boolean' },
              secret: { type: 'string', sensitive: { klass: 'credential' } },
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
      url: '/mixed',
      payload: { count: 3, flag: true, secret: CANARY },
    });

    expect(response.statusCode).toBe(200);

    const record = bodyOf(seen.get());

    expect(record['count']).toBe(3);
    expect(record['flag']).toBe(true);
    expect(record['secret']).toBeInstanceOf(SensitiveString);
  });

  test('rejects a malformed keyword schema at route registration', async () => {
    const app = buildApp();

    app.post(
      '/typo',
      {
        schema: {
          body: {
            type: 'object',
            properties: {
              // `klass` misspelled: the metaSchema refuses it.
              secret: { type: 'string', sensitive: { class: 'credential' } },
            },
          },
        },
      },
      async () => ({ ok: true })
    );

    await expect(app.ready()).rejects.toThrow(/sensitive/i);
  });

  test('is refused at route registration when the keyword is not registered', async () => {
    const { default: Fastify } = await import('fastify');
    const app = Fastify();

    app.post('/login', { schema: LOGIN_SCHEMA }, async () => ({ ok: true }));

    // Fastify's Ajv runs in strict mode, so an unknown keyword is a build
    // failure rather than a silently ignored annotation.
    await expect(app.ready()).rejects.toThrow(/sensitive/);
  });

  test('is inert in a response schema', async () => {
    const app = buildApp();

    app.get(
      '/out',
      {
        schema: {
          response: {
            200: {
              type: 'object',
              properties: {
                token: { type: 'string', sensitive: { klass: 'credential' } },
              },
            },
          },
        },
      },
      async () => ({ token: CANARY })
    );

    const response = await app.inject('/out');

    // fast-json-stringify ignores the keyword: this documents why the response
    // filter, not the keyword, is the mechanism for responses.
    expect(response.statusCode).toBe(200);
    expect(response.body).toContain(CANARY);
  });
});

describe('schemaUsesKeyword', () => {
  test('finds the keyword at any depth, through arrays and $ref', () => {
    expect(schemaUsesKeyword(undefined)).toBe(false);
    expect(schemaUsesKeyword({ type: 'object', properties: { a: { type: 'string' } } })).toBe(
      false
    );
    expect(
      schemaUsesKeyword({
        type: 'object',
        properties: { a: { type: 'string', sensitive: { klass: 'credential' } } },
      })
    ).toBe(true);
    expect(
      schemaUsesKeyword({
        anyOf: [{ type: 'null' }, { type: 'string', sensitive: { klass: 'sensitive' } }],
      })
    ).toBe(true);

    const shared = {
      type: 'object',
      properties: { a: { type: 'string', sensitive: { klass: 'credential' } } },
    };

    expect(schemaUsesKeyword({ $ref: 'shared#' }, () => shared)).toBe(true);
    expect(schemaUsesKeyword({ $ref: 'shared#' }, () => undefined)).toBe(false);
  });

  test('terminates on a self-referential schema', () => {
    const recursive: Record<string, unknown> = { type: 'object' };

    recursive['properties'] = { child: recursive };

    expect(schemaUsesKeyword(recursive)).toBe(false);

    const selfRef: Record<string, unknown> = { $ref: 'node#' };

    expect(schemaUsesKeyword(selfRef, () => selfRef)).toBe(false);
  });
});
