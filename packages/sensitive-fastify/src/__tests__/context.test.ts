import {
  getCurrentRevealContext,
  SensitiveString,
  type RevealContext,
} from '@platform-sec/sensitive-string-core';
import { createMockAuditLog } from '@platform-sec/sensitive-string-testing';
import { describe, expect, test } from 'vitest';
import { sensitivePlugin } from '../plugin.js';
import {
  buildApp,
  buildPlainApp,
  CANARY,
  capture,
  LOGIN_SCHEMA,
  type LoginBody,
} from './fixtures.js';

describe('reveal context', () => {
  // TEST-FST-006
  test('reaches the handler, and names the route pattern rather than the url', async () => {
    const app = buildPlainApp();
    const seen = capture<RevealContext | null>();

    await app.register(sensitivePlugin, {
      context: (request) => ({
        name: `${request.method} ${request.routeOptions.url ?? 'unrouted'}`,
        tags: { requestId: request.id },
      }),
    });

    app.get('/users/:id', async (request) => {
      seen.set(getCurrentRevealContext());

      return { id: request.params };
    });

    // A token in the query string is exactly what `request.url` would put into
    // every audit record; the route pattern carries none of it.
    await app.inject(`/users/7?token=${CANARY}`);

    const context = seen.get();

    expect(context?.name).toBe('GET /users/:id');
    expect(context?.tags?.['requestId']).toMatch(/^req-/);
    expect(JSON.stringify(context)).not.toContain(CANARY);
  });

  test('a factory returning undefined establishes no context', async () => {
    const app = buildPlainApp();
    const seen = capture<RevealContext | null>();

    await app.register(sensitivePlugin, { context: () => undefined });

    app.get('/none', async () => {
      seen.set(getCurrentRevealContext());

      return { ok: true };
    });

    await app.inject('/none');

    expect(seen.get()).toBeNull();
  });

  test('propagates through an await in an async handler', async () => {
    const app = buildPlainApp();
    const seen = capture<{ before: RevealContext | null; after: RevealContext | null }>();

    await app.register(sensitivePlugin, { context: () => ({ name: 'awaited' }) });

    app.get('/awaited', async () => {
      const before = getCurrentRevealContext();

      await new Promise((resolve) => setImmediate(resolve));

      seen.set({ before, after: getCurrentRevealContext() });

      return { ok: true };
    });

    await app.inject('/awaited');

    const { before, after } = seen.get();

    expect(before?.name).toBe('awaited');
    expect(after?.name).toBe('awaited');
  });

  // TEST-FST-INT-001
  test('reaches the error handler for a rejection after an await', async () => {
    const app = buildPlainApp();
    const seen = capture<RevealContext | null>();

    await app.register(sensitivePlugin, { context: () => ({ name: 'error-path' }) });

    app.setErrorHandler(async (_error, _request, reply) => {
      seen.set(getCurrentRevealContext());

      return reply.code(500).send({ error: 'handled' });
    });

    app.get('/boom', async () => {
      await new Promise((resolve) => setImmediate(resolve));

      throw new Error('boom');
    });

    const response = await app.inject('/boom');

    expect(response.statusCode).toBe(500);
    expect(seen.get()?.name).toBe('error-path');
  });

  test('reaches preSerialization, onSend and onResponse', async () => {
    const app = buildPlainApp();
    const positions: Record<string, string | undefined> = {};

    await app.register(sensitivePlugin, { context: () => ({ name: 'late-hooks' }) });

    for (const hook of ['preSerialization', 'onSend'] as const) {
      app.addHook(hook, async (_request, _reply, payload: unknown) => {
        positions[hook] = getCurrentRevealContext()?.name;

        return payload;
      });
    }

    // `onResponse` takes no payload, so an async handler there has two
    // arguments; a third makes Fastify refuse the hook.
    app.addHook('onResponse', async () => {
      positions['onResponse'] = getCurrentRevealContext()?.name;
    });

    await app.inject('/late');

    // A 404 is still a request the context hook ran for.
    expect(positions).toEqual({
      preSerialization: 'late-hooks',
      onSend: 'late-hooks',
      onResponse: 'late-hooks',
    });
  });

  test('contextHook preValidation and preHandler both work', async () => {
    for (const contextHook of ['preValidation', 'preHandler'] as const) {
      const app = buildPlainApp();
      const seen = capture<RevealContext | null>();

      await app.register(sensitivePlugin, {
        context: () => ({ name: contextHook }),
        contextHook,
      });

      app.get('/at', async () => {
        seen.set(getCurrentRevealContext());

        return { ok: true };
      });

      await app.inject('/at');

      expect(seen.get()?.name).toBe(contextHook);
    }
  });

  test('a preHandler context leaves a validation failure outside the scope', async () => {
    const app = buildApp();
    const inValidationHook = capture<RevealContext | null>();

    await app.register(sensitivePlugin, {
      context: () => ({ name: 'late' }),
      contextHook: 'preHandler',
    });

    app.setErrorHandler(async (error, _request, reply) => {
      inValidationHook.set(getCurrentRevealContext());

      return reply.code(400).send({ error: String(error) });
    });

    app.post('/login', { schema: LOGIN_SCHEMA }, async () => ({ ok: true }));

    const response = await app.inject({
      method: 'POST',
      url: '/login',
      payload: { email: 'a@b.co', password: 'short' },
    });

    expect(response.statusCode).toBe(400);
    // The documented cost of moving the hook later.
    expect(inValidationHook.get()).toBeNull();
  });

  // TEST-FST-SEC-004
  test('auditReveal receives the value and the operation for a reveal in the handler', async () => {
    const app = buildApp();
    const audit = createMockAuditLog('request');

    await app.register(sensitivePlugin, {
      context: (request) => ({
        ...audit.context,
        name: `${request.method} ${request.routeOptions.url ?? ''}`,
        tags: { requestId: request.id },
      }),
    });

    app.post<{ Body: LoginBody }>('/login', { schema: LOGIN_SCHEMA }, async (request) => {
      request.body.password.reveal();

      return { ok: true };
    });

    await app.inject({
      method: 'POST',
      url: '/login',
      payload: { email: 'a@b.co', password: CANARY },
    });

    expect(audit.entries).toHaveLength(1);
    expect(audit.entries[0]?.operation).toBe('reveal');
    expect(audit.entries[0]?.klass).toBe('credential');
    expect(audit.entries[0]?.label).toBe('password');
  });

  test('a reveal in the error handler is audited through the request context', async () => {
    const app = buildPlainApp();
    const audit = createMockAuditLog('request');
    const secret = new SensitiveString(CANARY, 'credential', 'recovery');

    await app.register(sensitivePlugin, {
      context: () => ({ ...audit.context, name: 'error-audit' }),
    });

    app.setErrorHandler(async (_error, _request, reply) => {
      secret.reveal();

      return reply.code(500).send({ error: 'handled' });
    });

    app.get('/boom', async () => {
      await new Promise((resolve) => setImmediate(resolve));

      throw new Error('boom');
    });

    await app.inject('/boom');

    expect(audit.entries.map((entry) => entry.label)).toEqual(['recovery']);
  });

  test('rejects a non-function context option at registration', async () => {
    const app = buildPlainApp();

    await expect(app.register(sensitivePlugin, { context: {} as never })).rejects.toThrow(
      /sensitivePlugin\.context must be a function/
    );
  });

  test('rejects an unknown contextHook at registration', async () => {
    const app = buildPlainApp();

    await expect(
      app.register(sensitivePlugin, {
        context: () => ({ name: 'x' }),
        contextHook: 'onSend' as never,
      })
    ).rejects.toThrow(/sensitivePlugin\.contextHook/);
  });
});
