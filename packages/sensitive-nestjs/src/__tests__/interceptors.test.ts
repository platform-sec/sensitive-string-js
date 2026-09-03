import 'reflect-metadata';
import { StreamableFile, type CallHandler, type ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import {
  SensitiveString,
  getCurrentRevealContext,
  type RevealContext,
} from '@platform-sec/sensitive-string-core';
import { Readable } from 'node:stream';
import { firstValueFrom, of } from 'rxjs';
import { describe, expect, test, vi } from 'vitest';
import { REVEAL_CONTEXT_KEY } from '../constants.js';
import { SensitiveContextInterceptor } from '../interceptors/sensitive-context.interceptor.js';
import { SensitiveResponseInterceptor } from '../interceptors/sensitive-response.interceptor.js';
import type { HandlerRevealContext, RevealContextFactory } from '../types.js';
import { CANARY, UserEntity } from './fixtures.js';

/** A minimal ExecutionContext: only what the interceptors actually read. */
function executionContext(
  declared?: HandlerRevealContext,
  request: Record<string, unknown> = {}
): ExecutionContext {
  const handler = (): void => {};

  if (declared !== undefined) {
    Reflect.defineMetadata(REVEAL_CONTEXT_KEY, declared, handler);
  }

  class Host {}

  return {
    getHandler: () => handler,
    getClass: () => Host,
    switchToHttp: () => ({ getRequest: () => request }),
  } as unknown as ExecutionContext;
}

function handlerReturning<T>(value: T, onCall?: () => void): CallHandler<T> {
  return {
    handle: () => {
      onCall?.();

      return of(value);
    },
  };
}

function interceptor(factory?: RevealContextFactory): SensitiveContextInterceptor {
  return factory
    ? new SensitiveContextInterceptor(new Reflector(), factory)
    : new SensitiveContextInterceptor(new Reflector());
}

describe('SensitiveContextInterceptor', () => {
  // TEST-NEST-003
  test('the factory context is active while the handler runs', async () => {
    let seen: RevealContext | null = null;
    const factory: RevealContextFactory = () => ({ name: 'GET /users' });
    const next = handlerReturning('ok', () => {
      seen = getCurrentRevealContext();
    });

    await firstValueFrom(interceptor(factory).intercept(executionContext(), next));

    expect(seen).toEqual({ name: 'GET /users' });
  });

  test('the context does not outlive the request', async () => {
    const factory: RevealContextFactory = () => ({ name: 'GET /users' });

    await firstValueFrom(
      interceptor(factory).intercept(executionContext(), handlerReturning('ok'))
    );

    expect(getCurrentRevealContext()).toBeNull();
  });

  test('the factory receives the ExecutionContext', () => {
    const factory = vi.fn<RevealContextFactory>(() => ({ name: 'ctx' }));
    const ctx = executionContext();

    interceptor(factory).intercept(ctx, handlerReturning('ok'));

    expect(factory).toHaveBeenCalledWith(ctx);
  });

  test('establishes no context when neither factory nor metadata is present', async () => {
    let seen: RevealContext | null = { name: 'sentinel' };
    const next = handlerReturning('ok', () => {
      seen = getCurrentRevealContext();
    });

    await firstValueFrom(interceptor().intercept(executionContext(), next));

    expect(seen).toBeNull();
  });

  test('applies handler metadata with no factory registered', async () => {
    let seen: RevealContext | null = null;
    const next = handlerReturning('ok', () => {
      seen = getCurrentRevealContext();
    });

    await firstValueFrom(
      interceptor().intercept(executionContext({ name: 'user-authentication' }), next)
    );

    expect(seen).toEqual({ name: 'user-authentication' });
  });

  // TEST-NEST-005
  test('handler metadata overrides the factory name, reason, and auditReveal', async () => {
    const requestAudit = vi.fn();
    const handlerAudit = vi.fn();
    let seen: RevealContext | null = null;
    const factory: RevealContextFactory = () => ({
      name: 'GET /payment/charge',
      reason: 'request',
      auditReveal: requestAudit,
    });
    const next = handlerReturning('ok', () => {
      seen = getCurrentRevealContext();
    });

    await firstValueFrom(
      interceptor(factory).intercept(
        executionContext({
          name: 'payment-processing',
          reason: 'charging customer card',
          auditReveal: handlerAudit,
        }),
        next
      )
    );

    expect(seen).toMatchObject({
      name: 'payment-processing',
      reason: 'charging customer card',
      auditReveal: handlerAudit,
    });
  });

  test('tags are merged, with handler tags winning on conflict', async () => {
    let seen: RevealContext | null = null;
    const factory: RevealContextFactory = () => ({
      name: 'request',
      tags: { requestId: 'r-1', stage: 'request' },
    });
    const next = handlerReturning('ok', () => {
      seen = getCurrentRevealContext();
    });

    await firstValueFrom(
      interceptor(factory).intercept(
        executionContext({ name: 'handler', tags: { stage: 'handler', orderId: 'o-9' } }),
        next
      )
    );

    expect(seen?.tags).toEqual({ requestId: 'r-1', stage: 'handler', orderId: 'o-9' });
  });

  test('a factory-form handler context receives the ExecutionContext', async () => {
    let seen: RevealContext | null = null;
    const ctx = executionContext(
      (execution) => ({
        name: 'refund-processing',
        tags: {
          orderId: execution.switchToHttp().getRequest<{ params: { orderId: string } }>().params
            .orderId,
        },
      }),
      { params: { orderId: 'o-42' } }
    );
    const next = handlerReturning('ok', () => {
      seen = getCurrentRevealContext();
    });

    await firstValueFrom(interceptor().intercept(ctx, next));

    expect(seen).toEqual({ name: 'refund-processing', tags: { orderId: 'o-42' } });
  });

  test('a handler factory returning undefined leaves the request context intact', async () => {
    let seen: RevealContext | null = null;
    const factory: RevealContextFactory = () => ({ name: 'request-level' });
    const next = handlerReturning('ok', () => {
      seen = getCurrentRevealContext();
    });

    await firstValueFrom(
      interceptor(factory).intercept(
        executionContext(() => undefined),
        next
      )
    );

    expect(seen).toEqual({ name: 'request-level' });
  });

  test('a factory returning undefined leaves the handler context intact', async () => {
    let seen: RevealContext | null = null;
    const next = handlerReturning('ok', () => {
      seen = getCurrentRevealContext();
    });

    await firstValueFrom(
      interceptor(() => undefined).intercept(executionContext({ name: 'handler-only' }), next)
    );

    expect(seen).toEqual({ name: 'handler-only' });
  });

  test('the merged auditReveal is what a reveal in the handler fires', async () => {
    const audit = vi.fn();
    const secret = new SensitiveString(CANARY, 'sensitive', 'email');
    const factory: RevealContextFactory = () => ({ name: 'request', auditReveal: audit });
    const next = handlerReturning('ok', () => {
      secret.reveal();
    });

    await firstValueFrom(interceptor(factory).intercept(executionContext(), next));

    expect(audit).toHaveBeenCalledOnce();
    expect(audit.mock.calls[0]?.[0]).toBe(secret);
  });
});

describe('SensitiveResponseInterceptor', () => {
  const responseInterceptor = new SensitiveResponseInterceptor();

  async function redact<T>(body: T): Promise<unknown> {
    return firstValueFrom(
      responseInterceptor.intercept({} as ExecutionContext, handlerReturning(body))
    );
  }

  // TEST-NEST-004
  test('replaces a SensitiveString with its redacted form', async () => {
    const body = await redact({ apiKey: new SensitiveString(CANARY, 'credential', 'api_key') });

    expect(body).toEqual({ apiKey: '[REDACTED:credential]' });
  });

  test('redacts inside arrays and nested objects', async () => {
    const body = await redact({
      users: [{ email: new SensitiveString(CANARY, 'sensitive') }],
    });

    expect(body).toEqual({ users: [{ email: '[REDACTED:sensitive]' }] });
  });

  test('replaces a serialized value with the redaction of its class', async () => {
    const token = new SensitiveString(CANARY, 'credential', 'token');
    const body = (await redact({ token: token.serialize() })) as { token: unknown };

    expect(body.token).toBe('[REDACTED:credential]');
    expect(JSON.stringify(body)).not.toContain(CANARY);
  });

  // TEST-NEST-EDGE-006
  test('keeps the prototype of a class instance', async () => {
    const entity = new UserEntity(
      1,
      new SensitiveString('a@b.c', 'sensitive', 'email'),
      new SensitiveString(CANARY, 'credential', 'api_key')
    );
    const body = (await redact(entity)) as UserEntity;

    expect(body).toBeInstanceOf(UserEntity);
    expect(body.id).toBe(1);
    expect(body.apiKey).toBe('[REDACTED:credential]');
  });

  // TEST-NEST-EDGE-008
  test('does not mutate the value the handler returned', async () => {
    const entity = new UserEntity(
      1,
      new SensitiveString('a@b.c', 'sensitive', 'email'),
      new SensitiveString(CANARY, 'credential', 'api_key')
    );

    await redact(entity);

    expect(entity.apiKey).toBeInstanceOf(SensitiveString);
    expect(entity.apiKey.reveal()).toBe(CANARY);
  });

  // TEST-NEST-EDGE-007
  test.each([
    ['a StreamableFile', new StreamableFile(Buffer.from('bytes'))],
    ['a Buffer', Buffer.from('bytes')],
    ['a Readable', Readable.from(['bytes'])],
  ])('passes %s through by reference', async (_name, body) => {
    expect(await redact(body)).toBe(body);
  });

  test('passes a Date through by reference', async () => {
    const date = new Date('2026-09-03T00:00:00.000Z');

    expect(await redact({ createdAt: date })).toEqual({ createdAt: date });
  });

  test.each([
    ['a Map', new Map([['k', 'v']])],
    ['a Set', new Set(['v'])],
    ['a RegExp', /pattern/u],
    ['a URL', new URL('https://example.com/path')],
  ])('passes %s through, since a property copy would break it', async (_name, member) => {
    const body = (await redact({ member })) as { member: unknown };

    expect(body.member).toBe(member);
  });

  test.each([
    ['null', null],
    ['undefined', undefined],
    ['a string', 'plain'],
    ['a number', 42],
    ['a boolean', false],
  ])('passes %s through unchanged', async (_name, body) => {
    expect(await redact(body)).toBe(body);
  });

  test('preserves a shared reference instead of reporting it as circular', async () => {
    const user = { email: new SensitiveString(CANARY, 'sensitive') };
    const body = (await redact({ author: user, reviewer: user })) as {
      author: unknown;
      reviewer: unknown;
    };

    expect(body.author).toEqual({ email: '[REDACTED:sensitive]' });
    expect(body.reviewer).toBe(body.author);
  });

  test('terminates on a cyclic body and keeps the cycle', async () => {
    const node: Record<string, unknown> = { secret: new SensitiveString(CANARY, 'sensitive') };

    node['self'] = node;

    const body = (await redact(node)) as Record<string, unknown>;

    expect(body['secret']).toBe('[REDACTED:sensitive]');
    expect(body['self']).toBe(body);
  });

  test('leaves a value produced by an explicit reveal alone', async () => {
    const body = await redact({ email: new SensitiveString('a@b.c', 'sensitive').reveal() });

    expect(body).toEqual({ email: 'a@b.c' });
  });
});
