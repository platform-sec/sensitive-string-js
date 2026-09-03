import 'reflect-metadata';
import {
  Body,
  Controller,
  Get,
  Injectable,
  Post,
  Query,
  UseGuards,
  ValidationPipe,
  type ArgumentMetadata,
  type CallHandler,
  type CanActivate,
  type ExecutionContext,
  type INestApplication,
  type NestInterceptor,
  type PipeTransform,
} from '@nestjs/common';
import { APP_INTERCEPTOR, APP_PIPE } from '@nestjs/core';
import {
  SensitiveString,
  getCurrentRevealContext,
  type RevealContext,
} from '@platform-sec/sensitive-string-core';
import { tap, type Observable } from 'rxjs';
import request from 'supertest';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import { SENSITIVE_CONTEXT_FACTORY } from '../constants.js';
import { SensitiveHeader } from '../decorators/sensitive-header.decorator.js';
import { SensitiveParam } from '../decorators/sensitive-param.decorator.js';
import { SensitiveQuery } from '../decorators/sensitive-query.decorator.js';
import { WithRevealContext } from '../decorators/with-reveal-context.decorator.js';
import { SensitiveContextInterceptor } from '../interceptors/sensitive-context.interceptor.js';
import { SensitiveTransformPipe } from '../pipes/sensitive-transform.pipe.js';
import type { RevealContextFactory } from '../types.js';
import {
  AdminLoginDto,
  CANARY,
  CardDto,
  LoginDto,
  PaymentDto,
  WhitelistDto,
  createTestApp,
  validationPipe,
} from './fixtures.js';

/** Where each stage of the lifecycle reports what it saw. */
const probe = {
  dto: undefined as unknown,
  contexts: {} as Record<string, RevealContext | null>,
};

beforeEach(() => {
  probe.dto = undefined;
  probe.contexts = {};
});

/** Records the reveal context visible to a pipe, which runs after interceptors. */
@Injectable()
class ContextProbePipe implements PipeTransform {
  transform(value: unknown, _metadata: ArgumentMetadata): unknown {
    probe.contexts['pipe'] = getCurrentRevealContext();

    return value;
  }
}

/** Registered after the context interceptor, so it is inner and sees the scope. */
@Injectable()
class ContextProbeInterceptor implements NestInterceptor {
  intercept(_context: ExecutionContext, next: CallHandler): Observable<unknown> {
    probe.contexts['interceptor:before'] = getCurrentRevealContext();

    return next.handle().pipe(
      tap(() => {
        probe.contexts['interceptor:after'] = getCurrentRevealContext();
      })
    );
  }
}

@Injectable()
class ContextProbeGuard implements CanActivate {
  canActivate(_context: ExecutionContext): boolean {
    probe.contexts['guard'] = getCurrentRevealContext();

    return true;
  }
}

@Controller('auth')
class AuthController {
  @Post('login')
  login(@Body() dto: LoginDto) {
    probe.dto = dto;
    probe.contexts['handler'] = getCurrentRevealContext();

    return { ok: true };
  }

  @Post('admin-login')
  adminLogin(@Body() dto: AdminLoginDto) {
    probe.dto = dto;

    return { ok: true };
  }

  @Post('named')
  @WithRevealContext({ name: 'user-authentication', tags: { flow: 'password' } })
  named(@Body() dto: LoginDto) {
    probe.dto = dto;
    probe.contexts['handler'] = getCurrentRevealContext();

    return { ok: true };
  }

  @Post('guarded')
  @UseGuards(ContextProbeGuard)
  guarded(@Body() dto: LoginDto) {
    probe.dto = dto;
    probe.contexts['handler'] = getCurrentRevealContext();

    return { ok: true };
  }
}

@Controller('payment')
class PaymentController {
  @Post('charge')
  charge(@Body() dto: PaymentDto) {
    probe.dto = dto;

    return { ok: true };
  }

  @Post('whitelist')
  whitelist(@Body() dto: WhitelistDto) {
    probe.dto = dto;

    return { ok: true };
  }
}

@Controller('api')
class ApiController {
  @Get('resource')
  resource(
    @SensitiveHeader('authorization', 'credential') auth: SensitiveString<'credential'> | null,
    @SensitiveQuery('api_key', 'credential') apiKey: SensitiveString<'credential'> | null
  ) {
    probe.dto = { auth, apiKey };

    return { ok: true };
  }

  @Get('users/:userId/orders')
  user(
    @SensitiveParam('userId', 'sensitive') userId: SensitiveString<'sensitive'> | null,
    @Query('page') page: string
  ) {
    probe.dto = { userId, page };

    return { ok: true };
  }
}

const CONTROLLERS = [AuthController, PaymentController, ApiController];

let app: INestApplication | undefined;

/**
 * The running HTTP server, typed.
 *
 * `getHttpServer()` is declared `any`, and handing that straight to supertest
 * makes every request in the file an unchecked call.
 */
function server(): Parameters<typeof request>[0] {
  return app?.getHttpServer() as Parameters<typeof request>[0];
}

afterEach(async () => {
  await app?.close();
  app = undefined;
});

describe('DTO transformation over HTTP', () => {
  beforeEach(async () => {
    app = await createTestApp({
      controllers: CONTROLLERS,
      providers: [{ provide: APP_PIPE, useClass: SensitiveTransformPipe }],
    });
  });

  // TEST-NEST-001
  test('the handler receives wrapped fields on a DTO instance', async () => {
    await request(server())
      .post('/auth/login')
      .send({ email: 'user@example.com', password: CANARY, clientId: 'web' })
      .expect(201);

    const dto = probe.dto as LoginDto;

    expect(dto).toBeInstanceOf(LoginDto);
    expect(dto.email).toBeInstanceOf(SensitiveString);
    expect(dto.email.klass).toBe('sensitive');
    expect(dto.password.klass).toBe('credential');
    expect(dto.password.reveal()).toBe(CANARY);
    expect(dto.clientId).toBe('web');
  });

  // TEST-NEST-007
  test('a subclass DTO has both inherited and added fields wrapped', async () => {
    await request(server())
      .post('/auth/admin-login')
      .send({ email: 'admin@example.com', password: CANARY, clientId: 'web', totp: '123456' })
      .expect(201);

    const dto = probe.dto as AdminLoginDto;

    expect(dto.password).toBeInstanceOf(SensitiveString);
    expect(dto.totp).toBeInstanceOf(SensitiveString);
    expect(dto.totp.label).toBe('totp');
  });

  // TEST-NEST-EDGE-002
  test('a nested DTO is wrapped when transform is on', async () => {
    await request(server())
      .post('/payment/charge')
      .send({ card: { number: CANARY, holder: 'A. User' }, amount: 100 })
      .expect(201);

    const dto = probe.dto as PaymentDto;

    expect(dto.card).toBeInstanceOf(CardDto);
    expect(dto.card.number).toBeInstanceOf(SensitiveString);
    expect(dto.card.number.reveal()).toBe(CANARY);
    expect(dto.amount).toBe(100);
  });

  // TEST-NEST-INT-005
  test('whitelist strips a field carrying only @Sensitive', async () => {
    await request(server())
      .post('/payment/whitelist')
      .send({ stripped: CANARY, kept: CANARY })
      .expect(201);

    const dto = probe.dto as WhitelistDto;

    expect(dto.stripped).toBeUndefined();
    expect(dto.kept).toBeInstanceOf(SensitiveString);
  });

  // TEST-NEST-006 / TEST-NEST-INT-001
  test('validation rejects a bad value before any wrapping happens', async () => {
    const response = await request(server())
      .post('/auth/login')
      .send({ email: 'not-an-email', password: 'short', clientId: 'web' })
      .expect(400);

    expect(probe.dto).toBeUndefined();
    expect(JSON.stringify(response.body)).toContain('email must be an email');
  });

  test('a validator sees the plain string, not a wrapped value', async () => {
    // @IsEmail() accepting the value is the proof: it rejects anything that is
    // not a string, so a SensitiveString reaching it would fail here.
    await request(server())
      .post('/auth/login')
      .send({ email: 'user@example.com', password: CANARY, clientId: 'web' })
      .expect(201);

    expect((probe.dto as LoginDto).email.reveal()).toBe('user@example.com');
  });
});

describe('DTO transformation without ValidationPipe', () => {
  beforeEach(async () => {
    app = await createTestApp({
      controllers: CONTROLLERS,
      providers: [{ provide: APP_PIPE, useClass: SensitiveTransformPipe }],
      validation: false,
    });
  });

  test('top-level fields are still wrapped', async () => {
    await request(server())
      .post('/auth/login')
      .send({ email: 'user@example.com', password: CANARY, clientId: 'web' })
      .expect(201);

    expect((probe.dto as LoginDto).password).toBeInstanceOf(SensitiveString);
  });

  test('a nested DTO is not wrapped, because nothing instantiated its class', async () => {
    await request(server())
      .post('/payment/charge')
      .send({ card: { number: CANARY, holder: 'A. User' }, amount: 100 })
      .expect(201);

    // Documented limitation: nested discovery keys off the runtime class, which
    // only exists once class-transformer has built it.
    expect((probe.dto as PaymentDto).card.number).toBe(CANARY as never);
  });
});

describe('reveal context across the request lifecycle', () => {
  const contextFactory: RevealContextFactory = (ctx) => {
    const req = ctx.switchToHttp().getRequest<{ method: string; path: string }>();

    return { name: `${req.method} ${req.path}`, tags: { stage: 'request' } };
  };

  beforeEach(async () => {
    app = await createTestApp({
      controllers: CONTROLLERS,
      providers: [
        { provide: APP_PIPE, useClass: SensitiveTransformPipe },
        { provide: APP_PIPE, useClass: ContextProbePipe },
        { provide: SENSITIVE_CONTEXT_FACTORY, useValue: contextFactory },
        { provide: APP_INTERCEPTOR, useClass: SensitiveContextInterceptor },
        { provide: APP_INTERCEPTOR, useClass: ContextProbeInterceptor },
      ],
    });
  });

  // TEST-NEST-003
  test('pipes, the handler, and a downstream intercept() all see the context', async () => {
    await request(server())
      .post('/auth/login')
      .send({ email: 'user@example.com', password: CANARY, clientId: 'web' })
      .expect(201);

    expect(probe.contexts['pipe']?.name).toBe('POST /auth/login');
    expect(probe.contexts['handler']?.name).toBe('POST /auth/login');
    expect(probe.contexts['interceptor:before']?.name).toBe('POST /auth/login');
  });

  // The documented gap. NestJS emits the handler result from outside the
  // region it bound to the async context, so the response operators of an
  // inner interceptor run without one. Pinned here so a NestJS upgrade that
  // changes it shows up as a failing test rather than as a quiet promotion.
  test('the response operators of an inner interceptor see no context', async () => {
    await request(server())
      .post('/auth/login')
      .send({ email: 'user@example.com', password: CANARY, clientId: 'web' })
      .expect(201);

    expect(probe.contexts['interceptor:after']).toBeNull();
  });

  // TEST-NEST-005
  test('@WithRevealContext merges over the request context', async () => {
    await request(server())
      .post('/auth/named')
      .send({ email: 'user@example.com', password: CANARY, clientId: 'web' })
      .expect(201);

    expect(probe.contexts['handler']).toEqual({
      name: 'user-authentication',
      tags: { stage: 'request', flow: 'password' },
    });
  });

  // TEST-NEST-INT-002
  test('a guard sees no context, and an explicit one still audits', async () => {
    await request(server())
      .post('/auth/guarded')
      .send({ email: 'user@example.com', password: CANARY, clientId: 'web' })
      .expect(201);

    expect(probe.contexts['guard']).toBeNull();

    const audit = vi.fn();

    new SensitiveString(CANARY, 'credential').reveal({ name: 'guard', auditReveal: audit });

    expect(audit).toHaveBeenCalledOnce();
  });
});

describe('reveal context without a factory', () => {
  beforeEach(async () => {
    app = await createTestApp({
      controllers: CONTROLLERS,
      providers: [
        { provide: APP_PIPE, useClass: SensitiveTransformPipe },
        { provide: APP_INTERCEPTOR, useClass: SensitiveContextInterceptor },
      ],
    });
  });

  test('the interceptor still applies handler metadata', async () => {
    await request(server())
      .post('/auth/named')
      .send({ email: 'user@example.com', password: CANARY, clientId: 'web' })
      .expect(201);

    expect(probe.contexts['handler']).toEqual({
      name: 'user-authentication',
      tags: { flow: 'password' },
    });
  });

  // TEST-NEST-005
  test('@WithRevealContext is a no-op with no interceptor registered', async () => {
    await app?.close();
    app = await createTestApp({
      controllers: CONTROLLERS,
      providers: [{ provide: APP_PIPE, useClass: SensitiveTransformPipe }],
    });

    await request(server())
      .post('/auth/named')
      .send({ email: 'user@example.com', password: CANARY, clientId: 'web' })
      .expect(201);

    expect(probe.contexts['handler']).toBeNull();
  });
});

describe('parameter decorators', () => {
  beforeEach(async () => {
    app = await createTestApp({
      controllers: CONTROLLERS,
      providers: [{ provide: APP_PIPE, useClass: SensitiveTransformPipe }],
    });
  });

  // TEST-NEST-002
  test('wraps a header and a query parameter', async () => {
    await request(server())
      .get('/api/resource')
      .query({ api_key: CANARY })
      .set('authorization', `Bearer ${CANARY}`)
      .expect(200);

    const seen = probe.dto as { auth: SensitiveString; apiKey: SensitiveString };

    expect(seen.auth).toBeInstanceOf(SensitiveString);
    expect(seen.auth.klass).toBe('credential');
    expect(seen.auth.label).toBe('authorization');
    expect(seen.auth.reveal()).toBe(`Bearer ${CANARY}`);
    expect(seen.apiKey.reveal()).toBe(CANARY);
  });

  // TEST-NEST-002
  test('yields null for an absent header or query parameter', async () => {
    await request(server()).get('/api/resource').expect(200);

    expect(probe.dto).toEqual({ auth: null, apiKey: null });
  });

  test('yields null for an empty header', async () => {
    await request(server()).get('/api/resource').set('authorization', '').expect(200);

    expect((probe.dto as { auth: unknown }).auth).toBeNull();
  });

  // TEST-NEST-002
  test('uses the first value of a repeated query parameter', async () => {
    await request(server()).get('/api/resource?api_key=first&api_key=second').expect(200);

    expect((probe.dto as { apiKey: SensitiveString }).apiKey.reveal()).toBe('first');
  });

  // TEST-NEST-002 / TEST-NEST-INT-003
  test('wraps a route parameter and leaves a plain @Query alongside it', async () => {
    await request(server()).get('/api/users/u-7/orders?page=2').expect(200);

    const seen = probe.dto as { userId: SensitiveString; page: string };

    expect(seen.userId).toBeInstanceOf(SensitiveString);
    expect(seen.userId.klass).toBe('sensitive');
    expect(seen.userId.reveal()).toBe('u-7');
    expect(seen.page).toBe('2');
  });
});

describe('pipe ordering', () => {
  test('wrapping before validation breaks every request', async () => {
    // What the ordering rule prevents. With SensitiveTransformPipe first,
    // ValidationPipe hands the already-wrapped payload to class-transformer,
    // which tries to rebuild each SensitiveString by calling its constructor
    // with no arguments. That throws before any validator runs, so the failure
    // is a 500 rather than a validation error.
    app = await createTestApp({
      controllers: CONTROLLERS,
      providers: [
        { provide: APP_PIPE, useClass: SensitiveTransformPipe },
        { provide: APP_PIPE, useValue: validationPipe() },
      ],
      validation: false,
    });

    await request(server())
      .post('/auth/login')
      .send({ email: 'user@example.com', password: CANARY, clientId: 'web' })
      .expect(500);
  });

  test('a ValidationPipe with transform off still leaves top-level fields wrapped', async () => {
    app = await createTestApp({
      controllers: CONTROLLERS,
      providers: [{ provide: APP_PIPE, useClass: SensitiveTransformPipe }],
      validation: new ValidationPipe({
        transform: false,
        validationError: { target: false, value: false },
      }),
    });

    await request(server())
      .post('/auth/login')
      .send({ email: 'user@example.com', password: CANARY, clientId: 'web' })
      .expect(201);

    expect((probe.dto as LoginDto).password).toBeInstanceOf(SensitiveString);
  });
});
