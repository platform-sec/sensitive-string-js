import 'reflect-metadata';
import {
  BadRequestException,
  Body,
  ClassSerializerInterceptor,
  Controller,
  Get,
  Post,
  ValidationPipe,
  type INestApplication,
  type ValidationError,
} from '@nestjs/common';
import { APP_INTERCEPTOR, APP_PIPE } from '@nestjs/core';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { inspect } from 'node:util';
import request from 'supertest';
import { afterEach, describe, expect, test } from 'vitest';
import { SensitiveHeader } from '../decorators/sensitive-header.decorator.js';
import { SensitiveResponseInterceptor } from '../interceptors/sensitive-response.interceptor.js';
import { SensitiveTransformPipe } from '../pipes/sensitive-transform.pipe.js';
import { CANARY, LoginDto, UserEntity, createTestApp, validationPipe } from './fixtures.js';

/** What each controller last saw or returned, for the log-side assertions. */
const captured: { dto?: LoginDto; header?: SensitiveString | null } = {};

function entity(): UserEntity {
  return new UserEntity(
    1,
    new SensitiveString('user@example.com', 'sensitive', 'email'),
    new SensitiveString(CANARY, 'credential', 'api_key')
  );
}

@Controller('sec')
class SecurityController {
  @Post('login')
  login(@Body() dto: LoginDto) {
    captured.dto = dto;

    return { ok: true };
  }

  /** Returns the DTO itself, the worst case for a response leak. */
  @Post('echo')
  echo(@Body() dto: LoginDto) {
    return dto;
  }

  @Get('plain')
  plain() {
    return { apiKey: new SensitiveString(CANARY, 'credential', 'api_key') };
  }

  @Get('entity')
  entityResponse() {
    return entity();
  }

  @Get('nested')
  nested() {
    return { data: { users: [entity()] }, count: 1 };
  }

  @Get('header')
  header(@SensitiveHeader('x-api-key', 'credential') key: SensitiveString<'credential'> | null) {
    captured.header = key;

    return { received: key !== null };
  }
}

let app: INestApplication | undefined;

afterEach(async () => {
  await app?.close();
  app = undefined;
  delete captured.dto;
  delete captured.header;
});

/**
 * Boot an app with the transform pipe plus whatever a test adds, and hand back
 * the HTTP server supertest drives.
 */
async function boot(
  providers: unknown[] = [],
  validation?: ValidationPipe
): Promise<Parameters<typeof request>[0]> {
  app = await createTestApp({
    controllers: [SecurityController],
    providers: [{ provide: APP_PIPE, useClass: SensitiveTransformPipe }, ...providers],
    ...(validation ? { validation } : {}),
  });

  return app.getHttpServer() as Parameters<typeof request>[0];
}

describe('CANARY: a transformed DTO does not leak when logged', () => {
  // TEST-NEST-SEC-001
  test('through util.inspect, JSON.stringify, or template interpolation', async () => {
    await request(await boot())
      .post('/sec/login')
      .send({ email: 'user@example.com', password: CANARY, clientId: 'web' })
      .expect(201);

    const dto = captured.dto!;

    expect(inspect(dto)).not.toContain(CANARY);
    expect(inspect(dto, { depth: 10, showHidden: true })).not.toContain(CANARY);
    expect(JSON.stringify(dto)).not.toContain(CANARY);
    expect(`${String(dto.password)}`).not.toContain(CANARY);
    expect(Object.values(dto).join(' ')).not.toContain(CANARY);

    // The value is still reachable, deliberately and only through reveal().
    expect(dto.password.reveal()).toBe(CANARY);
  });

  test('through the enumerable properties a naive serializer would copy', async () => {
    await request(await boot())
      .post('/sec/login')
      .send({ email: 'user@example.com', password: CANARY, clientId: 'web' })
      .expect(201);

    const own = Object.getOwnPropertyNames(captured.dto!.password);

    expect(own).not.toContain('value');
    expect(JSON.stringify(Object.entries(captured.dto!.password))).not.toContain(CANARY);
  });
});

describe('CANARY: responses do not leak', () => {
  // TEST-NEST-SEC-002
  test('a DTO returned straight from the handler is redacted by toJSON', async () => {
    const response = await request(await boot())
      .post('/sec/echo')
      .send({ email: 'user@example.com', password: CANARY, clientId: 'web' })
      .expect(201);

    expect(response.text).not.toContain(CANARY);
    expect(response.body).toMatchObject({ password: '[REDACTED:credential]' });
  });

  // TEST-NEST-SEC-002
  test.each([
    ['a plain object', '/sec/plain'],
    ['an entity instance', '/sec/entity'],
    ['a nested structure', '/sec/nested'],
  ])('%s is redacted with the response interceptor registered', async (_name, path) => {
    const response = await request(
      await boot([{ provide: APP_INTERCEPTOR, useClass: SensitiveResponseInterceptor }])
    )
      .get(path)
      .expect(200);

    expect(response.text).not.toContain(CANARY);
    expect(response.text).toContain('[REDACTED:credential]');
  });

  test.each([
    ['a plain object', '/sec/plain'],
    ['an entity instance', '/sec/entity'],
    ['a nested structure', '/sec/nested'],
  ])('%s is redacted by toJSON even without the response interceptor', async (_name, path) => {
    const response = await request(await boot())
      .get(path)
      .expect(200);

    expect(response.text).not.toContain(CANARY);
    expect(response.text).toContain('[REDACTED:credential]');
  });

  test('an entity keeps its own fields rather than collapsing to a string', async () => {
    const response = await request(
      await boot([{ provide: APP_INTERCEPTOR, useClass: SensitiveResponseInterceptor }])
    )
      .get('/sec/entity')
      .expect(200);

    expect(response.body).toEqual({
      id: 1,
      email: '[REDACTED:sensitive]',
      apiKey: '[REDACTED:credential]',
    });
  });
});

describe('CANARY: ClassSerializerInterceptor', () => {
  /** The recommended order: serializer outer, redaction inner. */
  const RECOMMENDED = [
    { provide: APP_INTERCEPTOR, useClass: ClassSerializerInterceptor },
    { provide: APP_INTERCEPTOR, useClass: SensitiveResponseInterceptor },
  ];

  // TEST-NEST-SEC-004
  test('keeps the redaction marker in the recommended order', async () => {
    const response = await request(await boot(RECOMMENDED))
      .get('/sec/entity')
      .expect(200);

    expect(response.text).not.toContain(CANARY);
    expect(response.body).toEqual({
      id: 1,
      email: '[REDACTED:sensitive]',
      apiKey: '[REDACTED:credential]',
    });
  });

  // TEST-NEST-SEC-004
  test('drops the marker without the response interceptor, which is why it exists', async () => {
    const response = await request(
      await boot([{ provide: APP_INTERCEPTOR, useClass: ClassSerializerInterceptor }])
    )
      .get('/sec/entity')
      .expect(200);

    // instanceToPlain copies the public fields of a SensitiveString and never
    // calls toJSON, so the marker is gone. The raw value stays out of reach,
    // because #value is a private field and not an own property, but a client
    // reading this response cannot tell a redacted field from a missing one.
    expect(response.text).not.toContain(CANARY);
    expect(response.text).not.toContain('[REDACTED');
    expect(response.body).toMatchObject({
      apiKey: { klass: 'credential', label: 'api_key' },
    });
  });
});

describe('CANARY: validation errors', () => {
  // TEST-NEST-SEC-003
  test('the recommended ValidationPipe options keep the value out of the response', async () => {
    const response = await request(await boot())
      .post('/sec/login')
      .send({ email: CANARY, password: 'short', clientId: 'web' })
      .expect(400);

    expect(response.text).not.toContain(CANARY);
  });

  // TEST-NEST-SEC-003
  test('and out of the ValidationError objects an exception factory receives', async () => {
    const seen: ValidationError[] = [];
    const pipe = validationPipe({
      exceptionFactory: (errors: ValidationError[]) => {
        seen.push(...errors);

        return new BadRequestException('invalid');
      },
    });

    await request(await boot([], pipe))
      .post('/sec/login')
      .send({ email: CANARY, password: 'short', clientId: 'web' })
      .expect(400);

    expect(seen.length).toBeGreaterThan(0);
    expect(JSON.stringify(seen)).not.toContain(CANARY);
    expect(inspect(seen, { depth: 10 })).not.toContain(CANARY);
  });

  // TEST-NEST-SEC-003
  test('the default ValidationPipe options do leak, which is why they are overridden', async () => {
    const seen: ValidationError[] = [];
    const pipe = new ValidationPipe({
      transform: true,
      whitelist: true,
      exceptionFactory: (errors: ValidationError[]) => {
        seen.push(...errors);

        return new BadRequestException('invalid');
      },
    });

    await request(await boot([], pipe))
      .post('/sec/login')
      .send({ email: CANARY, password: 'short', clientId: 'web' })
      .expect(400);

    // class-validator attaches the offending value and the whole target object
    // to every ValidationError unless told not to. Nothing in this package can
    // stop that, so the documentation makes
    // `validationError: { target: false, value: false }` part of the setup.
    expect(JSON.stringify(seen)).toContain(CANARY);
  });

  test('a rejected request never reaches the handler, so nothing is wrapped', async () => {
    await request(await boot())
      .post('/sec/login')
      .send({ email: CANARY, password: 'short', clientId: 'web' })
      .expect(400);

    expect(captured.dto).toBeUndefined();
  });
});

describe('CANARY: parameter decorators', () => {
  test('a wrapped header does not leak through logging or the response', async () => {
    const response = await request(await boot())
      .get('/sec/header')
      .set('x-api-key', CANARY)
      .expect(200);

    expect(response.text).not.toContain(CANARY);
    expect(inspect(captured.header)).not.toContain(CANARY);
    expect(JSON.stringify(captured.header)).not.toContain(CANARY);
    expect(captured.header?.reveal()).toBe(CANARY);
  });
});
