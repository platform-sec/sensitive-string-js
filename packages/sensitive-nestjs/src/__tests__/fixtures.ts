import 'reflect-metadata';
import { ValidationPipe, type INestApplication } from '@nestjs/common';
import { APP_PIPE } from '@nestjs/core';
import { Test } from '@nestjs/testing';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import {
  Allow,
  IsEmail,
  IsInt,
  IsOptional,
  IsString,
  MinLength,
  ValidateNested,
} from 'class-validator';
import { Type } from 'class-transformer';
import { Sensitive } from '../decorators/sensitive.decorator.js';

/**
 * The canary every leak assertion looks for. One constant, so a test that
 * forgets to assert absence is visible next to one that does not.
 */
export const CANARY = 'LEAKED_SECRET_abc123xyz';

export class LoginDto {
  @Sensitive('sensitive', 'email')
  @IsEmail()
  email!: SensitiveString<'sensitive'>;

  @Sensitive('credential', 'password')
  @IsString()
  @MinLength(8)
  password!: SensitiveString<'credential'>;

  @IsString()
  clientId!: string;
}

/** Exercises inheritance: every parent field, plus one the subclass adds. */
export class AdminLoginDto extends LoginDto {
  @Sensitive('credential', 'totp')
  @IsString()
  totp!: SensitiveString<'credential'>;
}

export class CardDto {
  @Sensitive('credential', 'card_number')
  @IsString()
  number!: SensitiveString<'credential'>;

  @IsString()
  holder!: string;
}

export class PaymentDto {
  @ValidateNested()
  @Type(() => CardDto)
  card!: CardDto;

  @IsInt()
  amount!: number;
}

export class TokenBagDto {
  @Sensitive('credential', 'tokens')
  @Allow()
  tokens!: SensitiveString<'credential'>[];
}

export class OptionalDto {
  @Sensitive('credential', 'password')
  @IsOptional()
  @IsString()
  password?: SensitiveString<'credential'>;

  @IsString()
  username!: string;
}

/** A field carrying only `@Sensitive`, which `whitelist: true` strips. */
export class WhitelistDto {
  @Sensitive('credential', 'stripped')
  stripped!: SensitiveString<'credential'>;

  @Sensitive('credential', 'kept')
  @Allow()
  kept!: SensitiveString<'credential'>;
}

/** Stands in for an ORM entity: a class instance, not a plain object. */
export class UserEntity {
  constructor(
    readonly id: number,
    readonly email: SensitiveString<'sensitive'>,
    readonly apiKey: SensitiveString<'credential'>
  ) {}
}

/** The recommended ValidationPipe settings, in one place. */
export function validationPipe(overrides: ConstructorParameters<typeof ValidationPipe>[0] = {}) {
  return new ValidationPipe({
    transform: true,
    whitelist: true,
    // Without this, every ValidationError carries the raw value and the whole
    // target object, and any exception factory or filter that serializes one
    // echoes the secret straight back to the client.
    validationError: { target: false, value: false },
    ...overrides,
  });
}

export interface TestAppOptions {
  controllers: unknown[];
  providers?: unknown[];
  /** Registered before the transform pipe, as the ordering rule requires. */
  validation?: ValidationPipe | false;
}

/**
 * Boot a NestJS application over the Express adapter.
 *
 * Pipes and interceptors are registered through `APP_PIPE` and
 * `APP_INTERCEPTOR` so the relative order is the registration order, which is
 * the ordering guarantee the package documents.
 */
export async function createTestApp(options: TestAppOptions): Promise<INestApplication> {
  const providers = [...(options.providers ?? [])];

  if (options.validation !== false) {
    providers.unshift({
      provide: APP_PIPE,
      useValue: options.validation ?? validationPipe(),
    });
  }

  const moduleRef = await Test.createTestingModule({
    controllers: options.controllers as never[],
    providers: providers as never[],
  }).compile();

  const app = moduleRef.createNestApplication();

  await app.init();

  return app;
}
