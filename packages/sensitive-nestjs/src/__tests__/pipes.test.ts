import 'reflect-metadata';
import type { ArgumentMetadata } from '@nestjs/common';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { describe, expect, test } from 'vitest';
import { SensitiveTransformPipe } from '../pipes/sensitive-transform.pipe.js';
import {
  CANARY,
  CardDto,
  LoginDto,
  OptionalDto,
  PaymentDto,
  TokenBagDto,
  UserEntity,
} from './fixtures.js';

const pipe = new SensitiveTransformPipe();

function meta(metatype: unknown, type: ArgumentMetadata['type'] = 'body'): ArgumentMetadata {
  return { type, metatype: metatype as ArgumentMetadata['metatype'], data: undefined };
}

function login(overrides: Partial<Record<keyof LoginDto, unknown>> = {}): LoginDto {
  return Object.assign(new LoginDto(), {
    email: 'user@example.com',
    password: CANARY,
    clientId: 'web',
    ...overrides,
  });
}

describe('SensitiveTransformPipe', () => {
  // TEST-NEST-001
  test('wraps decorated fields and leaves the rest alone', () => {
    const dto = pipe.transform(login(), meta(LoginDto)) as LoginDto;

    expect(dto.email).toBeInstanceOf(SensitiveString);
    expect(dto.email.klass).toBe('sensitive');
    expect(dto.email.label).toBe('email');
    expect(dto.password.klass).toBe('credential');
    expect(dto.clientId).toBe('web');
  });

  test('preserves the DTO prototype and identity', () => {
    const input = login();
    const output = pipe.transform(input, meta(LoginDto));

    expect(output).toBe(input);
    expect(output).toBeInstanceOf(LoginDto);
  });

  test('labels a field by its property name when the decorator gives none', () => {
    class Unlabelled {
      token = CANARY;
    }

    Reflect.defineMetadata(
      'platform-sec:sensitive-fields',
      new Map([['token', { klass: 'credential', label: undefined }]]),
      Unlabelled
    );

    const dto = pipe.transform(new Unlabelled(), meta(Unlabelled)) as {
      token: SensitiveString<'credential'>;
    };

    expect(dto.token.label).toBe('token');
  });

  test.each([
    ['query', 'query'],
    ['param', 'param'],
    ['custom', 'custom'],
  ] as const)('applies to %s parameters, not only bodies', (_name, type) => {
    const dto = pipe.transform(login(), meta(LoginDto, type)) as LoginDto;

    expect(dto.password).toBeInstanceOf(SensitiveString);
  });

  test.each([
    ['undefined', undefined],
    ['Object', Object],
    ['String', String],
    ['Number', Number],
    ['Boolean', Boolean],
    ['Array', Array],
  ])('passes through a %s metatype without walking the value', (_name, metatype) => {
    const value = Object.assign(new LoginDto(), { password: CANARY });

    pipe.transform(value, meta(metatype));

    expect(value.password).toBe(CANARY);
  });

  // TEST-NEST-EDGE-004
  test('running the pipe twice does not double-wrap', () => {
    const once = pipe.transform(login(), meta(LoginDto)) as LoginDto;
    const first = once.password;
    const twice = pipe.transform(once, meta(LoginDto)) as LoginDto;

    expect(twice.password).toBe(first);
    expect(twice.password.reveal()).toBe(CANARY);
  });

  // TEST-NEST-EDGE-005
  test.each([
    ['a number', 12345],
    ['an object', { nested: true }],
    ['null', null],
    ['a boolean', true],
  ])('leaves %s in a sensitive field untouched', (_name, value) => {
    const dto = pipe.transform(login({ password: value }), meta(LoginDto)) as {
      password: unknown;
    };

    expect(dto.password).toEqual(value);
  });

  // TEST-NEST-EDGE-001
  test('leaves a missing optional field undefined', () => {
    const dto = pipe.transform(
      Object.assign(new OptionalDto(), { username: 'alice' }),
      meta(OptionalDto)
    ) as OptionalDto;

    expect(dto.password).toBeUndefined();
    expect(dto.username).toBe('alice');
  });

  // TEST-NEST-EDGE-003
  test('wraps every string in an array field', () => {
    const dto = pipe.transform(
      Object.assign(new TokenBagDto(), { tokens: [CANARY, 'second'] }),
      meta(TokenBagDto)
    ) as TokenBagDto;

    expect(dto.tokens).toHaveLength(2);
    expect(dto.tokens[0]).toBeInstanceOf(SensitiveString);
    expect(dto.tokens[0]?.reveal()).toBe(CANARY);
    expect(dto.tokens[1]?.klass).toBe('credential');
  });

  test('leaves non-string members of an array field untouched', () => {
    const dto = pipe.transform(
      Object.assign(new TokenBagDto(), { tokens: [CANARY, 42] }),
      meta(TokenBagDto)
    ) as { tokens: unknown[] };

    expect(dto.tokens[0]).toBeInstanceOf(SensitiveString);
    expect(dto.tokens[1]).toBe(42);
  });

  // TEST-NEST-EDGE-002
  test('wraps a nested DTO instance', () => {
    const card = Object.assign(new CardDto(), { number: CANARY, holder: 'A. User' });
    const payment = Object.assign(new PaymentDto(), { card, amount: 100 });

    pipe.transform(payment, meta(PaymentDto));

    expect(payment.card.number).toBeInstanceOf(SensitiveString);
    expect(payment.card.number.klass).toBe('credential');
    expect(payment.card.holder).toBe('A. User');
  });

  test('leaves a nested plain object alone, because it carries no metadata', () => {
    const payment = Object.assign(new PaymentDto(), {
      card: { number: CANARY, holder: 'A. User' },
      amount: 100,
    });

    pipe.transform(payment, meta(PaymentDto));

    expect(payment.card.number).toBe(CANARY);
  });

  test('wraps DTO instances nested inside an array', () => {
    class Basket {
      cards: CardDto[] = [];
    }

    Reflect.defineMetadata('platform-sec:sensitive-fields', new Map(), Basket);

    const basket = Object.assign(new Basket(), {
      cards: [Object.assign(new CardDto(), { number: CANARY, holder: 'A' })],
    });

    pipe.transform(basket, meta(Basket));

    expect(basket.cards[0]?.number).toBeInstanceOf(SensitiveString);
  });

  test('terminates on a self-referencing object graph', () => {
    const card = Object.assign(new CardDto(), { number: CANARY, holder: 'A' });
    const payment = Object.assign(new PaymentDto(), { card, amount: 1 }) as PaymentDto & {
      self?: unknown;
    };

    payment.self = payment;

    expect(() => pipe.transform(payment, meta(PaymentDto))).not.toThrow();
    expect(payment.card.number).toBeInstanceOf(SensitiveString);
  });

  test('does not recurse into an already-wrapped value', () => {
    const dto = Object.assign(new LoginDto(), {
      email: new SensitiveString(CANARY, 'sensitive', 'email'),
      password: CANARY,
      clientId: 'web',
    });

    pipe.transform(dto, meta(LoginDto));

    expect(dto.email.reveal()).toBe(CANARY);
    expect(dto.password.klass).toBe('credential');
  });

  test.each([
    ['null', null],
    ['undefined', undefined],
    ['a string', 'plain'],
    ['a number', 3],
  ])('returns %s unchanged when the metatype is decorated', (_name, value) => {
    expect(pipe.transform(value, meta(LoginDto))).toBe(value);
  });

  test('wraps every entry of an array payload', () => {
    const payload = [login(), login({ password: 'second' })];

    pipe.transform(payload, meta(LoginDto));

    expect((payload[0] as unknown as { password: SensitiveString }).password).toBeInstanceOf(
      SensitiveString
    );
    expect((payload[1] as unknown as { password: SensitiveString }).password.reveal()).toBe(
      'second'
    );
  });

  test('leaves a nested class instance with no sensitive fields untouched', () => {
    const user = new UserEntity(1, 'a@b.c' as never, CANARY as never);

    // The walk reaches UserEntity, finds no @Sensitive fields on it, and
    // moves on.
    pipe.transform({ user }, meta(LoginDto));

    expect(user.apiKey).toBe(CANARY);
  });
});
