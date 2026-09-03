import 'reflect-metadata';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { describe, expect, test } from 'vitest';
import type { ExecutionContext } from '@nestjs/common';
import { REVEAL_CONTEXT_KEY } from '../constants.js';
import { extractSensitive } from '../decorators/request-part.js';
import { Sensitive, getSensitiveFields } from '../decorators/sensitive.decorator.js';
import { WithRevealContext } from '../decorators/with-reveal-context.decorator.js';
import { AdminLoginDto, LoginDto } from './fixtures.js';

describe('@Sensitive', () => {
  test('records the class and label of each decorated property', () => {
    const fields = getSensitiveFields(LoginDto);

    expect(fields?.get('email')).toEqual({ klass: 'sensitive', label: 'email' });
    expect(fields?.get('password')).toEqual({ klass: 'credential', label: 'password' });
  });

  test('leaves undecorated properties out of the map', () => {
    expect(getSensitiveFields(LoginDto)?.has('clientId')).toBe(false);
  });

  test('records an undefined label when none is given', () => {
    class Unlabelled {
      @Sensitive('credential')
      token!: SensitiveString<'credential'>;
    }

    expect(getSensitiveFields(Unlabelled)?.get('token')).toEqual({
      klass: 'credential',
      label: undefined,
    });
  });

  // TEST-NEST-007
  test('a subclass inherits its parent fields and adds its own', () => {
    const fields = getSensitiveFields(AdminLoginDto);

    expect([...(fields?.keys() ?? [])].sort()).toEqual(['email', 'password', 'totp']);
    expect(fields?.get('password')).toEqual({ klass: 'credential', label: 'password' });
    expect(fields?.get('totp')).toEqual({ klass: 'credential', label: 'totp' });
  });

  test('a subclass can re-decorate a parent field without changing the parent', () => {
    class Base {
      @Sensitive('sensitive', 'value')
      value = '';
    }

    class Child extends Base {
      @Sensitive('credential', 'tightened')
      override value = '';
    }

    expect(getSensitiveFields(Child)?.get('value')).toEqual({
      klass: 'credential',
      label: 'tightened',
    });
    expect(getSensitiveFields(Base)?.get('value')).toEqual({
      klass: 'sensitive',
      label: 'value',
    });
  });

  test('refuses a static property rather than writing metadata to Function', () => {
    expect(() => {
      class Static {
        @Sensitive('credential', 'token')
        static token = '';
      }

      return Static;
    }).toThrow(/static property 'token'/);

    // The failure mode this prevents: a static decorator's target is the
    // constructor, so target.constructor is Function itself.
    expect(getSensitiveFields(Function)).toBeUndefined();
  });

  test('refuses a symbol-keyed property, which no payload can populate', () => {
    const key = Symbol('token');

    expect(() => {
      class Symbolic {
        @Sensitive('credential')
        [key] = '';
      }

      return Symbolic;
    }).toThrow(/symbol-keyed property/);
  });

  test('a subclass that adds nothing still reports the parent fields', () => {
    class Passthrough extends LoginDto {}

    expect(getSensitiveFields(Passthrough)?.size).toBe(2);
  });
});

describe('getSensitiveFields', () => {
  test('returns undefined for a class with no decorated properties', () => {
    class Plain {
      name = '';
    }

    expect(getSensitiveFields(Plain)).toBeUndefined();
  });

  test.each([
    ['undefined', undefined],
    ['null', null],
    ['a string', 'LoginDto'],
    ['a plain object', {}],
    ['a number', 7],
  ])('returns undefined for %s', (_label, input) => {
    expect(getSensitiveFields(input)).toBeUndefined();
  });

  test('ignores metadata that is not a Map', () => {
    class Tampered {}

    Reflect.defineMetadata('platform-sec:sensitive-fields', { email: 'credential' }, Tampered);

    expect(getSensitiveFields(Tampered)).toBeUndefined();
  });
});

describe('@WithRevealContext', () => {
  test('attaches a static context to a handler', () => {
    class Controller {
      @WithRevealContext({ name: 'user-authentication' })
      login(this: void): void {}
    }

    expect(Reflect.getMetadata(REVEAL_CONTEXT_KEY, Controller.prototype.login)).toEqual({
      name: 'user-authentication',
    });
  });

  test('attaches a factory to a handler', () => {
    const factory = () => ({ name: 'refund-processing' });

    class Controller {
      @WithRevealContext(factory)
      refund(this: void): void {}
    }

    expect(Reflect.getMetadata(REVEAL_CONTEXT_KEY, Controller.prototype.refund)).toBe(factory);
  });

  test('attaches a context to a whole controller class', () => {
    @WithRevealContext({ name: 'payments' })
    class PaymentController {}

    expect(Reflect.getMetadata(REVEAL_CONTEXT_KEY, PaymentController)).toEqual({
      name: 'payments',
    });
  });
});

describe('request part extraction', () => {
  function contextFor(request: unknown): ExecutionContext {
    return {
      switchToHttp: () => ({ getRequest: () => request }),
    } as unknown as ExecutionContext;
  }

  const spec = { name: 'x-api-key', klass: 'credential', label: undefined } as const;

  test('reads a header case-insensitively', () => {
    const value = extractSensitive(contextFor({ headers: { 'x-api-key': 'k-1' } }), 'headers', {
      ...spec,
      name: 'X-API-Key',
    });

    expect(value?.reveal()).toBe('k-1');
    expect(value?.label).toBe('X-API-Key');
  });

  test('does not lowercase a query or route parameter name', () => {
    expect(
      extractSensitive(contextFor({ query: { apiKey: 'k-1' } }), 'query', {
        ...spec,
        name: 'apiKey',
      })?.reveal()
    ).toBe('k-1');
  });

  test.each([
    ['the request is not an object', 'no-request'],
    ['the request is null', null],
    ['the request is undefined', undefined],
  ])('fails closed when %s', (_name, request) => {
    expect(extractSensitive(contextFor(request), 'headers', spec)).toBeNull();
  });

  test.each([
    ['the container is missing', {}],
    ['the container is not an object', { headers: 'nonsense' }],
    ['the container is null', { headers: null }],
  ])('fails closed when %s', (_name, request) => {
    expect(extractSensitive(contextFor(request), 'headers', spec)).toBeNull();
  });

  test('fails closed when the value is not a string', () => {
    expect(
      extractSensitive(contextFor({ headers: { 'x-api-key': 7 } }), 'headers', spec)
    ).toBeNull();
  });

  test('fails closed when a repeated value has a non-string first element', () => {
    expect(
      extractSensitive(contextFor({ headers: { 'x-api-key': [7, 'k-1'] } }), 'headers', spec)
    ).toBeNull();
  });
});
