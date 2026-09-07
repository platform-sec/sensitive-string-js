import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { describe, expect, it } from 'vitest';

import { describeValue } from './describe.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

describe('describeValue', () => {
  it.each([
    ['null', null, 'null'],
    ['an array', [1], 'an array'],
    ['a plain object', {}, 'a plain object'],
    ['a null-prototype object', Object.create(null) as object, 'a plain object'],
    ['a number', 42, 'a number'],
    ['a boolean', true, 'a boolean'],
    ['a string', 'x', 'a string'],
    ['undefined', undefined, 'an undefined'],
    ['a Date', new Date(), 'a Date'],
    ['a Uint8Array', new Uint8Array(), 'an Uint8Array'],
  ])('describes %s', (_label, value, expected) => {
    expect(describeValue(value)).toBe(expected);
  });

  it('names a class without reading its contents', () => {
    class PaymentToken {
      constructor(readonly secret: string) {}
    }

    expect(describeValue(new PaymentToken(CANARY))).toBe('a PaymentToken');
  });

  it('never reports the value', () => {
    expect(describeValue(CANARY)).not.toContain(CANARY);
    expect(describeValue({ secret: CANARY })).not.toContain(CANARY);
    expect(describeValue(new SensitiveString(CANARY, 'credential'))).toBe('a SensitiveString');
  });

  // This runs on the way to throwing, so an object that refuses to describe
  // itself must not replace the refusal that names the real problem.
  it('survives a revoked Proxy, which throws from Array.isArray', () => {
    const { proxy, revoke } = Proxy.revocable({}, {});
    revoke();

    expect(describeValue(proxy)).toBe('an object');
  });

  it('survives an object that throws from getPrototypeOf', () => {
    const hostile = new Proxy(
      {},
      {
        getPrototypeOf() {
          throw new Error('no');
        },
      }
    );

    expect(describeValue(hostile)).toBe('an object');
  });

  it('survives an object that throws from a property read', () => {
    const hostile = new Proxy(Object.create({ marker: true }) as object, {
      get() {
        throw new Error('no');
      },
    });

    expect(describeValue(hostile)).toBe('an object');
  });

  it('survives a constructor with no usable name', () => {
    const anonymous = Object.create({ constructor: { name: 42 } }) as object;

    expect(describeValue(anonymous)).toBe('an object');
  });
});
