import { describe, expect, it } from 'vitest';
import { SensitiveString } from '../index.js';

const CANARY = 'LEAKED_SECRET_ctor_7f3a';

/**
 * The constructor used to accept any value. A number redacted like a string
 * and then threw inside `equals()`; an instance wrapped a second time
 * revealed the inner instance rather than the value. Both are wrong values
 * that surface far from their cause, so construction refuses them.
 */
describe('SensitiveString constructor input', () => {
  it.each([
    ['a number', 1234],
    ['a boolean', true],
    ['null', null],
    ['undefined', undefined],
    ['an array', [CANARY]],
    ['an object', { value: CANARY }],
    ['a function', () => CANARY],
    ['a bigint', 10n],
  ])('rejects %s with a TypeError', (_name, value) => {
    expect(() => new SensitiveString(value as unknown as string, 'credential')).toThrow(TypeError);
  });

  it('rejects a symbol with a TypeError', () => {
    expect(() => new SensitiveString(Symbol('s') as unknown as string, 'credential')).toThrow(
      TypeError
    );
  });

  it('rejects an existing SensitiveString rather than nesting it', () => {
    const inner = new SensitiveString(CANARY, 'credential', 'token');

    expect(() => new SensitiveString(inner as unknown as string, 'credential')).toThrow(
      /received a SensitiveString/
    );
  });

  it('names the kind of value, never its content', () => {
    const rejected: unknown[] = [{ value: CANARY }, [CANARY], () => CANARY];

    for (const value of rejected) {
      let message = '';

      try {
        new SensitiveString(value as string, 'sensitive');
      } catch (error) {
        message = (error as Error).message;
      }

      expect(message).toMatch(/received (an object|an array|a function)/);
      expect(message).not.toContain(CANARY);
    }
  });

  it('rejects a non-string result from map(), which builds a derived value', () => {
    const secret = new SensitiveString(CANARY, 'sensitive');

    expect(() => secret.map(() => 42 as unknown as string)).toThrow(TypeError);
  });

  it('still accepts the empty string', () => {
    expect(new SensitiveString('', 'sensitive').isEmpty()).toBe(true);
  });

  it('leaves fromOptional() and deserialize() as they were', () => {
    expect(SensitiveString.fromOptional(null, 'sensitive')).toBeNull();
    expect(SensitiveString.fromOptional('', 'sensitive')).toBeNull();
    expect(SensitiveString.fromOptional('x', 'sensitive')).toBeInstanceOf(SensitiveString);
    expect(() =>
      SensitiveString.deserialize({ __sensitive: true, klass: 'sensitive', value: 42 })
    ).toThrow(/value must be a string/);
  });
});
