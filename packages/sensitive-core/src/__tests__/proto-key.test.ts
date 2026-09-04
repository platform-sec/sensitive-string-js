/**
 * A `__proto__` key in caller data stays a key in every copy a walk makes.
 *
 * `JSON.parse` produces an own property named `__proto__` for that key, inert
 * on the parsed object. A copy that assigned it, `target[key] = value`, hit
 * the accessor on `Object.prototype` instead and made the attacker's object
 * the copy's prototype: `wrapSensitiveByPath` on a webhook body answered
 * `wrapped.isAdmin === true` where the body answered `undefined`, a shadowed
 * `hasOwnProperty` turned the next call into a TypeError, `redactInStructure`
 * silently dropped that subtree from the log line, and `redactCopy` handed an
 * entity a prototype that was not its class. The path helpers already refused
 * the name; the copies did not.
 */

import { describe, expect, it } from 'vitest';
import {
  SensitiveString,
  redactCopy,
  redactInStructure,
  safeStringify,
  unwrapSensitiveByPath,
  wrapSensitiveByPath,
} from '../index.js';

const CANARY = 'PROTO_KEY_CANARY_7b3e1d';

/** What a JSON body with an injected key parses to: an own, inert `__proto__`. */
function hostileBody(token = 'tok_plain'): Record<string, unknown> {
  return JSON.parse(
    `{"__proto__":{"isAdmin":true,"hasOwnProperty":1},"token":"${token}"}`
  ) as Record<string, unknown>;
}

/** The injected subtree, read as the own property it is. */
function injectedSubtree(body: Record<string, unknown>): Record<string, unknown> {
  return body['__proto__'] as Record<string, unknown>;
}

describe('a __proto__ key in caller data', () => {
  it('is inert on the parsed input, which is the property every copy must keep', () => {
    const body = hostileBody();

    expect(Object.hasOwn(body, '__proto__')).toBe(true);
    expect(Object.getPrototypeOf(body)).toBe(Object.prototype);
    expect(body['isAdmin']).toBeUndefined();
  });

  describe('through wrapSensitiveByPath', () => {
    it('does not become the prototype of the wrapped object', () => {
      const wrapped = wrapSensitiveByPath(hostileBody(CANARY), { token: 'credential' });

      expect(Object.getPrototypeOf(wrapped)).toBe(Object.prototype);
      expect(wrapped['isAdmin']).toBeUndefined();
      expect('isAdmin' in wrapped).toBe(false);
      expect(Object.hasOwn(wrapped, '__proto__')).toBe(true);
      expect(wrapped['token']).toBeInstanceOf(SensitiveString);
    });

    it('leaves Object.prototype methods reachable on the wrapped object', () => {
      const wrapped = wrapSensitiveByPath(hostileBody(CANARY), {
        token: 'credential',
      }) as unknown as { hasOwnProperty(key: string): boolean };

      // The body tried to replace this method with `1`, which would make the
      // call a TypeError. Reaching Object.prototype is the assertion.
      // eslint-disable-next-line no-prototype-builtins -- the shadowed method is the point of the test
      expect(wrapped.hasOwnProperty('token')).toBe(true);
    });

    it('CANARY: the wrapped object still logs safely, with the key as a key', () => {
      const wrapped = wrapSensitiveByPath(hostileBody(CANARY), { token: 'credential' });
      const json = safeStringify(wrapped);

      expect(json).not.toContain(CANARY);
      const parsed = JSON.parse(json) as Record<string, unknown>;
      expect(Object.hasOwn(parsed, '__proto__')).toBe(true);
      expect(injectedSubtree(parsed)).toEqual({ isAdmin: true, hasOwnProperty: 1 });
      expect(parsed['token']).toBe('[REDACTED:credential]');
    });

    it('survives the round trip through unwrapSensitiveByPath', () => {
      const wrapped = wrapSensitiveByPath(hostileBody(CANARY), { token: 'credential' });
      const unwrapped = unwrapSensitiveByPath(wrapped, { token: 'credential' });

      expect(Object.getPrototypeOf(unwrapped)).toBe(Object.prototype);
      expect(unwrapped['isAdmin']).toBeUndefined();
      expect(Object.hasOwn(unwrapped, '__proto__')).toBe(true);
      expect(unwrapped['token']).toBe(CANARY);
    });

    it('never reaches the global Object.prototype', () => {
      wrapSensitiveByPath(hostileBody(CANARY), { token: 'credential' });

      expect(({} as Record<string, unknown>)['isAdmin']).toBeUndefined();
      expect(Object.hasOwn(Object.prototype, 'isAdmin')).toBe(false);
    });
  });

  describe('through redactInStructure', () => {
    it('keeps the subtree in the log line as the key it was, redacted', () => {
      const payload = hostileBody();
      injectedSubtree(payload)['secret'] = new SensitiveString(CANARY, 'credential');

      const redacted = redactInStructure(payload) as Record<string, unknown>;

      expect(Object.getPrototypeOf(redacted)).toBe(Object.prototype);
      expect(redacted['isAdmin']).toBeUndefined();
      expect(Object.hasOwn(redacted, '__proto__')).toBe(true);
      expect(injectedSubtree(redacted)['secret']).toBe('[REDACTED:credential]');
    });

    it('CANARY: safeStringify emits the key rather than dropping the subtree', () => {
      const payload = hostileBody();
      injectedSubtree(payload)['secret'] = new SensitiveString(CANARY, 'credential');

      const json = safeStringify(payload);

      expect(json).not.toContain(CANARY);
      const parsed = JSON.parse(json) as Record<string, unknown>;
      expect(Object.hasOwn(parsed, '__proto__')).toBe(true);
      expect(injectedSubtree(parsed)).toEqual({
        isAdmin: true,
        hasOwnProperty: 1,
        secret: '[REDACTED:credential]',
      });
      expect(parsed['token']).toBe('tok_plain');
    });
  });

  describe('through redactCopy', () => {
    it('keeps an entity on its own prototype', () => {
      class Entity {
        constructor(readonly apiKey: SensitiveString<'credential'>) {}
      }

      const entity = new Entity(new SensitiveString(CANARY, 'credential'));
      Object.defineProperty(entity, '__proto__', {
        value: { isAdmin: true },
        enumerable: true,
        writable: true,
        configurable: true,
      });

      const copy = redactCopy(entity) as Record<string, unknown>;

      expect(copy).toBeInstanceOf(Entity);
      expect(copy['isAdmin']).toBeUndefined();
      expect(copy['apiKey']).toBe('[REDACTED:credential]');
      expect(Object.hasOwn(copy, '__proto__')).toBe(true);
    });

    it('CANARY: keeps a parsed body on Object.prototype and redacts inside the subtree', () => {
      const payload = hostileBody();
      injectedSubtree(payload)['secret'] = new SensitiveString(CANARY, 'credential');

      const copy = redactCopy(payload) as Record<string, unknown>;

      expect(Object.getPrototypeOf(copy)).toBe(Object.prototype);
      expect(copy['isAdmin']).toBeUndefined();
      expect(injectedSubtree(copy)['secret']).toBe('[REDACTED:credential]');
      expect(JSON.stringify(copy)).not.toContain(CANARY);
    });
  });
});
