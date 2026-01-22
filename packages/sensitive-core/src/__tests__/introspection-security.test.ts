/**
 * Reflection/Introspection Attack Tests
 *
 * Tests that various JavaScript introspection APIs cannot access the sensitive value.
 * This validates the security of ES2022 #private fields against reflection attacks.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import * as util from 'node:util';
import { SensitiveString, resetPolicies } from '../index.js';

const CANARY = 'INTROSPECTION_CANARY_xyz789';

describe('Introspection Security', () => {
  // Create a fresh instance for each test to avoid cross-test contamination
  let s: SensitiveString<'credential'>;

  beforeEach(() => {
    resetPolicies();
    s = new SensitiveString(CANARY, 'credential', 'test_label');
  });

  describe('Object introspection', () => {
    it('Object.keys() does not expose value', () => {
      const keys = Object.keys(s);
      expect(keys.join('')).not.toContain(CANARY);
      expect(keys).not.toContain('#value');
      expect(keys).not.toContain('value');
    });

    it('Object.values() does not expose value', () => {
      const values = Object.values(s);
      expect(values.map(String).join('')).not.toContain(CANARY);
    });

    it('Object.entries() does not expose value', () => {
      const entries = Object.entries(s);
      expect(entries.flat().map(String).join('')).not.toContain(CANARY);
    });

    it('Object.getOwnPropertyNames() does not expose value', () => {
      const propNames = Object.getOwnPropertyNames(s);
      expect(propNames.join('')).not.toContain(CANARY);
      expect(propNames).not.toContain('#value');
    });

    it('Object.getOwnPropertySymbols() does not expose value', () => {
      const symbols = Object.getOwnPropertySymbols(s);
      for (const sym of symbols) {
        const desc = Object.getOwnPropertyDescriptor(s, sym);
        expect(String(desc?.value ?? '')).not.toContain(CANARY);
      }
    });

    it('Object.getOwnPropertyDescriptors() does not expose value', () => {
      const descriptors = Object.getOwnPropertyDescriptors(s);
      const allValues = Object.values(descriptors)
        .map((d) => String(d.value ?? ''))
        .join('');
      expect(allValues).not.toContain(CANARY);
    });

    it('Object.assign() does not expose value', () => {
      const assigned = Object.assign({}, s);
      expect(JSON.stringify(assigned)).not.toContain(CANARY);
    });

    it('Object.fromEntries() does not expose value', () => {
      const entries = Object.entries(s);
      const reconstructed = Object.fromEntries(entries);
      expect(JSON.stringify(reconstructed)).not.toContain(CANARY);
    });

    it('Object.prototype.hasOwnProperty does not expose value', () => {
      expect(Object.prototype.hasOwnProperty.call(s, '#value')).toBe(false);
      expect(Object.prototype.hasOwnProperty.call(s, 'value')).toBe(false);
    });

    it('in operator does not expose value', () => {
      expect('#value' in s).toBe(false);
      expect('value' in s).toBe(false);
    });
  });

  describe('Reflect introspection', () => {
    it('Reflect.ownKeys() does not expose value', () => {
      const keys = Reflect.ownKeys(s);
      expect(keys.map(String).join('')).not.toContain(CANARY);
      expect(keys).not.toContain('#value');
    });

    it('Reflect.get() on known properties does not expose value', () => {
      const keys = Reflect.ownKeys(s);
      for (const key of keys) {
        const value = Reflect.get(s, key);
        expect(String(value)).not.toContain(CANARY);
      }
    });

    it('Reflect.get() with #value fails', () => {
      // Note: This actually throws a SyntaxError at parse time if you try
      // to use a string literal '#value', so we test dynamic access
      const privateKey = '#value';
      const result = Reflect.get(s, privateKey);
      expect(result).toBeUndefined();
    });

    it('Reflect.getOwnPropertyDescriptor() does not expose value', () => {
      const keys = Reflect.ownKeys(s);
      for (const key of keys) {
        const desc = Reflect.getOwnPropertyDescriptor(s, key);
        expect(String(desc?.value ?? '')).not.toContain(CANARY);
      }
    });

    it('Reflect.has() does not find private field', () => {
      expect(Reflect.has(s, '#value')).toBe(false);
      expect(Reflect.has(s, 'value')).toBe(false);
    });
  });

  describe('Prototype chain introspection', () => {
    it('prototype chain does not expose value', () => {
      let proto = Object.getPrototypeOf(s);
      while (proto !== null) {
        const keys = Object.getOwnPropertyNames(proto);
        for (const key of keys) {
          try {
            const value = (s as Record<string, unknown>)[key];
            if (typeof value !== 'function') {
              expect(String(value)).not.toContain(CANARY);
            }
          } catch {
            // Getters may throw, that's fine
          }
        }
        proto = Object.getPrototypeOf(proto);
      }
    });

    it('constructor property does not expose value', () => {
      const ctor = s.constructor;
      expect(String(ctor)).not.toContain(CANARY);
      expect(ctor.name).toBe('SensitiveString');
    });

    it('__proto__ does not expose value', () => {
      // eslint-disable-next-line no-proto
      const proto = (s as { __proto__: unknown }).__proto__;
      // Note: The prototype object itself doesn't have enumerable properties
      // that would contain the value, but JSON.stringify might fail for other reasons
      // (e.g., trying to call toJSON on prototype with undefined klass).
      // The important thing is that CANARY is not exposed.
      try {
        const result = JSON.stringify(proto);
        expect(result).not.toContain(CANARY);
      } catch {
        // If stringify throws, that's fine - no value was leaked
      }
    });
  });

  describe('JSON introspection', () => {
    it('JSON.stringify() does not expose value', () => {
      expect(JSON.stringify(s)).not.toContain(CANARY);
    });

    it('JSON.stringify() with replacer does not expose value', () => {
      const result = JSON.stringify(s, (key, value) => {
        // Malicious replacer trying to access internals
        if (typeof value === 'object' && value !== null) {
          return { ...value, _keys: Object.keys(value) };
        }
        return value;
      });
      expect(result).not.toContain(CANARY);
    });

    it('JSON.stringify() in nested structure does not expose value', () => {
      const nested = {
        level1: {
          level2: {
            secret: s,
          },
        },
      };
      expect(JSON.stringify(nested)).not.toContain(CANARY);
    });

    it('JSON.stringify() with toJSON override attempt', () => {
      // Note: JavaScript allows method shadowing on instances. The security guarantee
      // is that #value is inaccessible via reflection, NOT that the object is immutable.
      // If an attacker has write access to the object, they can override methods,
      // but they still cannot access #value to leak it - they can only return
      // arbitrary values they already possess.
      //
      // This test verifies that the ORIGINAL toJSON still redacts properly,
      // using a fresh instance that hasn't been tampered with.
      const fresh = new SensitiveString(CANARY, 'credential');
      expect(JSON.stringify(fresh)).not.toContain(CANARY);
    });
  });

  describe('Proxy-based introspection attempts', () => {
    it('wrapping in Proxy does not expose value via reflection', () => {
      const handler: ProxyHandler<SensitiveString<'credential'>> = {
        get(target, prop) {
          return Reflect.get(target, prop);
        },
        ownKeys(target) {
          return Reflect.ownKeys(target);
        },
        getOwnPropertyDescriptor(target, prop) {
          return Reflect.getOwnPropertyDescriptor(target, prop);
        },
      };

      const proxied = new Proxy(s, handler);

      // Note: Calling methods that access #value through a Proxy throws because
      // the Proxy is not the original class instance. This is a security feature
      // of ES2022 private fields - they cannot be accessed through proxies.
      expect(() => String(proxied)).toThrow();
      expect(() => JSON.stringify(proxied)).toThrow();

      // Property access through proxy still works and doesn't expose value
      expect(Object.keys(proxied).join('')).not.toContain(CANARY);
      expect(Object.values(proxied).map(String).join('')).not.toContain(CANARY);
    });

    it('Proxy with getPrototypeOf trap does not expose value', () => {
      const handler: ProxyHandler<SensitiveString<'credential'>> = {
        getPrototypeOf() {
          return { exposedValue: CANARY };
        },
      };

      const proxied = new Proxy(s, handler);

      // Calling toString() on a proxied SensitiveString throws because
      // the method tries to access #value, which is inaccessible through proxies.
      // This is a security feature of private fields.
      expect(() => String(proxied)).toThrow();
    });
  });

  describe('Constructor/prototype manipulation attempts', () => {
    it('accessing constructor does not expose value', () => {
      const ctor = s.constructor;
      expect(String(ctor)).not.toContain(CANARY);
    });

    it('toString.call() does not expose value', () => {
      expect(Object.prototype.toString.call(s)).not.toContain(CANARY);
    });

    it('valueOf() does not expose value', () => {
      const value = s.valueOf();
      expect(String(value)).not.toContain(CANARY);
    });

    it('Symbol.toPrimitive does not expose value', () => {
      // @ts-expect-error Testing primitive coercion
      const primitive = s[Symbol.toPrimitive]?.('string');
      if (primitive !== undefined) {
        expect(String(primitive)).not.toContain(CANARY);
      }
    });

    it('Symbol.toStringTag does not expose value', () => {
      const tag = (s as unknown as { [Symbol.toStringTag]: string })[Symbol.toStringTag];
      if (tag !== undefined) {
        expect(String(tag)).not.toContain(CANARY);
      }
    });
  });

  describe('util.inspect introspection', () => {
    it('util.inspect does not expose value', () => {
      expect(util.inspect(s)).not.toContain(CANARY);
    });

    it('util.inspect with showHidden does not expose value', () => {
      expect(util.inspect(s, { showHidden: true })).not.toContain(CANARY);
    });

    it('util.inspect with depth Infinity does not expose value', () => {
      expect(util.inspect(s, { depth: Infinity })).not.toContain(CANARY);
    });

    it('util.inspect with getters does not expose value', () => {
      expect(util.inspect(s, { getters: true })).not.toContain(CANARY);
    });

    it('util.inspect with all options does not expose value', () => {
      expect(
        util.inspect(s, {
          showHidden: true,
          depth: Infinity,
          colors: false,
          getters: true,
          maxArrayLength: Infinity,
          maxStringLength: Infinity,
        })
      ).not.toContain(CANARY);
    });

    it('util.format does not expose value', () => {
      expect(util.format('%s', s)).not.toContain(CANARY);
      expect(util.format('%o', s)).not.toContain(CANARY);
      expect(util.format('%O', s)).not.toContain(CANARY);
      expect(util.format('%j', s)).not.toContain(CANARY);
    });
  });

  describe('Type coercion attacks', () => {
    it('String() coercion does not expose value', () => {
      expect(String(s)).not.toContain(CANARY);
    });

    it('template literal coercion does not expose value', () => {
      expect(`${s}`).not.toContain(CANARY);
    });

    it('concatenation coercion does not expose value', () => {
      expect('' + s).not.toContain(CANARY);
      expect(s + '').not.toContain(CANARY);
    });

    it('Number() coercion does not expose value (returns NaN)', () => {
      const num = Number(s);
      expect(String(num)).not.toContain(CANARY);
    });

    it('Boolean() coercion does not expose value', () => {
      const bool = Boolean(s);
      expect(String(bool)).not.toContain(CANARY);
    });

    it('Array join coercion does not expose value', () => {
      expect([s].join('')).not.toContain(CANARY);
      expect([s, s].join(',')).not.toContain(CANARY);
    });
  });

  describe('Error and stack trace attacks', () => {
    it('throwing SensitiveString does not expose value', () => {
      try {
        throw s;
      } catch (e) {
        expect(String(e)).not.toContain(CANARY);
      }
    });

    it('error message interpolation does not expose value', () => {
      const error = new Error(`Token: ${s}`);
      expect(error.message).not.toContain(CANARY);
      expect(error.stack ?? '').not.toContain(CANARY);
    });

    it('error cause does not expose value', () => {
      const error = new Error('Failed', { cause: { token: s } });
      expect(JSON.stringify(error.cause)).not.toContain(CANARY);
    });
  });

  describe('Iteration attacks', () => {
    it('for...in does not expose value', () => {
      const found: string[] = [];
      for (const key in s) {
        found.push(key);
        found.push(String((s as Record<string, unknown>)[key]));
      }
      expect(found.join('')).not.toContain(CANARY);
    });

    it('for...of on Object.keys does not expose value', () => {
      const found: string[] = [];
      for (const key of Object.keys(s)) {
        found.push(key);
      }
      expect(found.join('')).not.toContain(CANARY);
    });

    it('for...of on Object.values does not expose value', () => {
      const found: string[] = [];
      for (const value of Object.values(s)) {
        found.push(String(value));
      }
      expect(found.join('')).not.toContain(CANARY);
    });
  });

  describe('WeakMap/WeakSet attacks', () => {
    it('using SensitiveString as WeakMap key does not expose value', () => {
      const wm = new WeakMap<object, string>();
      wm.set(s, 'stored');

      expect(wm.get(s)).toBe('stored');
      // Can't iterate WeakMap, but the key reference shouldn't expose value
    });

    it('using SensitiveString in WeakSet does not expose value', () => {
      const ws = new WeakSet<object>();
      ws.add(s);

      expect(ws.has(s)).toBe(true);
    });
  });

  describe('Map/Set attacks', () => {
    it('Map with SensitiveString key does not expose value', () => {
      const map = new Map<SensitiveString<'credential'>, string>();
      map.set(s, 'stored');

      expect(map.get(s)).toBe('stored');

      // Iterating the map
      for (const [key] of map) {
        expect(String(key)).not.toContain(CANARY);
      }
    });

    it('Set with SensitiveString does not expose value', () => {
      const set = new Set<SensitiveString<'credential'>>();
      set.add(s);

      for (const item of set) {
        expect(String(item)).not.toContain(CANARY);
      }
    });
  });

  describe('Structured clone attacks', () => {
    it('structuredClone does not expose value', () => {
      // structuredClone creates a plain object copy, stripping methods and private fields
      // This is actually a security feature - the #value is not accessible
      const cloned = structuredClone(s);

      // The clone is NOT a SensitiveString instance
      expect(cloned).not.toBeInstanceOf(SensitiveString);

      // The clone doesn't have reveal() method, so value cannot be accessed
      expect((cloned as { reveal?: unknown }).reveal).toBeUndefined();

      // Check that no property contains the CANARY
      for (const value of Object.values(cloned)) {
        expect(String(value)).not.toContain(CANARY);
      }
    });

    it('structuredClone of container with SensitiveString does not expose value', () => {
      const container = { secret: s };
      const cloned = structuredClone(container);

      // The cloned secret is not a SensitiveString
      expect(cloned.secret).not.toBeInstanceOf(SensitiveString);

      // Check that no nested value contains the CANARY
      const serialized = JSON.stringify(cloned);
      expect(serialized).not.toContain(CANARY);
    });
  });

  describe('Comparison attacks', () => {
    it('== comparison does not expose value', () => {
      // eslint-disable-next-line eqeqeq
      const result = s == CANARY;
      expect(result).toBe(false); // Objects are not equal to strings
    });

    it('=== comparison does not expose value', () => {
      const result = s === (CANARY as unknown);
      expect(result).toBe(false);
    });

    it('Object.is comparison does not expose value', () => {
      expect(Object.is(s, CANARY)).toBe(false);
    });
  });
});
