import { createHmac } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import {
  assertKeyedDerivationOptions,
  DEFAULT_DERIVED_TOKEN_LENGTH,
  deriveKeyedToken,
  MAX_DERIVED_TOKEN_LENGTH,
  MIN_DERIVATION_KEY_BYTES,
  MIN_DERIVED_TOKEN_LENGTH,
} from './derive.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';
const KEY = new Uint8Array(32).fill(7);

describe('deriveKeyedToken', () => {
  describe('the derivation', () => {
    it('is HMAC-SHA256 over the NUL-separated domain and the value, truncated', () => {
      // Written out longhand rather than asserted against a golden string, so
      // the test says what the construction is and would fail if the order of
      // the inputs changed.
      const hmac = createHmac('sha256', KEY);
      hmac.update('conv-1', 'utf8');
      hmac.update(new Uint8Array([0]));
      hmac.update('sensitive', 'utf8');
      hmac.update(new Uint8Array([0]));
      hmac.update(CANARY, 'utf8');

      expect(deriveKeyedToken(CANARY, { key: KEY, domain: ['conv-1', 'sensitive'] })).toBe(
        hmac.digest('hex').slice(0, DEFAULT_DERIVED_TOKEN_LENGTH)
      );
    });

    it('is stable for the same value, key and domain', () => {
      const a = deriveKeyedToken(CANARY, { key: KEY, domain: ['d'] });
      const b = deriveKeyedToken(CANARY, { key: KEY, domain: ['d'] });

      expect(a).toBe(b);
    });

    it.each([
      ['the value', 'other', { key: KEY, domain: ['d'] }],
      ['the key', CANARY, { key: new Uint8Array(32).fill(9), domain: ['d'] }],
      ['the domain', CANARY, { key: KEY, domain: ['e'] }],
      ['a domain component count', CANARY, { key: KEY, domain: ['d', ''] }],
    ])('changes with %s', (_label, value, options) => {
      expect(deriveKeyedToken(value, options)).not.toBe(
        deriveKeyedToken(CANARY, { key: KEY, domain: ['d'] })
      );
    });

    /**
     * The separator is what stops two domains sharing a token space. With an
     * ordinary joining character these two would hash identically, and a
     * caller could pick a scope that impersonated the segment after it.
     */
    it('separates domain components so they cannot be reassociated', () => {
      expect(deriveKeyedToken(CANARY, { key: KEY, domain: ['a', 'bc'] })).not.toBe(
        deriveKeyedToken(CANARY, { key: KEY, domain: ['ab', 'c'] })
      );
    });

    it('reveals nothing of the value it derived from', () => {
      const token = deriveKeyedToken(CANARY, { key: KEY });

      expect(token).not.toContain(CANARY);
      expect(token).toMatch(/^[0-9a-f]+$/);
    });

    it('reveals nothing of the key', () => {
      const token = deriveKeyedToken(CANARY, { key: 'a-key-of-at-least-sixteen-bytes' });

      expect(token).not.toContain('a-key');
    });
  });

  describe('bounds', () => {
    it('defaults to the floor, which is 12 hex characters', () => {
      expect(DEFAULT_DERIVED_TOKEN_LENGTH).toBe(MIN_DERIVED_TOKEN_LENGTH);
      expect(deriveKeyedToken(CANARY, { key: KEY })).toHaveLength(12);
    });

    it.each([MIN_DERIVED_TOKEN_LENGTH, 16, MAX_DERIVED_TOKEN_LENGTH])(
      'honours a length of %i',
      (length) => {
        expect(deriveKeyedToken(CANARY, { key: KEY, length })).toHaveLength(length);
      }
    );

    /**
     * 8 hex characters is 32 bits, where a one-in-a-million collision arrives
     * at about 90 distinct values and a one-in-a-thousand one at about 3,000.
     * A collision merges two subjects into one, so this floor is a correctness
     * guard as much as a security one and there is no way to opt out of it.
     */
    it.each([0, 8, 11, 65, 1.5, Number.NaN])('refuses a length of %s', (length) => {
      expect(() => deriveKeyedToken(CANARY, { key: KEY, length })).toThrow(RangeError);
    });

    it('refuses a key below the entropy floor', () => {
      const short = new Uint8Array(MIN_DERIVATION_KEY_BYTES - 1);

      expect(() => deriveKeyedToken(CANARY, { key: short })).toThrow(RangeError);
      expect(() => deriveKeyedToken(CANARY, { key: 'short' })).toThrow(RangeError);
    });

    it('accepts a key exactly at the floor', () => {
      const exact = new Uint8Array(MIN_DERIVATION_KEY_BYTES).fill(1);

      expect(deriveKeyedToken(CANARY, { key: exact })).toHaveLength(12);
    });

    it('reads a string key and its byte equivalent identically', () => {
      const text = 'a-key-of-at-least-sixteen-bytes';

      expect(deriveKeyedToken(CANARY, { key: text })).toBe(
        deriveKeyedToken(CANARY, { key: new TextEncoder().encode(text) })
      );
    });
  });

  describe('argument checking', () => {
    it('refuses a missing or wrongly typed key, so there is no unkeyed mode', () => {
      expect(() => deriveKeyedToken(CANARY, { key: undefined as unknown as Uint8Array })).toThrow(
        TypeError
      );
      expect(() => deriveKeyedToken(CANARY, { key: 42 as unknown as Uint8Array })).toThrow(
        TypeError
      );
    });

    it('refuses a non-string value', () => {
      expect(() => deriveKeyedToken(42 as unknown as string, { key: KEY })).toThrow(TypeError);
    });

    it('refuses a non-string domain component', () => {
      expect(() =>
        deriveKeyedToken(CANARY, { key: KEY, domain: [1 as unknown as string] })
      ).toThrow(TypeError);
    });

    it('refuses a domain component carrying the separator', () => {
      expect(() =>
        deriveKeyedToken(CANARY, { key: KEY, domain: [`a${String.fromCharCode(0)}b`] })
      ).toThrow(TypeError);
    });
  });

  describe('assertKeyedDerivationOptions', () => {
    /**
     * For a caller who has to read a protected value to derive from it. Every
     * refusal the derivation can raise is raised here instead, so the caller
     * settles a typo before the read rather than after it and an audit sink
     * does not record a reveal that produced nothing.
     */
    it('accepts exactly what the derivation accepts', () => {
      expect(() =>
        assertKeyedDerivationOptions({ key: KEY, domain: ['a', 'b'], length: 16 })
      ).not.toThrow();
      expect(() => assertKeyedDerivationOptions({ key: KEY })).not.toThrow();
    });

    it.each([
      ['a short key', { key: 'short' }],
      ['a wrongly typed key', { key: 42 as unknown as Uint8Array }],
      ['a length below the floor', { key: KEY, length: 8 }],
      ['a length above the ceiling', { key: KEY, length: 65 }],
      ['a fractional length', { key: KEY, length: 12.5 }],
      ['a non-string domain component', { key: KEY, domain: [1 as unknown as string] }],
      [
        'a domain component carrying the separator',
        {
          key: KEY,
          domain: [`a${String.fromCharCode(0)}b`],
        },
      ],
    ])('refuses %s', (_label, options) => {
      expect(() => assertKeyedDerivationOptions(options)).toThrow();
    });

    it('agrees with the derivation on every case, so neither can drift', () => {
      const cases = [
        { key: KEY },
        { key: KEY, length: 16 },
        { key: 'short' },
        { key: KEY, length: 8 },
        { key: KEY, domain: [`a${String.fromCharCode(0)}b`] },
      ];

      for (const options of cases) {
        const assertThrew = threw(() => assertKeyedDerivationOptions(options));
        const deriveThrew = threw(() => deriveKeyedToken(CANARY, options));

        expect(assertThrew, JSON.stringify(options)).toBe(deriveThrew);
      }
    });

    it('derives nothing, so it cannot itself be a disclosure path', () => {
      // It takes no value at all, which is the property that matters: there is
      // no argument for it to leak.
      expect(assertKeyedDerivationOptions({ key: KEY })).toBeUndefined();
    });
  });
});

function threw(fn: () => unknown): boolean {
  try {
    fn();
    return false;
  } catch {
    return true;
  }
}
