import { describe, expect, it } from 'vitest';
import { SensitiveString } from '@platform-sec/sensitive-string-core';

import { ResponseDecodeError } from './errors.js';
import { assertDecoded, decodeJson, safeUrl, wrapResponseFields } from './response.js';

const CANARY = 'sk_live_abc123';
const site = {
  method: 'GET',
  url: 'https://api.example.com/keys',
  contentType: 'application/json',
};

describe('decodeJson', () => {
  it('parses valid JSON', () => {
    expect(decodeJson('{"a":1}', site)).toEqual({ a: 1 });
  });

  it('discloses nothing from a short body that JSON.parse would have quoted whole', () => {
    // Measured: `JSON.parse('sk_live_abc123')` says
    // `Unexpected token 's', "sk_live_abc123" is not valid JSON`, and got
    // appends the full request URL to that.
    try {
      decodeJson(CANARY, site);
      expect.unreachable();
    } catch (error) {
      const decode = error as ResponseDecodeError;

      expect(decode).toBeInstanceOf(ResponseDecodeError);
      expect(decode.message).not.toContain(CANARY);
      expect(JSON.stringify(decode)).not.toContain(CANARY);
      expect(decode.message).toContain('GET https://api.example.com/keys');
      expect(decode.message).toContain('application/json');
      expect(decode.byteLength).toBe(CANARY.length);
    }
  });

  it('chains no cause, so a reporter walking the chain finds no quoted body', () => {
    try {
      decodeJson(CANARY, site);
      expect.unreachable();
    } catch (error) {
      expect((error as Error).cause).toBeUndefined();
    }
  });

  it('reports byte length rather than character length', () => {
    try {
      decodeJson('é'.repeat(4), site);
      expect.unreachable();
    } catch (error) {
      expect((error as ResponseDecodeError).byteLength).toBe(8);
    }
  });
});

describe('assertDecoded', () => {
  it("rewrites axios's silent non-JSON fallback into a decode error", () => {
    expect(() => assertDecoded(CANARY, { token: 'credential' }, site)).toThrow(ResponseDecodeError);
  });

  it('stays quiet when the caller declared no response fields', () => {
    expect(() => assertDecoded(CANARY, undefined, site)).not.toThrow();
  });

  it('stays quiet for a body that did parse into an object', () => {
    expect(() => assertDecoded({ token: CANARY }, { token: 'credential' }, site)).not.toThrow();
  });
});

describe('wrapResponseFields', () => {
  it('wraps the configured paths and leaves the rest alone', () => {
    const body = wrapResponseFields(
      { token: CANARY, customer: { email: 'a@example.com', id: 7 } },
      { token: 'credential', 'customer.email': 'sensitive' }
    );

    expect(body.token).toBeInstanceOf(SensitiveString);
    expect(body.customer.email).toBeInstanceOf(SensitiveString);
    expect(body.customer.id).toBe(7);
    expect(JSON.stringify(body)).not.toContain(CANARY);
  });

  it('leaves a path that is absent from the body absent', () => {
    expect(wrapResponseFields({ a: 1 }, { 'b.c': 'credential' })).toEqual({ a: 1 });
  });

  it('returns a primitive body unchanged rather than failing', () => {
    expect(wrapResponseFields('plain', { a: 'credential' })).toBe('plain');
    expect(wrapResponseFields(null, { a: 'credential' })).toBeNull();
  });

  it('is a no-op with no configuration, so nothing is wrapped by surprise', () => {
    const body = { token: CANARY };

    expect(wrapResponseFields(body, undefined)).toBe(body);
  });
});

describe('safeUrl', () => {
  it('drops the query string, where a credential most often is', () => {
    expect(safeUrl('https://api.example.com/x?token=abc#f')).toBe('https://api.example.com/x');
  });

  it('degrades gracefully for something that is not a URL', () => {
    expect(safeUrl('/relative?token=abc')).toBe('/relative');
  });
});
