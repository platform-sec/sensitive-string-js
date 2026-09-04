import { describe, it, expect } from 'vitest';

import { asObject, decodeBase64, decodeBase64Map, guardDecode, parsePayload } from './decode.js';
import { SecretPayloadError } from './errors.js';
import type { ResolvedSecretRef } from './types.js';

const REF: ResolvedSecretRef = { path: 'prod/db', version: '7', metadata: {} };

/** Exactly 20 characters, the length V8 echoes whole. */
const SHORT_CANARY = 'LEAKED_SECRET_abc123';
/** Longer than 20 characters, so V8 discloses the first ten. */
const LONG_CANARY = 'LEAKED_SECRET_abc123xyz_and_more';

describe('parsePayload', () => {
  it('parses a JSON object', () => {
    expect(parsePayload('{"a":1}', REF)).toEqual({ a: 1 });
  });

  describe('the V8 behaviour this guard exists for', () => {
    it('puts a 20-character input whole into the SyntaxError message', () => {
      expect(SHORT_CANARY).toHaveLength(20);

      let message = '';

      try {
        JSON.parse(SHORT_CANARY);
      } catch (error) {
        message = (error as Error).message;
      }

      // Pinned rather than assumed. If a future Node stops leaking here, this
      // fails and the design document's measurement table is out of date.
      expect(message).toContain(SHORT_CANARY);
    });

    it('puts the first ten characters of a longer input into the message', () => {
      let message = '';

      try {
        JSON.parse(LONG_CANARY);
      } catch (error) {
        message = (error as Error).message;
      }

      expect(message).toContain(LONG_CANARY.slice(0, 10));
      expect(message).not.toContain(LONG_CANARY);
    });

    it('reports only a position for a truncated JSON document, which is the safe case', () => {
      let message = '';

      try {
        JSON.parse(`{"password":"${SHORT_CANARY}"`);
      } catch (error) {
        message = (error as Error).message;
      }

      expect(message).not.toContain(SHORT_CANARY);
    });
  });

  it('does not disclose a 20-character payload that is not JSON', () => {
    let thrown: unknown;

    try {
      parsePayload(SHORT_CANARY, REF);
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(SecretPayloadError);
    expect((thrown as Error).message).not.toContain(SHORT_CANARY);
    expect((thrown as Error).message).toContain("Secret 'prod/db' version '7'");
  });

  it('does not disclose a longer payload that is not JSON', () => {
    try {
      parsePayload(LONG_CANARY, REF);
      expect.unreachable('parsePayload should have thrown');
    } catch (error) {
      expect((error as Error).message).not.toContain(LONG_CANARY.slice(0, 10));
    }
  });

  it('leaves cause unset, so no reporter can walk back to the SyntaxError', () => {
    try {
      parsePayload(SHORT_CANARY, REF);
      expect.unreachable('parsePayload should have thrown');
    } catch (error) {
      expect((error as { cause?: unknown }).cause).toBeUndefined();
    }
  });

  it('names the surface that reads a bare string', () => {
    expect(() => parsePayload('not json', REF)).toThrow(/Use get\(\)/);
  });

  it('rejects a JSON array', () => {
    expect(() => parsePayload('[1,2]', REF)).toThrow(/is not a JSON object/);
  });

  it('rejects JSON null', () => {
    expect(() => parsePayload('null', REF)).toThrow(/is not a JSON object/);
  });

  it('rejects a bare JSON string', () => {
    expect(() => parsePayload('"just-a-string"', REF)).toThrow(/is not a JSON object/);
  });
});

describe('asObject', () => {
  it('accepts an object', () => {
    expect(asObject({ a: 1 }, REF)).toEqual({ a: 1 });
  });

  it('rejects an array', () => {
    expect(() => asObject([1], REF)).toThrow(SecretPayloadError);
  });
});

describe('decodeBase64', () => {
  it('decodes valid base64', () => {
    expect(decodeBase64(Buffer.from(SHORT_CANARY).toString('base64'), REF)).toBe(SHORT_CANARY);
  });

  it('rejects a value outside the alphabet rather than skipping characters', () => {
    // Buffer.from is lenient enough to produce garbage from this.
    expect(() => decodeBase64('not base64!!', REF)).toThrow(/is not valid base64/);
  });

  it('accepts an unpadded value, since both forms decode to the same bytes', () => {
    expect(decodeBase64('QQ', REF)).toBe('A');
  });

  it('rejects a tail of one character, which no group of six-bit units produces', () => {
    expect(() => decodeBase64('QUJDR', REF)).toThrow(/is not valid base64/);
  });

  it('rejects a value that does not survive a re-encode', () => {
    // `Qh==` sits in the alphabet and decodes to the same byte as `Qg==`,
    // because the trailing bits are dropped. Buffer.from is happy to do that
    // silently; the round trip is what notices.
    expect(() => decodeBase64('Qh==', REF)).toThrow(/did not survive a base64 round trip/);
  });

  it('names the field without naming the content', () => {
    try {
      decodeBase64(`${SHORT_CANARY}!!`, REF, 'password');
      expect.unreachable('decodeBase64 should have thrown');
    } catch (error) {
      expect((error as Error).message).toContain("field 'password'");
      expect((error as Error).message).not.toContain(SHORT_CANARY);
    }
  });
});

describe('decodeBase64Map', () => {
  it('decodes every value', () => {
    const encoded = {
      username: Buffer.from('app').toString('base64'),
      password: Buffer.from(SHORT_CANARY).toString('base64'),
    };

    expect(decodeBase64Map(encoded, REF)).toEqual({ username: 'app', password: SHORT_CANARY });
  });

  it('rejects a non-string value', () => {
    expect(() => decodeBase64Map({ a: 5 }, REF)).toThrow(/field 'a' is not a string/);
  });
});

describe('guardDecode', () => {
  it('returns what the decoder produced', () => {
    expect(guardDecode(() => 42, REF, 'YAML')).toBe(42);
  });

  it('replaces a decoder error that carries content', () => {
    try {
      guardDecode(
        () => {
          throw new Error(`bad token near ${SHORT_CANARY} on line 3`);
        },
        REF,
        'YAML'
      );
      expect.unreachable('guardDecode should have thrown');
    } catch (error) {
      expect((error as Error).message).not.toContain(SHORT_CANARY);
      expect((error as Error).message).toContain('could not be decoded as YAML');
      expect((error as { cause?: unknown }).cause).toBeUndefined();
    }
  });
});
