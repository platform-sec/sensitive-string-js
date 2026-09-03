import { beforeEach, describe, expect, it } from 'vitest';
import { SensitiveString, resetPolicies } from '@platform-sec/sensitive-string-core';
import { collectFragments, findRawValue, joinFragments } from './leak-scan.js';

const CANARY = 'LEAK_SCAN_CANARY_4c1f';

describe('leak scanning', () => {
  beforeEach(() => {
    resetPolicies();
  });

  describe('what it reaches', () => {
    it('finds a value at the top level', () => {
      expect(findRawValue(CANARY, CANARY)).toEqual({
        path: '',
        context: '[LEAKED VALUE]',
      });
    });

    it('finds a value nested in objects and arrays', () => {
      const target = { body: { items: [{ token: `Bearer ${CANARY}` }] } };

      expect(findRawValue(target, CANARY)?.path).toBe('.body.items[0].token');
    });

    it('quotes a property name that is not an identifier', () => {
      const target = { headers: { 'x-api-key': CANARY } };

      expect(findRawValue(target, CANARY)?.path).toBe('.headers["x-api-key"]');
    });

    it('finds a value used as an object key', () => {
      const cache = { [CANARY]: 'cached response' };

      expect(findRawValue(cache, CANARY)?.path).toBe(`.${CANARY} (key)`);
    });

    it('quotes a leaking key that is not an identifier', () => {
      const cache = { [`bearer ${CANARY}`]: 'cached response' };

      expect(findRawValue(cache, CANARY)?.path).toBe(`["bearer ${CANARY}"] (key)`);
    });

    it('finds a value in a property attached to an array', () => {
      const matches = `prefix ${CANARY} suffix`.match(/prefix/);

      // The match itself is harmless; `input` is the whole subject string.
      expect(matches?.[0]).toBe('prefix');
      expect(findRawValue(matches, CANARY)?.path).toBe('.input');
    });

    it('finds a value in a Map key and a Map value', () => {
      expect(findRawValue(new Map([['token', CANARY]]), CANARY)?.path).toBe('<map value 0>');
      expect(findRawValue(new Map([[CANARY, 'x']]), CANARY)?.path).toBe('<map key 0>');
    });

    it('finds a value in a Set', () => {
      expect(findRawValue(new Set(['a', CANARY]), CANARY)?.path).toBe('<set 1>');
    });

    it('finds a value in an Error message, which is not enumerable', () => {
      const error = new Error(`auth failed for ${CANARY}`);

      // JSON.stringify renders an Error as {}, and Object.keys reports nothing.
      expect(Object.keys(error)).toHaveLength(0);
      expect(JSON.stringify(error)).toBe('{}');

      // The stack embeds the message, so whichever own property comes first is
      // the one reported. Both are places the value should never have reached.
      expect(findRawValue(error, CANARY)?.path).toMatch(/^\.(stack|message)$/);
    });

    it('finds a value on an Error cause', () => {
      const error = new Error('auth failed', { cause: { token: CANARY } });

      expect(findRawValue(error, CANARY)?.path).toBe('.cause.token');
    });

    it('finds a value behind a non-enumerable property', () => {
      const response = {};
      Object.defineProperty(response, 'raw', { value: CANARY, enumerable: false });

      expect(JSON.stringify(response)).toBe('{}');
      expect(findRawValue(response, CANARY)?.path).toBe('.raw');
    });

    it('finds a value behind a getter', () => {
      const config = {
        get token() {
          return CANARY;
        },
      };

      expect(findRawValue(config, CANARY)?.path).toBe('.token');
    });

    it('finds a value in a Buffer', () => {
      expect(findRawValue({ body: Buffer.from(CANARY, 'utf8') }, CANARY)?.path).toBe('.body');
    });

    it('finds a value in a typed array view over a larger buffer', () => {
      const buffer = Buffer.alloc(64);
      buffer.write(CANARY, 8, 'utf8');
      const view = new Uint8Array(buffer.buffer, buffer.byteOffset + 8, CANARY.length);

      expect(findRawValue(view, CANARY)).toBeDefined();
    });

    it('finds a value in a bare ArrayBuffer', () => {
      const bytes = Buffer.from(CANARY, 'utf8');
      const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);

      expect(findRawValue(buffer, CANARY)).toBeDefined();
    });

    it('finds a value in a RegExp source', () => {
      expect(findRawValue(new RegExp(CANARY), CANARY)?.path).toBe('.source');
    });

    it('finds a value on a class instance', () => {
      class Session {
        constructor(readonly token: string) {}
      }

      expect(findRawValue(new Session(CANARY), CANARY)?.path).toBe('.token');
    });

    it('finds a value on a null-prototype object', () => {
      const bag = Object.create(null) as Record<string, string>;
      bag['token'] = CANARY;

      expect(findRawValue(bag, CANARY)?.path).toBe('.token');
    });
  });

  describe('what it deliberately does not treat as a leak', () => {
    it('does not report a value that is still wrapped', () => {
      const secret = new SensitiveString(CANARY, 'credential', 'api_key');

      expect(findRawValue({ token: secret }, CANARY)).toBeUndefined();
    });

    it('records the redacted rendering of a wrapped value so a redaction check can find it', () => {
      const secret = new SensitiveString(CANARY, 'credential', 'api_key');

      expect(joinFragments(collectFragments({ token: secret }))).toContain('[REDACTED:credential]');
    });

    it('never reports an empty value, which every string contains', () => {
      expect(findRawValue({ anything: 'at all' }, '')).toBeUndefined();
    });

    it('does not report a value found only in a function body', () => {
      const target = {
        handler: () => CANARY,
      };

      expect(findRawValue(target, CANARY)).toBeUndefined();
    });
  });

  describe('why it does not use JSON.stringify', () => {
    it('sees through a toJSON that hides the field holding a leaked copy', () => {
      class Response {
        readonly rawToken = CANARY;

        toJSON() {
          return { status: 'ok' };
        }
      }

      const response = new Response();

      expect(JSON.stringify(response)).not.toContain(CANARY);
      expect(findRawValue(response, CANARY)?.path).toBe('.rawToken');
    });

    it('sees a leaked copy sitting next to a correctly wrapped value', () => {
      const secret = new SensitiveString(CANARY, 'credential', 'api_key');
      const payload = { token: secret, debugCopy: CANARY };

      expect(findRawValue(payload, CANARY)?.path).toBe('.debugCopy');
    });
  });

  describe('robustness', () => {
    it('terminates on a cycle', () => {
      const target: Record<string, unknown> = { token: CANARY };
      target['self'] = target;

      expect(findRawValue(target, CANARY)?.path).toBe('.token');
    });

    it('finds a leak at a depth an ordinary structure can reach', () => {
      let deep: Record<string, unknown> = { token: CANARY };
      for (let i = 0; i < 40; i += 1) {
        deep = { nested: deep };
      }

      expect(findRawValue(deep, CANARY)).toBeDefined();
    });

    it('finds a leak far deeper than any recursion would survive', () => {
      let deep: Record<string, unknown> = { token: CANARY };
      for (let i = 0; i < 20_000; i += 1) {
        deep = { nested: deep };
      }

      // The walk uses an explicit stack. A depth limit here would report a real
      // leak as no leak, which is the one answer this must never give wrongly.
      expect(findRawValue(deep, CANARY)?.path.endsWith('.token')).toBe(true);
    });

    it('gives up on a target that fabricates work without end', () => {
      const endless: object = new Proxy(
        {},
        {
          ownKeys: () => ['next'],
          getOwnPropertyDescriptor: () => ({
            configurable: true,
            enumerable: true,
            value: new Proxy({}, {}),
          }),
        }
      );

      expect(() => findRawValue(endless, CANARY)).not.toThrow();
    });

    it('skips a property that has only a setter', () => {
      const target = {
        set token(_value: string) {
          // Nothing to read here.
        },
        other: CANARY,
      };

      expect(findRawValue(target, CANARY)?.path).toBe('.other');
    });

    it('survives a view over a detached buffer', () => {
      const buffer = new ArrayBuffer(32);
      const view = new Uint8Array(buffer);
      structuredClone(buffer, { transfer: [buffer] });

      expect(() => findRawValue({ body: view }, CANARY)).not.toThrow();
    });

    it('survives a getter that throws', () => {
      const target = {
        get broken(): string {
          throw new Error('nope');
        },
        token: CANARY,
      };

      expect(findRawValue(target, CANARY)?.path).toBe('.token');
    });

    it('survives a value with no prototype and a symbol key', () => {
      const target = { [Symbol('secret')]: CANARY };

      expect(findRawValue(target, CANARY)?.path).toBe('[Symbol(secret)]');
    });
  });

  describe('reported context', () => {
    it('replaces the value with a placeholder', () => {
      const location = findRawValue({ header: `Authorization: Bearer ${CANARY} (v2)` }, CANARY);

      expect(location?.context).toBe('Authorization: Bearer [LEAKED VALUE] (v2)');
      expect(location?.context).not.toContain(CANARY);
    });

    it('replaces every occurrence within the window', () => {
      const location = findRawValue(`${CANARY} and again ${CANARY}`, CANARY);

      expect(location?.context).not.toContain(CANARY);
      expect(location?.context.split('[LEAKED VALUE]')).toHaveLength(3);
    });

    it('truncates a long surrounding text with ellipses', () => {
      const padding = 'x'.repeat(500);
      const location = findRawValue(`${padding}${CANARY}${padding}`, CANARY);

      expect(location?.context.startsWith('...')).toBe(true);
      expect(location?.context.endsWith('...')).toBe(true);
      expect(location?.context.length).toBeLessThan(200);
    });
  });
});
