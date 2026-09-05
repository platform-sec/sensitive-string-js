import {
  ExpiredSensitiveValueError,
  resetPolicies,
  SensitiveString,
  withRevealContext,
} from '@platform-sec/sensitive-string-core';
import { beforeEach, describe, expect, it } from 'vitest';

import { createHandleMap, entityHandle } from './handle.js';
import { rehydrate } from './rehydrate.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';
const KEY = new Uint8Array(32).fill(7);

/** A value, its handle, and the map the request built. */
function mint(raw = CANARY, label?: string) {
  const map = createHandleMap();
  const value = new SensitiveString(raw, 'sensitive', label);
  const handle = entityHandle(value, { key: KEY, scope: 'conv-1', record: map });

  return { map, value, handle };
}

describe('rehydrate', () => {
  beforeEach(() => {
    resetPolicies();
  });

  describe('the substitution oracle', () => {
    it('resolves only handles the calling request minted', () => {
      const { map, handle } = mint();

      // A forged token, correctly shaped and never minted. Forging one costs
      // nothing: a handle is a syntactic pattern, and a model echoes verbatim
      // spans from documents some user uploaded.
      const forged = '<<E:deadbeef0123>>';
      const result = rehydrate(`mail ${handle} and ${forged} today`, { map });

      expect(result.resolved).toEqual([handle]);
      expect(result.unresolved).toEqual([forged]);
      // Left in place verbatim, not deleted and not replaced with a marker.
      expect(result.text.reveal({ name: 't' })).toContain(forged);
    });

    it('resolves nothing at all against a map from a different request', () => {
      const { handle } = mint();
      const other = createHandleMap();

      const result = rehydrate(`mail ${handle}`, { map: other });

      expect(result.resolved).toEqual([]);
      expect(result.unresolved).toEqual([handle]);
      expect(result.text.reveal({ name: 't' })).toBe(`mail ${handle}`);
    });

    it('returns a wrapped value rather than a raw string', () => {
      const { map, handle } = mint();
      const { text } = rehydrate(`mail ${handle}`, { map });

      expect(text).toBeInstanceOf(SensitiveString);
      expect(String(text)).toBe('[REDACTED:sensitive]');
      expect(JSON.stringify({ text })).not.toContain(CANARY);
    });

    it('wraps the result even when nothing resolved, so a caller has one type', () => {
      const map = createHandleMap();
      const { text } = rehydrate('nothing to substitute here', { map });

      expect(text).toBeInstanceOf(SensitiveString);
      expect(text.reveal({ name: 't' })).toBe('nothing to substitute here');
    });

    it('takes assembled text, not a chunk', () => {
      const { map } = mint();

      // The type signature is the enforcement for the streaming problem: a
      // handle can span two fragments, and anything matching per chunk misses
      // a split handle and matches once the caller buffers.
      expect(() => rehydrate(['a', 'b'] as unknown as string, { map })).toThrow(TypeError);
    });

    it('requires the map', () => {
      expect(() =>
        rehydrate('x', { map: {} as unknown as ReturnType<typeof createHandleMap> })
      ).toThrow(TypeError);
    });
  });

  describe('substitution mechanics', () => {
    /**
     * `String.prototype.replaceAll` with a string replacement interprets `$`
     * patterns in the replacement even when the pattern is a plain string, so
     * the obvious implementation corrupts a value containing `$$` and splices
     * surrounding prompt text into one containing `` $` `` or `$'`. Neither
     * throws. Substitution here is by splitting and reassembly through core's
     * template tag, which has no replacement string to interpret.
     */
    it.each([
      ['a dollar-ampersand', 'pa$&word'],
      ['a dollar-backtick', 'pa$`word'],
      ['a dollar-quote', "pa$'word"],
      ['a double dollar', 'pa$$word'],
      ['every one at once', "$&$`$'$$"],
    ])('substitutes %s verbatim', (_label, raw) => {
      const { map, handle } = mint(raw);

      const { text } = rehydrate(`before ${handle} after`, { map });

      expect(text.reveal({ name: 't' })).toBe(`before ${raw} after`);
    });

    it('substitutes several handles in one pass', () => {
      const map = createHandleMap();
      const first = entityHandle(new SensitiveString('alice@test', 'sensitive'), {
        key: KEY,
        record: map,
      });
      const second = entityHandle(new SensitiveString('bob@test', 'sensitive'), {
        key: KEY,
        record: map,
      });

      const { text, resolved } = rehydrate(`from ${first} to ${second}`, { map });

      expect(resolved).toEqual([first, second]);
      expect(text.reveal({ name: 't' })).toBe('from alice@test to bob@test');
    });

    it('substitutes a repeated handle every time it appears, reporting it once', () => {
      const { map, handle } = mint('alice@test');

      const { text, resolved } = rehydrate(`${handle} then ${handle}`, { map });

      expect(resolved).toEqual([handle]);
      expect(text.reveal({ name: 't' })).toBe('alice@test then alice@test');
    });
  });

  describe('the gate', () => {
    it('audits each substituted value', () => {
      const { map, handle } = mint();
      const audited: string[] = [];

      withRevealContext({ name: 'response', auditReveal: (v) => audited.push(v.klass) }, () =>
        rehydrate(`mail ${handle}`, { map })
      );

      // Two: the mint above happened outside this context, so the one here is
      // the substitution's own read.
      expect(audited).toEqual(['sensitive']);
    });

    /**
     * A map that outlives a value's lifetime hands back an instance that
     * refuses, which is correct and free. The alternative, a map of strings,
     * would hand back a value that stopped being allowed to exist.
     */
    it('refuses through an expired value rather than handing back a raw string', () => {
      const map = createHandleMap();
      const value = new SensitiveString(CANARY, 'sensitive', undefined, { ttl: 60_000 });
      const handle = entityHandle(value, { key: KEY, record: map });

      const expired = new SensitiveString(CANARY, 'sensitive', undefined, { ttl: 0 });
      map.set(handle, expired);

      let thrown: unknown;
      try {
        rehydrate(`mail ${handle}`, { map });
      } catch (error) {
        thrown = error;
      }

      expect(thrown).toBeInstanceOf(ExpiredSensitiveValueError);
      expect(String(thrown)).not.toContain(CANARY);
    });
  });
});
