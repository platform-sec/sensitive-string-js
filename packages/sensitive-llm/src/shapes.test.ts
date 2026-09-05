import { DEFAULT_DENY_KEYS } from '@platform-sec/sensitive-string-scrub';
import { describe, expect, it } from 'vitest';

import { CONTENT_PATH_SHAPES, DEFAULT_CONTENT_PATHS, LLM_DENY_KEYS } from './shapes.js';

describe('provider shapes', () => {
  const shapes = Object.entries(CONTENT_PATH_SHAPES);

  describe('provenance', () => {
    /**
     * The claim this file makes about itself. Nothing here was measured against
     * an installed SDK, and a fixture written from a document tests the
     * document rather than the provider. A shape that ever flips to verified
     * records the SDK version in its `schema`, so this assertion is what forces
     * that to be a deliberate edit.
     */
    it('admits that no shape was measured against an SDK', () => {
      for (const [name, shape] of shapes) {
        expect(shape.verified, name).toBe(false);
        expect(shape.schema, name).not.toBe('');
      }
    });

    it('gives every shape at least the message content position', () => {
      for (const [name, shape] of shapes) {
        expect(shape.paths.length, name).toBeGreaterThan(0);
      }
    });
  });

  describe('the default content paths', () => {
    it('are the union of the shipped shapes, deduplicated', () => {
      const union = new Set(shapes.flatMap(([, shape]) => shape.paths));

      expect(new Set(DEFAULT_CONTENT_PATHS)).toEqual(union);
      expect(DEFAULT_CONTENT_PATHS.length).toBe(union.size);
    });

    it('are lowercase already, since matching lowercases them', () => {
      for (const path of DEFAULT_CONTENT_PATHS) {
        expect(path).toBe(path.toLowerCase());
      }
    });
  });

  describe('the envelope denylist', () => {
    /**
     * A list that quietly restated `scrub`'s defaults would read as coverage
     * this package added, and would grow by accident as the shared defaults
     * grow. Two names were removed when this test was written, for exactly
     * that reason.
     */
    it('adds only names the shared defaults do not already carry', () => {
      const defaults = new Set(DEFAULT_DENY_KEYS.map((key) => key.toLowerCase()));
      const redundant = LLM_DENY_KEYS.filter((key) => defaults.has(key.toLowerCase()));

      expect(redundant, 'these are already denied by @platform-sec/sensitive-string-scrub').toEqual(
        []
      );
    });

    it('names nothing to do with message content', () => {
      // Section 2.2 of the design: the key is `content`, the key is always
      // `content`, and denying it denies the request.
      for (const key of LLM_DENY_KEYS) {
        expect(key.toLowerCase()).not.toContain('content');
        expect(key.toLowerCase()).not.toContain('prompt');
        expect(key.toLowerCase()).not.toContain('message');
      }
    });
  });
});
