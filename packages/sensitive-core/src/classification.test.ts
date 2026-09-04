import { describe, it, expect } from 'vitest';
import { compileClassification, classifyField } from './classification.js';
import type { ClassificationSpec } from './classification.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

describe('compileClassification', () => {
  describe('precedence', () => {
    const spec: ClassificationSpec = {
      fields: { password: 'credential', port: 'plain' },
      rules: [
        { pattern: /password/i, klass: 'plain' },
        { pattern: /^db_/, klass: 'sensitive' },
      ],
      fallback: 'credential',
    };

    it('prefers fields over a rule that also matches', () => {
      expect(compileClassification(spec).classify('password')).toBe('credential');
    });

    it('prefers fields over the fallback', () => {
      expect(compileClassification(spec).classify('port')).toBe('plain');
    });

    it('prefers an earlier rule over a later one', () => {
      const first = compileClassification({
        rules: [
          { pattern: /^db_/, klass: 'sensitive' },
          { pattern: /_host$/, klass: 'plain' },
        ],
      });

      expect(first.classify('db_host')).toBe('sensitive');
    });

    it('falls back for a key no field and no rule matched', () => {
      expect(compileClassification(spec).classify('anything-else')).toBe('credential');
    });

    it('returns undefined when nothing matched and there is no fallback', () => {
      expect(compileClassification({ rules: [] }).classify('anything-else')).toBeUndefined();
    });
  });

  describe('keys, not values', () => {
    it('never sees a value, so a pattern cannot match one', () => {
      const compiled = compileClassification({
        rules: [{ pattern: new RegExp(CANARY), klass: 'credential' }],
        fallback: 'plain',
      });

      // The matcher's only input is the key name. A rule written against the
      // value classifies nothing, which is the intended dead end.
      expect(compiled.classify('token')).toBe('plain');
      expect(compiled.classify(CANARY)).toBe('credential');
    });
  });

  describe('aliases', () => {
    const compiled = compileClassification({
      fields: { 'db.password': 'credential' },
      rules: [{ pattern: /^apiKey$/, klass: 'credential' }],
      fallback: 'plain',
    });

    it('matches a dot path exactly through fields', () => {
      expect(compiled.classify('db.password', ['password'])).toBe('credential');
    });

    it('matches a rule against a leaf key of a nested path', () => {
      expect(compiled.classify('outer.apiKey', ['apiKey'])).toBe('credential');
    });

    it('leaves an unmatched nested key to the fallback', () => {
      expect(compiled.classify('outer.host', ['host'])).toBe('plain');
    });

    it('checks every alias at the fields level before trying any rule', () => {
      const both = compileClassification({
        fields: { password: 'plain' },
        rules: [{ pattern: /^db\.password$/, klass: 'credential' }],
      });

      expect(both.classify('db.password', ['password'])).toBe('plain');
    });
  });

  describe('pattern state', () => {
    it('strips the global flag so repeated keys classify the same way', () => {
      const compiled = compileClassification({
        rules: [{ pattern: /secret/g, klass: 'credential' }],
        fallback: 'plain',
      });

      expect(compiled.classify('secret')).toBe('credential');
      expect(compiled.classify('secret')).toBe('credential');
      expect(compiled.classify('secret')).toBe('credential');
    });

    it('strips the sticky flag for the same reason', () => {
      const compiled = compileClassification({
        rules: [{ pattern: /secret/y, klass: 'credential' }],
        fallback: 'plain',
      });

      expect(compiled.classify('secret')).toBe('credential');
      expect(compiled.classify('secret')).toBe('credential');
    });

    it('does not mutate the caller pattern', () => {
      const pattern = /secret/g;
      const compiled = compileClassification({ rules: [{ pattern, klass: 'credential' }] });

      compiled.classify('secret');

      expect(pattern.lastIndex).toBe(0);
      expect(pattern.flags).toBe('g');
    });

    it('keeps flags that carry meaning', () => {
      const compiled = compileClassification({
        rules: [{ pattern: /PASSWORD/i, klass: 'credential' }],
        fallback: 'plain',
      });

      expect(compiled.classify('password')).toBe('credential');
    });
  });

  describe('inherited keys', () => {
    it('does not read a field name off Object.prototype', () => {
      const compiled = compileClassification({ fields: { real: 'credential' }, fallback: 'plain' });

      expect(compiled.classify('toString')).toBe('plain');
      expect(compiled.classify('constructor')).toBe('plain');
      expect(compiled.classify('__proto__')).toBe('plain');
    });
  });

  describe('validation', () => {
    it('rejects a class that is not a FieldClass', () => {
      expect(() => compileClassification({ fields: { a: 'secret' as never } })).toThrow(
        /Invalid classification for field 'a'/
      );
    });

    it('rejects a bad fallback', () => {
      expect(() => compileClassification({ fallback: 'nope' as never })).toThrow(
        /Invalid classification for fallback/
      );
    });

    it('rejects a rule whose pattern is not a RegExp', () => {
      expect(() =>
        compileClassification({ rules: [{ pattern: 'password' as never, klass: 'credential' }] })
      ).toThrow(/rule at index 0: pattern must be a RegExp/);
    });

    it('names the offending rule index', () => {
      expect(() =>
        compileClassification({
          rules: [
            { pattern: /a/, klass: 'plain' },
            { pattern: /b/, klass: 'nope' as never },
          ],
        })
      ).toThrow(/rule at index 1/);
    });
  });

  describe('exposed shape', () => {
    it('exposes the compiled parts for a caller that wants to report them', () => {
      const compiled = compileClassification({
        fields: { password: 'credential' },
        rules: [{ pattern: /token/, klass: 'credential' }],
        fallback: 'plain',
      });

      expect([...compiled.fields]).toEqual([['password', 'credential']]);
      expect(compiled.rules).toHaveLength(1);
      expect(compiled.fallback).toBe('plain');
    });
  });
});

describe('classifyField', () => {
  it('answers a one-off question without a compiled spec', () => {
    expect(classifyField('password', { fields: { password: 'credential' } })).toBe('credential');
  });

  it('takes aliases like the compiled matcher', () => {
    expect(
      classifyField('db.password', { rules: [{ pattern: /^password$/, klass: 'credential' }] }, [
        'password',
      ])
    ).toBe('credential');
  });
});
