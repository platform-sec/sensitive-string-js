import { runInNewContext } from 'node:vm';
import { beforeEach, describe, expect, it } from 'vitest';
import safeRegex from 'safe-regex2';
import { patterns, resetPolicies, SensitiveString } from './index.js';

const CANARY = 'REGEX_CANARY_user@example.test';

describe('SensitiveString regular-expression operations', () => {
  beforeEach(() => {
    resetPolicies();
  });

  describe('queries', () => {
    it('tests and searches sensitive values', () => {
      const email = new SensitiveString('CANARY@example.test', 'sensitive', 'email');

      expect(email.test(patterns.email)).toBe(true);
      expect(email.test(/^admin@/)).toBe(false);
      expect(email.search(/@/)).toBe(6);
      expect(email.search(/missing/)).toBe(-1);
    });

    it('does not use or mutate a global pattern lastIndex', () => {
      const value = new SensitiveString('CANARY-CANARY', 'sensitive');
      const pattern = /CANARY/g;
      pattern.lastIndex = 7;

      expect(value.test(pattern)).toBe(true);
      expect(value.test(pattern)).toBe(true);
      expect(pattern.lastIndex).toBe(7);
    });

    it('accepts genuine regular expressions created in another realm', () => {
      const value = new SensitiveString('CANARY@example.test', 'sensitive');
      const crossRealmPattern: unknown = runInNewContext('/^CANARY@/i');

      expect(value.test(crossRealmPattern as RegExp)).toBe(true);
      expect(value.match(crossRealmPattern as RegExp)).not.toBeNull();
    });
  });

  describe('protected matches', () => {
    it('wraps the full match and numbered captures', () => {
      const value = new SensitiveString(CANARY, 'sensitive', 'contact');
      const matches = value.match(/^(REGEX_CANARY)_(.+)$/);

      expect(matches).not.toBeNull();
      expect(matches?.map((match) => match.reveal())).toEqual([
        CANARY,
        'REGEX_CANARY',
        'user@example.test',
      ]);
      expect(matches?.every((match) => match instanceof SensitiveString)).toBe(true);
      expect(matches?.every((match) => match.klass === 'sensitive')).toBe(true);
      expect(matches?.every((match) => match.label === 'contact')).toBe(true);
    });

    it('returns null when the expression does not match', () => {
      const value = new SensitiveString(CANARY, 'sensitive');

      expect(value.match(/^missing$/)).toBeNull();
    });

    it('omits optional captures that did not participate', () => {
      const value = new SensitiveString('CANARY', 'sensitive');

      expect(value.match(/^(CANARY)(-OPTIONAL)?$/)?.map((match) => match.reveal())).toEqual([
        'CANARY',
        'CANARY',
      ]);
    });

    it('wraps named groups and derives group labels', () => {
      const email = new SensitiveString('CANARY@example.test', 'sensitive', 'email');
      const groups = email.matchGroups(/^(?<local>[^@]+)@(?<domain>[^@]+)$/);

      expect(groups?.['local']?.reveal()).toBe('CANARY');
      expect(groups?.['domain']?.reveal()).toBe('example.test');
      expect(groups?.['local']?.label).toBe('email:local');
      expect(groups?.['domain']?.label).toBe('email:domain');
      expect(groups?.['local']?.klass).toBe('sensitive');
    });

    it('uses the group name as the label when the source is unlabeled', () => {
      const value = new SensitiveString('CANARY', 'credential');
      const groups = value.matchGroups(/^(?<marker>CANARY)$/);

      expect(groups?.['marker']?.label).toBe('marker');
      expect(groups?.['marker']?.klass).toBe('credential');
    });

    it('treats an empty source label as present', () => {
      const value = new SensitiveString('CANARY', 'sensitive', '');
      const groups = value.matchGroups(/^(?<marker>CANARY)$/);

      expect(groups?.['marker']?.label).toBe(':marker');
    });

    it('distinguishes no match from a match without named groups', () => {
      const value = new SensitiveString('CANARY', 'sensitive');
      const groups = value.matchGroups(/^CANARY$/);

      expect(Object.keys(groups ?? {})).toEqual([]);
      expect(Object.getPrototypeOf(groups)).toBeNull();
      expect(value.matchGroups(/^missing$/)).toBeNull();
    });

    it('returns named groups without an object prototype', () => {
      const value = new SensitiveString('CANARY', 'sensitive');
      const groups = value.matchGroups(/^(?<__proto__>CANARY)$/);

      expect(groups?.['__proto__']).toBeInstanceOf(SensitiveString);
      expect(groups?.['__proto__']?.reveal()).toBe('CANARY');
      expect(Object.getPrototypeOf(groups)).toBeNull();
    });

    it('omits named groups that did not participate', () => {
      const value = new SensitiveString('CANARY', 'sensitive');
      const groups = value.matchGroups(/^(?<marker>CANARY)(?<optional>-OPTIONAL)?$/);

      expect(Object.keys(groups ?? {})).toEqual(['marker']);
    });

    it('iterates over protected full matches and captures', () => {
      const value = new SensitiveString('CANARY-1 CANARY-2', 'credential', 'token');
      const matches = Array.from(value.matchAll(/(CANARY)-(\d)/g));

      expect(matches.map((match) => match.map((part) => part.reveal()))).toEqual([
        ['CANARY-1', 'CANARY', '1'],
        ['CANARY-2', 'CANARY', '2'],
      ]);
      expect(matches.flat().every((match) => match.klass === 'credential')).toBe(true);
      expect(matches.flat().every((match) => match.label === 'token')).toBe(true);
    });

    it('requires a global expression for matchAll without accessing the value', () => {
      const value = new SensitiveString(CANARY, 'credential');

      expect(() => value.matchAll(/CANARY/)).toThrowError(
        new TypeError('SensitiveString.matchAll requires a global regular expression')
      );
    });
  });

  describe('built-in patterns', () => {
    it('provides an anchored email pattern', () => {
      expect(patterns.email.test('user@example.test')).toBe(true);
      expect(patterns.email.test('prefix user@example.test suffix')).toBe(false);
      expect(patterns.email.test('missing-at.example.test')).toBe(false);
      expect(patterns.email.test('user@example.test\n')).toBe(false);
      expect(patterns.email.test('user@example.test\r\n')).toBe(false);
      expect(patterns.email.source.startsWith('^')).toBe(true);
      expect(Object.isFrozen(patterns)).toBe(true);
    });

    it('returns independent built-in expressions so callers cannot mutate shared state', () => {
      const mutated = patterns.email;
      mutated.compile('^mutated$');

      expect(mutated.test('user@example.test')).toBe(false);
      expect(patterns.email.test('user@example.test')).toBe(true);
      expect(patterns.email).not.toBe(mutated);
    });

    it('passes every built-in pattern through the ReDoS checker', () => {
      for (const pattern of Object.values(patterns)) {
        expect(safeRegex(pattern)).toBe(true);
      }
    });
  });
});
