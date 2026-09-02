import { beforeEach, describe, expect, it } from 'vitest';
import { SensitiveString, resetPolicies } from './index.js';

const CANARY = '  CANARY-Ab_Cd_Ab-93841  ';

describe('SensitiveString string methods', () => {
  beforeEach(() => {
    resetPolicies();
  });

  describe('transformations', () => {
    it('trims whitespace with native String semantics', () => {
      const value = new SensitiveString('  CANARY  ', 'credential', 'api_key');

      expect(value.trim().reveal()).toBe('CANARY');
      expect(value.trimStart().reveal()).toBe('CANARY  ');
      expect(value.trimEnd().reveal()).toBe('  CANARY');
    });

    it('changes case while retaining protection', () => {
      const value = new SensitiveString('CaNaRy', 'credential', 'api_key');

      expect(value.toLowerCase().reveal()).toBe('canary');
      expect(value.toUpperCase().reveal()).toBe('CANARY');
    });

    it('pads both ends with native String semantics', () => {
      const value = new SensitiveString('CANARY', 'sensitive', 'marker');

      expect(value.padStart(8, '0').reveal()).toBe('00CANARY');
      expect(value.padEnd(8, '0').reveal()).toBe('CANARY00');
      expect(value.padStart(8).reveal()).toBe('  CANARY');
    });

    it('slices with positive and negative indices', () => {
      const value = new SensitiveString('CANARY-SECRET', 'credential', 'token');

      expect(value.slice(0, 6).reveal()).toBe('CANARY');
      expect(value.slice(-6).reveal()).toBe('SECRET');
    });

    it('splits into protected values and respects the limit', () => {
      const value = new SensitiveString('CANARY-ONE-TWO', 'credential', 'token');
      const parts = value.split('-', 2);

      expect(parts).toHaveLength(2);
      expect(parts.map((part) => part.reveal())).toEqual(['CANARY', 'ONE']);
      expect(parts.every((part) => part instanceof SensitiveString)).toBe(true);
      expect(parts.every((part) => part.klass === 'credential')).toBe(true);
      expect(parts.every((part) => part.label === 'token')).toBe(true);
    });

    it('returns a protected empty value when splitting an empty string', () => {
      const [part] = new SensitiveString('', 'sensitive', 'empty').split(',');

      expect(part).toBeInstanceOf(SensitiveString);
      expect(part?.reveal()).toBe('');
      expect(part?.label).toBe('empty');
    });

    it('replaces one or all matches using string replacement patterns', () => {
      const value = new SensitiveString('CANARY-Ab-Ab', 'credential', 'token');

      expect(value.replace('Ab', 'X').reveal()).toBe('CANARY-X-Ab');
      expect(value.replaceAll('Ab', 'X').reveal()).toBe('CANARY-X-X');
      expect(value.replace(/Ab/g, '[$&]').reveal()).toBe('CANARY-[Ab]-[Ab]');
      expect(value.replaceAll(/Ab/g, 'X').reveal()).toBe('CANARY-X-X');
    });

    it('provides protected character access with native bounds behavior', () => {
      const value = new SensitiveString('CANARY', 'credential', 'token');

      expect(value.charAt(1).reveal()).toBe('A');
      expect(value.charAt(99).reveal()).toBe('');
      expect(value.at(-1)?.reveal()).toBe('Y');
      expect(value.at(99)).toBeUndefined();
    });

    it('preserves class and label through chained transformations', () => {
      const transformed = new SensitiveString(CANARY, 'credential', 'api_key')
        .trim()
        .toLowerCase()
        .replaceAll('_', '-')
        .slice(0, 16)
        .padEnd(18, '*');

      expect(transformed.klass).toBe('credential');
      expect(transformed.label).toBe('api_key');
      expect(transformed.reveal()).toBe('canary-ab-cd-ab-**');
    });

    it('preserves Unicode characters', () => {
      const value = new SensitiveString('  CA\u0301NARY-🔐  ', 'sensitive', 'unicode');

      expect(value.trim().slice(-3).reveal()).toBe('-🔐');
    });
  });

  describe('partial queries', () => {
    it('mirrors native search behavior for sensitive values', () => {
      const value = new SensitiveString('CANARY-abc-CANARY', 'sensitive', 'marker');

      expect(value.startsWith('CANARY')).toBe(true);
      expect(value.startsWith('abc', 7)).toBe(true);
      expect(value.endsWith('CANARY')).toBe(true);
      expect(value.endsWith('abc', 10)).toBe(true);
      expect(value.includes('abc')).toBe(true);
      expect(value.includes('abc', 8)).toBe(false);
      expect(value.indexOf('CANARY')).toBe(0);
      expect(value.indexOf('CANARY', 1)).toBe(11);
      expect(value.lastIndexOf('CANARY')).toBe(11);
      expect(value.lastIndexOf('CANARY', 10)).toBe(0);
    });
  });
});
