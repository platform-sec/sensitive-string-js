/**
 * Policy Redaction Security Tests
 *
 * Verifies that registered policies' redact functions actually redact values
 * and don't leak the original sensitive data through any means.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  SensitiveString,
  SensitivityClass,
  registerPolicy,
  getPolicy,
  resetPolicies,
} from '../index.js';

// Multiple canary values to catch various bypass attempts
// Note: Avoid values with substrings that appear in redaction format
// (e.g., avoid "cred" since it appears in "[REDACTED:credential]")
const CANARY_VALUES = [
  'CANARY_SECRET_abc123',
  'password123!@#',
  'sk-proj-abcdefghijklmnop',
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test',
  'user@example.com',
  '555-123-4567',
  'SSN-123-45-6789',
  'payment-4111-1111-1111-1111',  // Avoid "credit" which contains "cred"
];

const ALL_CLASSES: SensitivityClass[] = ['credential', 'sensitive'];

describe('Policy Redaction Security', () => {
  beforeEach(() => {
    resetPolicies();
  });

  describe('default policies never leak values', () => {
    for (const klass of ALL_CLASSES) {
      for (const canary of CANARY_VALUES) {
        const displayCanary =
          canary.length > 20 ? `${canary.slice(0, 20)}...` : canary;

        it(`${klass} policy redacts "${displayCanary}"`, () => {
          const policy = getPolicy(klass);
          const redacted = policy.redact(canary);

          // Core invariant: redacted output must not contain the original
          expect(redacted).not.toContain(canary);
          expect(redacted).not.toBe(canary);

          // Should not contain any substring longer than 3 chars
          // (to catch partial leaks)
          for (let i = 0; i < canary.length - 3; i++) {
            const substring = canary.slice(i, i + 4);
            expect(redacted).not.toContain(substring);
          }
        });
      }
    }
  });

  describe('SensitiveString uses policy redaction correctly', () => {
    for (const klass of ALL_CLASSES) {
      for (const canary of CANARY_VALUES) {
        const displayCanary =
          canary.length > 20 ? `${canary.slice(0, 20)}...` : canary;

        it(`SensitiveString<${klass}> redacts "${displayCanary}" via toString`, () => {
          const s = new SensitiveString(canary, klass);
          const result = s.toString();

          expect(result).not.toContain(canary);
          expect(result).not.toBe(canary);
        });

        it(`SensitiveString<${klass}> redacts "${displayCanary}" via toJSON`, () => {
          const s = new SensitiveString(canary, klass);
          const result = JSON.stringify(s);

          expect(result).not.toContain(canary);
        });
      }
    }
  });

  describe('policy registration validates redact function', () => {
    it('rejects identity redact function', () => {
      expect(() =>
        registerPolicy(
          {
            name: 'credential',
            redact: (value) => value, // Identity - leaks!
          },
          { overwrite: true }
        )
      ).toThrow(/redact function/i);
    });

    it('rejects redact function that includes value', () => {
      expect(() =>
        registerPolicy(
          {
            name: 'credential',
            redact: (value) => `hidden: ${value}`, // Includes value!
          },
          { overwrite: true }
        )
      ).toThrow(/redact function/i);
    });

    it('rejects redact function that returns value with prefix only', () => {
      expect(() =>
        registerPolicy(
          {
            name: 'credential',
            redact: (value) => `[SECRET]${value}`, // Includes value!
          },
          { overwrite: true }
        )
      ).toThrow(/redact function/i);
    });

    it('rejects redact function that returns value with suffix only', () => {
      expect(() =>
        registerPolicy(
          {
            name: 'credential',
            redact: (value) => `${value}[/SECRET]`, // Includes value!
          },
          { overwrite: true }
        )
      ).toThrow(/redact function/i);
    });

    it('accepts valid constant redact function', () => {
      expect(() =>
        registerPolicy(
          {
            name: 'credential',
            redact: () => '[REDACTED]',
          },
          { overwrite: true }
        )
      ).not.toThrow();
    });

    it('accepts valid length-based redact function', () => {
      expect(() =>
        registerPolicy(
          {
            name: 'credential',
            redact: (value) => `[REDACTED:${value.length} chars]`,
          },
          { overwrite: true }
        )
      ).not.toThrow();
    });

    it('accepts valid asterisk masking function', () => {
      expect(() =>
        registerPolicy(
          {
            name: 'credential',
            redact: (value) => '*'.repeat(value.length),
          },
          { overwrite: true }
        )
      ).not.toThrow();
    });

    it('accepts valid partial masking function (first/last chars hidden)', () => {
      // This is borderline but acceptable - shows structure without content
      expect(() =>
        registerPolicy(
          {
            name: 'sensitive',
            redact: (value) => {
              if (value.length <= 4) return '****';
              return '**' + '*'.repeat(value.length - 4) + '**';
            },
          },
          { overwrite: true }
        )
      ).not.toThrow();
    });
  });

  describe('custom policy redaction is applied', () => {
    it('custom redact function is used for toString', () => {
      registerPolicy(
        {
          name: 'sensitive',
          redact: () => '[CUSTOM_REDACTED]',
        },
        { overwrite: true }
      );

      const s = new SensitiveString('secret-value', 'sensitive');
      expect(s.toString()).toBe('[CUSTOM_REDACTED]');
    });

    it('custom redact function is used for toJSON', () => {
      registerPolicy(
        {
          name: 'sensitive',
          redact: () => '[CUSTOM_REDACTED]',
        },
        { overwrite: true }
      );

      const s = new SensitiveString('secret-value', 'sensitive');
      expect(JSON.stringify({ value: s })).toContain('[CUSTOM_REDACTED]');
    });

    it('custom redact function receives the actual value', () => {
      let receivedValue: string | null = null;
      registerPolicy(
        {
          name: 'sensitive',
          redact: (value) => {
            receivedValue = value;
            return `[REDACTED:${value.length}]`;
          },
        },
        { overwrite: true }
      );

      const secret = 'my-secret-value';
      const s = new SensitiveString(secret, 'sensitive');
      s.toString();

      expect(receivedValue).toBe(secret);
    });
  });

  describe('edge cases in redaction', () => {
    it('handles empty string', () => {
      const s = new SensitiveString('', 'sensitive');
      const result = s.toString();

      // Should still produce valid redacted output
      expect(typeof result).toBe('string');
      expect(result.length).toBeGreaterThan(0);
    });

    it('handles very long strings', () => {
      const longSecret = 'x'.repeat(10000);
      const s = new SensitiveString(longSecret, 'credential');
      const result = s.toString();

      expect(result).not.toContain(longSecret);
      // Redacted output should be reasonable length
      expect(result.length).toBeLessThan(1000);
    });

    it('handles unicode strings', () => {
      const unicodeSecret = '密码🔐パスワードكلمة السر';
      const s = new SensitiveString(unicodeSecret, 'credential');
      const result = s.toString();

      expect(result).not.toContain(unicodeSecret);
      // Should not contain any of the unicode characters
      expect(result).not.toContain('密');
      expect(result).not.toContain('🔐');
      expect(result).not.toContain('パ');
    });

    it('handles null bytes and control characters', () => {
      const weirdSecret = 'secret\x00with\x01control\x02chars';
      const s = new SensitiveString(weirdSecret, 'credential');
      const result = s.toString();

      expect(result).not.toContain(weirdSecret);
      expect(result).not.toContain('\x00');
      expect(result).not.toContain('\x01');
    });

    it('handles JSON-like strings', () => {
      const jsonSecret = '{"password": "secret123", "key": "value"}';
      const s = new SensitiveString(jsonSecret, 'credential');
      const result = s.toString();

      expect(result).not.toContain('secret123');
      expect(result).not.toContain('password');
    });

    it('handles template literal injection attempts', () => {
      const injectionSecret = '${process.env.SECRET}';
      const s = new SensitiveString(injectionSecret, 'credential');
      const result = s.toString();

      expect(result).not.toContain(injectionSecret);
      expect(result).not.toContain('process.env');
    });
  });
});
