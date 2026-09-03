/**
 * Constant-Time Comparison Verification Tests
 *
 * Deterministic tests for the constant-time comparison path: that the policy
 * requires it for credentials, and that `equals()` answers correctly whatever
 * the comparand.
 *
 * The statistical measurements that were here live in
 * `timing-analysis.timing.test.ts`, which `pnpm test:timing` runs. A wall clock
 * assertion belongs behind an opt-in, not in the suite that gates a release.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { SensitiveString, getPolicy, resetPolicies } from '../index.js';

describe('Constant-Time Comparison Security', () => {
  beforeEach(() => {
    resetPolicies();
  });

  describe('policy configuration', () => {
    it('credential class requires constant-time comparison', () => {
      const policy = getPolicy('credential');
      expect(policy.requireConstantTimeEquals).toBe(true);
    });

    it('sensitive class does not require constant-time comparison', () => {
      const policy = getPolicy('sensitive');
      expect(policy.requireConstantTimeEquals).toBe(false);
    });
  });

  describe('equals() correctness', () => {
    it('credential equals returns true for matching values', () => {
      const secret = 'my-secret-password-12345';
      const s = new SensitiveString(secret, 'credential');

      expect(s.equals(secret)).toBe(true);
    });

    it('credential equals returns false for non-matching values', () => {
      const secret = 'my-secret-password-12345';
      const s = new SensitiveString(secret, 'credential');

      expect(s.equals('wrong-password')).toBe(false);
    });

    it('credential equals returns false for partial match at start', () => {
      const secret = 'my-secret-password-12345';
      const s = new SensitiveString(secret, 'credential');

      expect(s.equals('my-secret')).toBe(false);
    });

    it('credential equals returns false for partial match at end', () => {
      const secret = 'my-secret-password-12345';
      const s = new SensitiveString(secret, 'credential');

      expect(s.equals('password-12345')).toBe(false);
    });

    it('credential equals handles empty strings', () => {
      const empty = new SensitiveString('', 'credential');

      expect(empty.equals('')).toBe(true);
      expect(empty.equals('x')).toBe(false);
    });

    it('credential equals handles unicode', () => {
      const unicode = '密码🔐パスワード';
      const s = new SensitiveString(unicode, 'credential');

      expect(s.equals(unicode)).toBe(true);
      expect(s.equals('密码🔐')).toBe(false);
    });

    it('credential equals works with SensitiveString argument', () => {
      const secret = 'shared-secret';
      const s1 = new SensitiveString(secret, 'credential');
      const s2 = new SensitiveString(secret, 'credential');
      const s3 = new SensitiveString('different', 'credential');

      expect(s1.equals(s2)).toBe(true);
      expect(s1.equals(s3)).toBe(false);
    });
  });

  describe('comparison correctness across lengths', () => {
    const SECRET = 'a'.repeat(64);

    it('rejects comparands of every length without regard to timing', () => {
      const s = new SensitiveString(SECRET, 'credential');

      // A length mismatch returns before the constant-time comparison, which
      // the threat model documents as unavoidable leakage. What matters here is
      // that the answer is still correct.
      expect(s.equals('short')).toBe(false);
      expect(s.equals('x'.repeat(64))).toBe(false);
      expect(s.equals('x'.repeat(128))).toBe(false);
      expect(s.equals(SECRET)).toBe(true);
    });

    it('rejects a mismatch wherever it falls in the value', () => {
      const s = new SensitiveString(SECRET, 'credential');

      expect(s.equals('b' + 'a'.repeat(63))).toBe(false);
      expect(s.equals('a'.repeat(63) + 'b')).toBe(false);
      expect(s.equals('a'.repeat(32) + 'b' + 'a'.repeat(31))).toBe(false);
    });
  });

  describe('edge cases in constant-time comparison', () => {
    it('handles repeated comparisons correctly', () => {
      const secret = 'my-secret';
      const s = new SensitiveString(secret, 'credential');

      // Verify multiple comparisons don't affect correctness
      for (let i = 0; i < 100; i++) {
        expect(s.equals(secret)).toBe(true);
        expect(s.equals('wrong')).toBe(false);
      }
    });

    it('handles concurrent comparisons correctly', async () => {
      const secret = 'concurrent-secret';
      const s = new SensitiveString(secret, 'credential');

      const results = await Promise.all(
        Array(100)
          .fill(null)
          .map(async (_, i) => {
            // Simulate some async work
            await new Promise((resolve) => setTimeout(resolve, Math.random() * 10));
            return {
              matchResult: s.equals(secret),
              mismatchResult: s.equals(`wrong-${i}`),
            };
          })
      );

      // All match results should be true
      expect(results.every((r) => r.matchResult)).toBe(true);
      // All mismatch results should be false
      expect(results.every((r) => !r.mismatchResult)).toBe(true);
    });

    it('handles comparison with various string encodings', () => {
      // Test UTF-8 byte-level comparison
      const tests = [
        ['hello', 'hello', true],
        ['hello', 'Hello', false], // Case sensitive
        ['café', 'café', true],
        ['café', 'cafe\u0301', false], // Different Unicode normalization
        ['🔐', '🔐', true],
        ['🔐', '\uD83D\uDD10', true], // Same emoji, different representation
      ] as const;

      for (const [secret, comparand, expected] of tests) {
        const s = new SensitiveString(secret, 'credential');
        expect(s.equals(comparand)).toBe(expected);
      }
    });
  });
});
