/**
 * Constant-Time Comparison Verification Tests
 *
 * Statistical timing tests to verify constant-time behavior for credential comparisons.
 * These tests help detect timing side-channel vulnerabilities.
 *
 * Note: Timing tests can be flaky in CI environments due to scheduling variance.
 * They're primarily useful for development and should be run with `continue-on-error: true` in CI.
 */

// Timing diagnostics are intentional output from these statistical tests.
/* eslint-disable no-console */

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

  describe('timing analysis', () => {
    // These tests measure timing differences to verify constant-time behavior.
    // They're statistical in nature and may have false positives/negatives.

    const ITERATIONS = 500;
    const SECRET = 'a'.repeat(64); // 64-char secret

    // Strings with differences at different positions
    const EARLY_MISMATCH = 'b' + 'a'.repeat(63); // First char different
    const LATE_MISMATCH = 'a'.repeat(63) + 'b'; // Last char different
    const COMPLETE_MATCH = 'a'.repeat(64); // Exact match

    function measureComparison(
      sensitive: SensitiveString<'credential'>,
      comparand: string,
      iterations: number
    ): number[] {
      const times: number[] = [];

      // Warmup - important for JIT optimization
      for (let i = 0; i < 100; i++) {
        sensitive.equals(comparand);
      }

      // Measure
      for (let i = 0; i < iterations; i++) {
        const start = process.hrtime.bigint();
        sensitive.equals(comparand);
        const end = process.hrtime.bigint();
        times.push(Number(end - start));
      }

      return times;
    }

    function median(arr: number[]): number {
      const sorted = [...arr].sort((a, b) => a - b);
      const mid = Math.floor(sorted.length / 2);
      return sorted.length % 2 ? sorted[mid]! : (sorted[mid - 1]! + sorted[mid]!) / 2;
    }

    function percentile(arr: number[], p: number): number {
      const sorted = [...arr].sort((a, b) => a - b);
      const index = Math.ceil((p / 100) * sorted.length) - 1;
      return sorted[Math.max(0, index)]!;
    }

    function mean(arr: number[]): number {
      return arr.reduce((a, b) => a + b, 0) / arr.length;
    }

    function stdDev(arr: number[]): number {
      const avg = mean(arr);
      const squareDiffs = arr.map((value) => Math.pow(value - avg, 2));
      return Math.sqrt(mean(squareDiffs));
    }

    it('credential equals() shows no significant timing difference based on match position', () => {
      const s = new SensitiveString(SECRET, 'credential');

      const earlyTimes = measureComparison(s, EARLY_MISMATCH, ITERATIONS);
      const lateTimes = measureComparison(s, LATE_MISMATCH, ITERATIONS);
      const matchTimes = measureComparison(s, COMPLETE_MATCH, ITERATIONS);

      const earlyMedian = median(earlyTimes);
      const lateMedian = median(lateTimes);
      const matchMedian = median(matchTimes);

      // Calculate coefficient of variation for timing difference
      // A constant-time implementation should have similar medians
      const maxDiff = Math.max(
        Math.abs(earlyMedian - lateMedian),
        Math.abs(earlyMedian - matchMedian),
        Math.abs(lateMedian - matchMedian)
      );

      const avgMedian = (earlyMedian + lateMedian + matchMedian) / 3;
      const percentDiff = (maxDiff / avgMedian) * 100;

      // Log timing data for debugging
      console.log('Timing analysis (credential class):');
      console.log('  Early mismatch:', {
        median: earlyMedian.toFixed(0),
        p95: percentile(earlyTimes, 95).toFixed(0),
        stdDev: stdDev(earlyTimes).toFixed(0),
      });
      console.log('  Late mismatch:', {
        median: lateMedian.toFixed(0),
        p95: percentile(lateTimes, 95).toFixed(0),
        stdDev: stdDev(lateTimes).toFixed(0),
      });
      console.log('  Exact match:', {
        median: matchMedian.toFixed(0),
        p95: percentile(matchTimes, 95).toFixed(0),
        stdDev: stdDev(matchTimes).toFixed(0),
      });
      console.log('  Max percent diff:', percentDiff.toFixed(2) + '%');

      // Allow up to 30% timing variance (generous for CI environments)
      // A vulnerable implementation would typically show 50%+ difference
      // Note: This is a statistical test and may have false positives
      expect(percentDiff).toBeLessThan(30);
    });

    it('sensitive class may show timing difference (not constant-time)', () => {
      // This test documents that sensitive class doesn't use constant-time
      // comparison, which is expected behavior
      const s = new SensitiveString(SECRET, 'sensitive');

      const earlyTimes = measureComparison(
        s as unknown as SensitiveString<'credential'>,
        EARLY_MISMATCH,
        ITERATIONS
      );
      const lateTimes = measureComparison(
        s as unknown as SensitiveString<'credential'>,
        LATE_MISMATCH,
        ITERATIONS
      );

      const earlyMedian = median(earlyTimes);
      const lateMedian = median(lateTimes);

      // Log for informational purposes
      console.log('Timing analysis (sensitive class - not constant-time):');
      console.log('  Early mismatch median:', earlyMedian.toFixed(0));
      console.log('  Late mismatch median:', lateMedian.toFixed(0));

      // We don't assert timing difference here since the optimizer might
      // make regular comparison appear constant-time in some cases
      expect(true).toBe(true); // Placeholder assertion
    });

    it('different length comparisons complete (length is allowed to leak)', () => {
      const s = new SensitiveString(SECRET, 'credential');

      // Length checks can be non-constant-time (documented behavior)
      // This test verifies the comparison still works correctly
      const shortTimes = measureComparison(s, 'short', ITERATIONS);
      const sameLengthTimes = measureComparison(s, 'x'.repeat(64), ITERATIONS);
      const longTimes = measureComparison(s, 'x'.repeat(128), ITERATIONS);

      const shortMedian = median(shortTimes);
      const sameMedian = median(sameLengthTimes);
      const longMedian = median(longTimes);

      console.log('Length-based timing (may vary - documented behavior):');
      console.log('  Short (5 chars):', shortMedian.toFixed(0));
      console.log('  Same length (64 chars):', sameMedian.toFixed(0));
      console.log('  Long (128 chars):', longMedian.toFixed(0));

      // Just verify the comparisons complete correctly
      expect(s.equals('short')).toBe(false);
      expect(s.equals('x'.repeat(64))).toBe(false);
      expect(s.equals('x'.repeat(128))).toBe(false);
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
