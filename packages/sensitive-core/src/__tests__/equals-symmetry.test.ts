/**
 * The comparison path is chosen by either operand, not by the receiver alone.
 *
 * `equals()` used to pick constant-time comparison from the receiver's policy
 * only, so `sensitiveValue.equals(credentialValue)` compared with `===` while
 * `credentialValue.equals(sensitiveValue)` did not. Which side of the call a
 * credential lands on is not a decision anyone makes on purpose.
 *
 * Observed through a spy on `timingSafeEqual` rather than a clock. The wall
 * clock measurements live in `timing-analysis.timing.test.ts`, behind
 * `pnpm test:timing`, because their verdict depends on how busy the machine is.
 */

import { timingSafeEqual } from 'node:crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { SensitiveString, registerPolicy, resetPolicies, type RevealAccess } from '../index.js';

vi.mock('node:crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:crypto')>();

  return { ...actual, timingSafeEqual: vi.fn(actual.timingSafeEqual) };
});

const credential = (value: string) => new SensitiveString(value, 'credential');
const sensitive = (value: string) => new SensitiveString(value, 'sensitive');

function constantTimeComparisons(): number {
  return vi.mocked(timingSafeEqual).mock.calls.length;
}

describe('equals() chooses the comparison path from either operand', () => {
  beforeEach(() => {
    resetPolicies();
    vi.mocked(timingSafeEqual).mockClear();
  });

  it('compares in constant time when the receiver is a credential', () => {
    expect(credential('abc').equals(sensitive('abc'))).toBe(true);
    expect(constantTimeComparisons()).toBe(1);
  });

  it('compares in constant time when only the argument is a credential', () => {
    expect(sensitive('abc').equals(credential('abc'))).toBe(true);
    expect(constantTimeComparisons()).toBe(1);
  });

  it('compares in constant time when both operands are credentials', () => {
    expect(credential('abc').equals(credential('abc'))).toBe(true);
    expect(constantTimeComparisons()).toBe(1);
  });

  it('compares plainly when neither class requires otherwise', () => {
    expect(sensitive('abc').equals(sensitive('abc'))).toBe(true);
    expect(sensitive('abc').equals('abc')).toBe(true);
    expect(constantTimeComparisons()).toBe(0);
  });

  it('follows the policy flag rather than the class name', () => {
    registerPolicy(
      {
        name: 'credential',
        redact: () => '[REDACTED:credential]',
        requireConstantTimeEquals: false,
      },
      { overwrite: true }
    );

    expect(sensitive('abc').equals(credential('abc'))).toBe(true);
    expect(credential('abc').equals(sensitive('abc'))).toBe(true);
    expect(constantTimeComparisons()).toBe(0);
  });

  it.each([
    ['equal values', 'abc', 'abc', true],
    ['values of the same length', 'abc', 'abd', false],
    ['values of different lengths', 'abc', 'abcd', false],
    ['empty against non-empty', '', 'a', false],
  ])('answers the same in both directions for %s', (_name, left, right, expected) => {
    expect(sensitive(left).equals(credential(right))).toBe(expected);
    expect(credential(right).equals(sensitive(left))).toBe(expected);
  });

  it('still consults the argument policy gate, as it always did', () => {
    const accesses: RevealAccess[] = [];

    registerPolicy(
      {
        name: 'credential',
        redact: () => '[REDACTED:credential]',
        requireConstantTimeEquals: true,
        checkRevealAllowed: (_ctx, _value, access) => {
          accesses.push(access);
        },
      },
      { overwrite: true }
    );

    expect(sensitive('abc').equals(credential('abc'))).toBe(true);
    expect(accesses).toEqual(['compare']);
    expect(constantTimeComparisons()).toBe(1);
  });
});
