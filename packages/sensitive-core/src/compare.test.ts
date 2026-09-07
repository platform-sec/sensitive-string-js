import { describe, it, expect } from 'vitest';
import { constantTimeEquals } from './compare.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

describe('constantTimeEquals', () => {
  it('answers true only for byte-identical values', () => {
    expect(constantTimeEquals(CANARY, CANARY)).toBe(true);
    expect(constantTimeEquals(CANARY, CANARY + 'x')).toBe(false);
    expect(constantTimeEquals(CANARY, CANARY.slice(0, -1))).toBe(false);
    expect(constantTimeEquals(CANARY, CANARY.toUpperCase())).toBe(false);
  });

  it('compares values of different lengths without throwing', () => {
    // `timingSafeEqual` rejects operands of unequal length with a RangeError,
    // which is the whole reason both sides are hashed to a fixed width first.
    // This is the one regression a unit test can catch here: removing the
    // hashing and handing the raw values over throws, loudly, rather than
    // quietly returning the right answer.
    //
    // What it cannot catch is the branch coming back. Restoring an early
    // return on a length mismatch would keep every assertion in this file
    // green, because the answers were never wrong; only the time they took
    // was. That case is measured, not asserted, by the stored-length group in
    // `__tests__/timing-analysis.timing.test.ts`, for the reason every timing
    // test in this repository asserts nothing: a wall clock verdict depends on
    // how busy the machine is and must not gate a release.
    expect(constantTimeEquals('a', 'a'.repeat(4096))).toBe(false);
    expect(constantTimeEquals('', CANARY)).toBe(false);
    expect(constantTimeEquals(CANARY, '')).toBe(false);
  });

  it('treats the empty string as an ordinary value', () => {
    expect(constantTimeEquals('', '')).toBe(true);
  });

  it('compares by bytes rather than by code units', () => {
    // The same character composed (U+00E9) and decomposed (e + U+0301) is two
    // different values. A comparison that normalized first would be wrong for
    // a password stored in one form and typed in the other, so it must not.
    const composed = '\u00e9';
    const decomposed = 'e\u0301';

    expect(composed).not.toBe(decomposed);
    expect(constantTimeEquals(composed, decomposed)).toBe(false);
    expect(constantTimeEquals(composed, composed)).toBe(true);
  });

  it('is stable across calls within a process', () => {
    // The key is generated once at module load. A key regenerated per call
    // would still compare correctly, so this pins the intended shape rather
    // than an observable behaviour.
    for (let i = 0; i < 100; i += 1) {
      expect(constantTimeEquals(CANARY, CANARY)).toBe(true);
    }
  });

  it('does not put either operand in a thrown message', () => {
    // Nothing here should throw, but if a future change makes it, the value
    // must not ride out on the error.
    try {
      expect(constantTimeEquals(CANARY, 'other')).toBe(false);
    } catch (error) {
      expect(String(error)).not.toContain(CANARY);
      throw error;
    }
  });
});
