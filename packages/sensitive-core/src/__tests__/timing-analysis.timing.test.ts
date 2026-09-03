/**
 * Constant-Time Comparison Timing Analysis
 *
 * Statistical timing measurements for `equals()` on the credential class. These
 * are excluded from `pnpm test` and run with `pnpm test:timing`, because a wall
 * clock assertion depends on the machine it runs on and a shared CI runner is
 * the worst case for one.
 *
 * The measurement is built to be worth trusting when it does run:
 *
 * - Each timed sample covers a batch of calls, so the cost of reading the clock
 *   is amortized instead of dominating a single comparison of a few hundred
 *   nanoseconds.
 * - Groups are interleaved and rotated, so CPU frequency ramping or another
 *   process arriving partway through cannot land on one group alone.
 * - Each group is scored by its fastest batch. Interference only ever adds
 *   time, so the minimum is the closest estimate of the real cost.
 * - Several groups run the identical comparison. The spread between those is
 *   the machine's noise floor, and the verdict is a comparison against it
 *   rather than against a threshold picked on someone else's hardware.
 * - A run whose noise floor is too large to support a conclusion reports that
 *   and skips, rather than failing.
 *
 * Calibrated over twelve runs each way on a WSL2 developer machine. Against the
 * correct implementation: no failures, eleven passes and one skip. Against a
 * deliberately broken `equals()` that compares with `===`: nine caught, two
 * skipped, one missed. The assertion this replaced failed the correct
 * implementation in seven runs out of twelve, and passed that same broken
 * implementation in seven out of eight.
 */

// Timing diagnostics are intentional output from these statistical tests.
/* eslint-disable no-console */

import { describe, it, expect, beforeEach } from 'vitest';
import { SensitiveString, resetPolicies } from '../index.js';

/** Calls per timed sample. Large enough to amortize two clock reads. */
const BATCH = 2000;

/** Timed samples per group. Each group is scored by its fastest sample. */
const SAMPLES = 60;

/**
 * How much larger than the noise floor a spread has to be before it counts as
 * position-dependent timing. A correct implementation measures at or below the
 * noise floor; the broken implementation this was calibrated against measured
 * twenty times it.
 */
const SIGNAL_TO_NOISE_LIMIT = 6;

/**
 * The largest noise floor, as a fraction of the per-call cost, that still
 * supports a conclusion. Above this the machine is too busy to measure on.
 */
const MAX_USABLE_NOISE = 0.1;

const SECRET = 'a'.repeat(64);
const EARLY_MISMATCH = 'b' + 'a'.repeat(63);
const LATE_MISMATCH = 'a'.repeat(63) + 'b';
const COMPLETE_MATCH = 'a'.repeat(64);

/**
 * Consumes every comparison result, so the optimizer cannot decide the calls
 * are unobservable and remove the loop being measured. The first test reads it,
 * which is what makes consuming them count.
 */
let sink = 0;

interface Group {
  readonly name: string;
  readonly comparand: string;
}

/**
 * Time each group's comparison, interleaved, and return the fastest per-call
 * cost each one achieved in nanoseconds.
 */
function measure(
  value: SensitiveString<'credential'>,
  groups: readonly Group[]
): Map<string, number> {
  const samples = new Map<string, number[]>(groups.map((group) => [group.name, []]));

  for (const group of groups) {
    for (let i = 0; i < BATCH; i += 1) {
      sink ^= value.equals(group.comparand) ? 1 : 0;
    }
  }

  for (let sample = 0; sample < SAMPLES; sample += 1) {
    for (let offset = 0; offset < groups.length; offset += 1) {
      // Rotating the order each round keeps a group from always being measured
      // first, when the cache is coldest.
      const group = groups[(sample + offset) % groups.length];
      if (group === undefined) {
        continue;
      }

      const start = process.hrtime.bigint();
      for (let i = 0; i < BATCH; i += 1) {
        sink ^= value.equals(group.comparand) ? 1 : 0;
      }
      const end = process.hrtime.bigint();

      samples.get(group.name)?.push(Number(end - start) / BATCH);
    }
  }

  const fastest = new Map<string, number>();
  for (const [name, times] of samples) {
    fastest.set(name, Math.min(...times));
  }

  return fastest;
}

function spread(values: readonly number[]): number {
  return Math.max(...values) - Math.min(...values);
}

describe('constant-time comparison timing analysis', () => {
  beforeEach(() => {
    resetPolicies();
  });

  it('credential equals() shows no timing difference beyond the noise floor', (ctx) => {
    const value = new SensitiveString(SECRET, 'credential');

    // Three extra groups run the same comparison as `early`. Whatever spread
    // appears between four identical measurements is what this machine can do
    // to a measurement on its own.
    const fastest = measure(value, [
      { name: 'early', comparand: EARLY_MISMATCH },
      { name: 'late', comparand: LATE_MISMATCH },
      { name: 'match', comparand: COMPLETE_MATCH },
      { name: 'control-1', comparand: EARLY_MISMATCH },
      { name: 'control-2', comparand: EARLY_MISMATCH },
      { name: 'control-3', comparand: EARLY_MISMATCH },
    ]);

    const at = (name: string): number => fastest.get(name) ?? Number.NaN;
    const positional = [at('early'), at('late'), at('match')];
    const identical = [at('early'), at('control-1'), at('control-2'), at('control-3')];

    const signal = spread(positional);
    const noise = spread(identical);
    const perCall = Math.min(...positional);
    const noiseFraction = noise / perCall;

    console.log('Timing analysis (credential class), nanoseconds per call:');
    console.log('  early mismatch:', at('early').toFixed(1));
    console.log('  late mismatch: ', at('late').toFixed(1));
    console.log('  exact match:   ', at('match').toFixed(1));
    console.log('  noise floor:   ', noise.toFixed(1), `(${(noiseFraction * 100).toFixed(1)}%)`);
    console.log('  signal:        ', signal.toFixed(1));
    console.log('  signal / noise:', (signal / Math.max(noise, 0.01)).toFixed(2));

    if (noiseFraction > MAX_USABLE_NOISE) {
      // Failing here would report a busy machine as a timing leak. The reason
      // is logged rather than passed to skip(), which takes no argument in this
      // version of the runner and would otherwise discard it silently.
      console.log(
        `  SKIPPED: noise floor is ${(noiseFraction * 100).toFixed(1)}% of the per-call cost, ` +
          `above the ${MAX_USABLE_NOISE * 100}% this measurement can conclude from`
      );
      ctx.skip();
      return;
    }

    expect(signal).toBeLessThanOrEqual(noise * SIGNAL_TO_NOISE_LIMIT);

    // Reading the sink is the half of the dead code guard that a write alone
    // does not provide. Every comparison result was folded into it.
    expect(sink === 0 || sink === 1).toBe(true);
  });

  it('reports the sensitive class for comparison, which is not constant-time', () => {
    const value = new SensitiveString(
      SECRET,
      'sensitive'
    ) as unknown as SensitiveString<'credential'>;

    const fastest = measure(value, [
      { name: 'early', comparand: EARLY_MISMATCH },
      { name: 'late', comparand: LATE_MISMATCH },
    ]);

    // No assertion. The sensitive class compares with ===, and whether V8 makes
    // that observably position-dependent is V8's business, not a property this
    // library promises either way.
    console.log('Timing analysis (sensitive class, not constant-time):');
    console.log('  early mismatch:', (fastest.get('early') ?? Number.NaN).toFixed(1));
    console.log('  late mismatch: ', (fastest.get('late') ?? Number.NaN).toFixed(1));
  });

  it('reports length-based timing, which is documented to leak', () => {
    const value = new SensitiveString(SECRET, 'credential');

    const fastest = measure(value, [
      { name: 'short', comparand: 'short' },
      { name: 'same', comparand: 'x'.repeat(64) },
      { name: 'long', comparand: 'x'.repeat(128) },
    ]);

    // No assertion. A length mismatch returns before the constant-time
    // comparison, which the threat model documents as unavoidable.
    console.log('Timing analysis (length, documented to leak):');
    console.log('  5 characters:  ', (fastest.get('short') ?? Number.NaN).toFixed(1));
    console.log('  64 characters: ', (fastest.get('same') ?? Number.NaN).toFixed(1));
    console.log('  128 characters:', (fastest.get('long') ?? Number.NaN).toFixed(1));
  });
});
