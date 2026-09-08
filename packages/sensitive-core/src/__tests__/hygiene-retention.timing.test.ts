/**
 * Whether `clear()` actually removes the plaintext from the V8 heap.
 *
 * The only tests in this feature that measure the heap rather than behaviour,
 * which is why they live under `pnpm test:timing` beside the timing analysis
 * instead of gating `pnpm test`: a heap-snapshot search is slow, GC scheduling
 * depends on what else the machine is doing, and neither is a release gate. CI
 * runs this file with `continue-on-error: true`.
 *
 * Two details make the probe trustworthy, and both are load bearing:
 *
 * - The needle is a `Buffer`. Buffer bytes live in external memory and are not
 *   in a snapshot's string table, so holding the needle does not put the text
 *   into the heap being measured.
 * - Every canary is a single flat string from `randomBytes().toString('hex')`.
 *   A canary built as `'PREFIX_' + randomBytes(16).toString('hex')` is a V8
 *   cons string: the joined text is never materialized, so a snapshot search
 *   finds nothing even while the value is fully live. A suite that builds
 *   canaries by concatenation is testing string representation, not retention.
 */
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { writeHeapSnapshot } from 'node:v8';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import {
  clearAllSensitiveValues,
  resetMemoryHygiene,
  SensitiveString,
  setMemoryHygiene,
} from '../index.js';
import { trackedRefCount } from '../hygiene.js';

const HAS_GC = typeof global.gc === 'function';

const scratch = mkdtempSync(join(tmpdir(), 'sensitive-retention-'));
let snapshots = 0;

afterAll(() => {
  rmSync(scratch, { recursive: true, force: true });
});

/** A flat canary of `bytes * 2` hex characters. Never a concatenation. */
function flatCanary(bytes = 24): string {
  return randomBytes(bytes).toString('hex').toUpperCase();
}

/** Whether the heap still holds this text, searched as bytes. */
function presentInHeap(needle: Buffer): boolean {
  const path = join(scratch, `probe-${snapshots++}.heapsnapshot`);
  writeHeapSnapshot(path);

  try {
    return readFileSync(path).includes(needle);
  } finally {
    unlinkSync(path);
  }
}

/** Collect hard enough that a released string is actually gone. */
function collect(): void {
  for (let i = 0; i < 4; i++) {
    global.gc?.();
  }
}

/**
 * Collect and then yield the turn, which is what a `FinalizationRegistry`
 * callback needs: it was measured wanting two GC cycles and two macrotask
 * turns before a set of 5,005 entries fell to 5.
 */
async function collectAcrossTurns(rounds = 4): Promise<void> {
  for (let i = 0; i < rounds; i++) {
    global.gc?.();
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

// `global.gc` needs `--expose-gc`, which `vitest.timing.config.ts` supplies
// through its top-level `execArgv` (Vitest 4 removed the `poolOptions.forks`
// nesting, and accepts and ignores it, so nested there the flag would never
// reach the fork). Skipping rather than passing matters: a green suite for a
// measurement never taken is worse than a skipped one.
describe.skipIf(!HAS_GC)('what clear() removes from the heap', () => {
  beforeEach(() => {
    resetMemoryHygiene();
  });

  it('builds every canary as a flat string, not a concatenation', () => {
    // The guard on the rest of the file. A cons string reads as absent while
    // fully live, so if this ever stops holding, every result below inverts.
    const canary = flatCanary();
    const needle = Buffer.from(canary, 'utf8');

    const holder = { canary };
    expect(presentInHeap(needle)).toBe(true);

    // And the trap itself, so the reason for the rule is measured rather than
    // asserted: the same text assembled by concatenation is not in the table,
    // because the joined text of a cons string is never materialized.
    //
    // The needle has to be assembled from the two halves as bytes.
    // `Buffer.from(prefix + suffix)` would flatten the concatenation on its way
    // into the buffer, putting the joined text into the heap and reporting
    // `present` for a reason that is the measurement's own doing.
    const prefix = 'CANARY_';
    const suffix = randomBytes(16).toString('hex').toUpperCase();
    const consed = prefix + suffix;
    const consNeedle = Buffer.concat([Buffer.from(prefix, 'utf8'), Buffer.from(suffix, 'utf8')]);

    expect(presentInHeap(consNeedle)).toBe(false);

    expect(holder.canary).toBe(canary);
    expect(consed.length).toBe(prefix.length + suffix.length);
  });

  it('removes a canary with no other holder', () => {
    let needle!: Buffer;

    // Built inside a function so the canary dies with the frame and the
    // instance is the only holder.
    const make = (): SensitiveString<'credential'> => {
      const canary = flatCanary();
      needle = Buffer.from(canary, 'utf8');
      return new SensitiveString(canary, 'credential', 'probe');
    };

    const token = make();
    expect(presentInHeap(needle)).toBe(true);

    token.clear();
    collect();

    expect(presentInHeap(needle)).toBe(false);
    expect(token.isCleared).toBe(true);
  });

  it('does not remove one the caller still references, which is the documented limit', () => {
    const canary = flatCanary();
    const needle = Buffer.from(canary, 'utf8');

    // The common HTTP shape: the parsed body holds the same string object the
    // instance does, so the library's clear releases nothing.
    const body = JSON.parse(JSON.stringify({ token: canary })) as { token: string };
    const token = new SensitiveString(body.token, 'credential', 'probe');

    token.clear();
    collect();

    expect(presentInHeap(needle)).toBe(true);
    expect(body.token).toBe(canary);
  });

  it('is pinned by a derivative until that derivative is cleared too', () => {
    let needle!: Buffer;

    const make = (): SensitiveString<'credential'> => {
      const canary = flatCanary();
      needle = Buffer.from(canary, 'utf8');
      return new SensitiveString(canary, 'credential', 'probe');
    };

    const parent = make();
    // Sixteen characters, comfortably over V8's slicing threshold, so this is a
    // SlicedString pointing into the parent's backing store rather than a copy.
    // The behaviour is what is asserted; the threshold itself is an unspecified
    // V8 implementation detail and is deliberately not.
    const derivative = parent.substring(0, 16);

    parent.clear();
    collect();

    expect(presentInHeap(needle)).toBe(true);

    derivative.clear();
    collect();

    expect(presentInHeap(needle)).toBe(false);
  });

  it('releases a short derivative immediately, because V8 copied it', () => {
    let needle!: Buffer;

    const make = (): SensitiveString<'credential'> => {
      const canary = flatCanary();
      needle = Buffer.from(canary, 'utf8');
      return new SensitiveString(canary, 'credential', 'probe');
    };

    const parent = make();
    // Under the threshold, so V8 copies and the parent is not pinned. The
    // asymmetry with the case above is the whole reason the pin is documented
    // rather than fixed.
    const derivative = parent.substring(0, 8);

    parent.clear();
    collect();

    expect(presentInHeap(needle)).toBe(false);
    expect(derivative.isCleared).toBe(true);
  });
});

/**
 * What the tracked set does as the collector runs.
 *
 * These live here rather than in `hygiene-security.test.ts` for the reason
 * that file now records: they need `global.gc`, `pnpm test` does not supply
 * it, and a test guarded by `typeof global.gc` that returns early reports a
 * pass for a measurement it never took.
 */
describe.skipIf(!HAS_GC)('what tracking does to the collector', () => {
  beforeEach(() => {
    resetMemoryHygiene();
  });

  afterAll(() => {
    resetMemoryHygiene();
  });

  it('never keeps a tracked instance alive', async () => {
    setMemoryHygiene({ trackInstances: true });

    let ref!: WeakRef<SensitiveString<'sensitive'>>;

    // Built and dropped inside a function, so the frame that held it is gone.
    (() => {
      const value = new SensitiveString(flatCanary(), 'sensitive', 'transient');
      ref = new WeakRef(value);
    })();

    await collectAcrossTurns();

    // The whole contract of tracking: it must not keep alive the thing it
    // exists to destroy. A strong reference here would be a leak of exactly
    // the value this library protects.
    expect(ref.deref()).toBeUndefined();
  });

  it('lets the finalizer prune the set, with a lag and no promised bound', async () => {
    setMemoryHygiene({ trackInstances: true });

    (() => {
      for (let i = 0; i < 500; i++) {
        new SensitiveString(flatCanary(8), 'sensitive', `transient-${i}`);
      }
    })();

    expect(trackedRefCount()).toBe(500);

    await collectAcrossTurns(6);

    // Asserted as "it shrinks", not as "it empties". The callbacks run on the
    // collector's schedule across turns, so a exact figure here would be a
    // promise the runtime does not make.
    expect(trackedRefCount()).toBeLessThan(500);
  });

  it('does not double-count an instance a sweep already cleared', async () => {
    setMemoryHygiene({ trackInstances: true });

    const held = new SensitiveString(flatCanary(), 'sensitive', 'held');

    expect(clearAllSensitiveValues()).toBe(1);
    expect(held.isCleared).toBe(true);

    // The sweep unregistered it from the finalizer, so its later collection
    // cannot delete a ref the set no longer holds or count it a second time.
    await collectAcrossTurns();

    expect(clearAllSensitiveValues()).toBe(0);
  });
});
