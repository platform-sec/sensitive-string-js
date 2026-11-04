/**
 * What sealing actually removes from memory, measured rather than argued.
 *
 * Two instruments, because the two threats need different ones and they
 * disagree:
 *
 * - A **heap snapshot** is what `v8.writeHeapSnapshot()`, `--heapsnapshot-signal`
 *   and an open inspector port produce. It records V8 heap objects, every string
 *   among them, and no `Buffer` backing store.
 * - A **process dump** is what a core file, `gcore`, an OOM-killing container
 *   runtime, or `/proc/<pid>/mem` produces. It records every mapped page,
 *   including freed pages the allocator has not reused yet.
 *
 * The disagreement is the point: a string that is dropped and collected is
 * absent from a snapshot and still present in a dump, and the dump is the one
 * that is right about what is in the machine. Only the second instrument can see
 * the property this feature is built on, which is that a `Buffer` can be zeroed
 * and a string can never be.
 *
 * These live under `pnpm test:timing` beside the hygiene retention probe, and
 * for the same reasons: a heap-snapshot search is slow, a GC schedule depends on
 * what else the machine is doing, and neither is a release gate. CI runs this
 * file with `continue-on-error: true`.
 *
 * The process scan needs Linux, a readable `/proc`, ptrace rights over a child,
 * and a built `dist` for the child to import. Every one of those is checked
 * before the suite runs, and a missing one skips rather than passes: a green
 * result for a measurement never taken is worse than no result.
 */
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import {
  closeSync,
  existsSync,
  mkdtempSync,
  openSync,
  readFileSync,
  readSync,
  rmSync,
  unlinkSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { writeHeapSnapshot } from 'node:v8';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import { resetSealing, SensitiveString, setSealing } from '../index.js';

/**
 * This package's directory, from the working directory rather than from
 * `import.meta.url`, because the root type-check compiles this file as
 * CommonJS and rejects the meta-property there. The same anchor as
 * `worker-boundary.test.ts`.
 */
const PACKAGE_DIR = existsSync(join(process.cwd(), 'packages', 'sensitive-core'))
  ? join(process.cwd(), 'packages', 'sensitive-core')
  : process.cwd();

const FIXTURE = join(PACKAGE_DIR, 'src', '__tests__', 'fixtures', 'sealing-memory.mjs');
const DIST = join(PACKAGE_DIR, 'dist', 'index.js');

const HAS_GC = typeof global.gc === 'function';

// ---------------------------------------------------------------------------
// Instrument one: the heap snapshot.
// ---------------------------------------------------------------------------

const scratch = mkdtempSync(join(tmpdir(), 'sensitive-sealing-'));
let snapshots = 0;

afterAll(() => {
  rmSync(scratch, { recursive: true, force: true });
  resetSealing();
});

/**
 * A flat canary. Never a concatenation: `'PREFIX_' + hex` is a V8 cons string
 * whose joined text is never materialized, so a snapshot search finds nothing
 * even while the value is fully live, and every result below would invert.
 */
function flatCanary(bytes = 24): string {
  return randomBytes(bytes).toString('hex').toUpperCase();
}

/** Whether the V8 heap still holds this text, searched as bytes. */
function presentInHeap(needle: Buffer): boolean {
  const path = join(scratch, `probe-${String(snapshots++)}.heapsnapshot`);
  writeHeapSnapshot(path);

  try {
    return readFileSync(path).includes(needle);
  } finally {
    unlinkSync(path);
  }
}

function collect(): void {
  for (let round = 0; round < 4; round++) {
    global.gc?.();
  }
}

// ---------------------------------------------------------------------------
// Instrument two: the cross-process scan.
// ---------------------------------------------------------------------------

/**
 * Regions a scan must not read.
 *
 * `[vvar]` and its relatives are kernel-mapped pages that report as readable and
 * fault or return nothing when read through `/proc/<pid>/mem`.
 */
const UNREADABLE_REGIONS = new Set(['[vvar]', '[vdso]', '[vsyscall]', '[vvar_vclock]']);

/** Regions larger than this are V8's address-space reservation, not its data. */
const MAX_REGION_BYTES = 1 << 30;

const CHUNK_BYTES = 1 << 20;

/** Count occurrences of `needle` in every readable page another process maps. */
function scanProcess(pid: number, needle: Buffer): number {
  const maps = readFileSync(`/proc/${String(pid)}/maps`, 'utf8').split('\n');
  const fd = openSync(`/proc/${String(pid)}/mem`, 'r');
  const chunk = Buffer.allocUnsafe(CHUNK_BYTES);
  let hits = 0;

  try {
    for (const line of maps) {
      if (line === '') {
        continue;
      }

      const fields = line.trim().split(/\s+/);
      const range = fields[0] ?? '';
      const perms = fields[1] ?? '';
      const path = fields[5] ?? '';

      if (!perms.startsWith('r') || UNREADABLE_REGIONS.has(path)) {
        continue;
      }

      const [startHex, endHex] = range.split('-');
      const start = BigInt(`0x${startHex ?? '0'}`);
      const end = BigInt(`0x${endHex ?? '0'}`);
      const size = end - start;

      if (size <= 0n || size > BigInt(MAX_REGION_BYTES)) {
        continue;
      }

      let offset = 0n;
      // Carried between chunks so a needle straddling a chunk boundary is still
      // found exactly once rather than zero times or twice.
      let carry = Buffer.alloc(0);

      while (offset < size) {
        const want = Number(
          size - offset < BigInt(CHUNK_BYTES) ? size - offset : BigInt(CHUNK_BYTES)
        );
        let read = 0;

        try {
          read = readSync(fd, chunk, 0, want, start + offset);
        } catch {
          break;
        }

        if (read <= 0) {
          break;
        }

        const window = Buffer.concat([carry, chunk.subarray(0, read)]);
        let at = 0;

        for (;;) {
          const found = window.indexOf(needle, at);

          if (found === -1) {
            break;
          }

          hits += 1;
          at = found + 1;
        }

        carry = Buffer.from(window.subarray(Math.max(0, window.length - needle.length + 1)));
        offset += BigInt(read);
      }
    }
  } finally {
    closeSync(fd);
  }

  return hits;
}

/**
 * Build one case in a child, scan the child, and report the copies beyond the
 * needle the child holds in order to report it.
 */
async function copiesInProcessMemory(mode: string): Promise<number> {
  const child = spawn(process.execPath, ['--expose-gc', FIXTURE, mode], {
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  try {
    const hex = await new Promise<string>((resolve, reject) => {
      let out = '';
      let err = '';
      const timer = setTimeout(() => {
        reject(new Error(`case '${mode}' did not report a needle: ${err}`));
      }, 30_000);

      child.stdout.on('data', (data: Buffer) => {
        out += data.toString('utf8');
        const newline = out.indexOf('\n');

        if (newline !== -1) {
          clearTimeout(timer);
          resolve(out.slice(0, newline).trim());
        }
      });
      child.stderr.on('data', (data: Buffer) => {
        err += data.toString('utf8');
      });
      child.on('exit', (code) => {
        clearTimeout(timer);
        reject(new Error(`case '${mode}' exited ${String(code)}: ${err}`));
      });
    });

    // Minus one: the child holds the needle itself so it can print it.
    return scanProcess(child.pid!, Buffer.from(hex, 'hex')) - 1;
  } finally {
    child.kill('SIGKILL');
  }
}

/**
 * Whether the scan can see a child at all.
 *
 * Yama's `ptrace_scope` is 1 on an ordinary Linux box, which lets a parent read
 * a child and not the reverse. That is why the parent has to be the scanner, and
 * this is the check that the arrangement worked: the control case holds nothing
 * but the needle, so a working scan finds exactly it.
 */
async function scannerWorks(): Promise<boolean> {
  if (process.platform !== 'linux' || !existsSync('/proc/self/maps') || !existsSync(DIST)) {
    return false;
  }

  try {
    return (await copiesInProcessMemory('control')) === 0;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------

describe.skipIf(!HAS_GC)('what a heap snapshot holds', () => {
  it('builds every canary as a flat string, not a concatenation', () => {
    // The guard on the rest of this block, for the reason `flatCanary` gives.
    const canary = flatCanary();
    const holder = { canary };

    expect(presentInHeap(Buffer.from(canary, 'utf8'))).toBe(true);
    expect(holder.canary).toBe(canary);
  });

  it('does not hold a sealed value that was never revealed', () => {
    let needle!: Buffer;

    const build = (): SensitiveString<'credential'> => {
      const canary = flatCanary();
      needle = Buffer.from(canary, 'utf8');
      return SensitiveString.fromBuffer(Buffer.from(canary, 'utf8'), 'credential', 'probe');
    };

    const sealed = build();
    collect();

    // Built in a function so the canary string the fixture needed is dead, and
    // through `fromBuffer` so the value itself was never one.
    expect(presentInHeap(needle)).toBe(false);
    expect(sealed.isSealed).toBe(true);
    expect(sealed.reveal()).toBe(needle.toString('utf8'));
  });

  it('holds an unsealed value for as long as the instance lives', () => {
    // The contrast, and the check that the probe can find what is there.
    let needle!: Buffer;

    const build = (): SensitiveString<'credential'> => {
      const canary = flatCanary();
      needle = Buffer.from(canary, 'utf8');
      return new SensitiveString(canary, 'credential', 'probe');
    };

    const plain = build();
    collect();

    expect(presentInHeap(needle)).toBe(true);
    expect(plain.reveal()).toBe(needle.toString('utf8'));
  });

  it('holds a sealed value while a reveal result is live, and not afterwards', () => {
    let needle!: Buffer;

    const build = (): SensitiveString<'credential'> => {
      const canary = flatCanary();
      needle = Buffer.from(canary, 'utf8');
      return SensitiveString.fromBuffer(Buffer.from(canary, 'utf8'), 'credential', 'probe');
    };

    const sealed = build();
    collect();
    expect(presentInHeap(needle)).toBe(false);

    let revealed: string | undefined = sealed.reveal();
    expect(presentInHeap(needle)).toBe(true);

    revealed = undefined;
    collect();

    // Gone from the snapshot. Still in process memory, which the next block
    // measures and which is the whole reason there are two instruments.
    expect(presentInHeap(needle)).toBe(false);
    expect(revealed).toBeUndefined();
  });

  it('does not hold a sealed value that is only logged', () => {
    let needle!: Buffer;

    const build = (): SensitiveString<'credential'> => {
      const canary = flatCanary();
      needle = Buffer.from(canary, 'utf8');
      return SensitiveString.fromBuffer(Buffer.from(canary, 'utf8'), 'credential', 'probe');
    };

    const sealed = build();

    for (let line = 0; line < 100; line++) {
      JSON.stringify({ line, token: sealed });
    }

    collect();
    expect(presentInHeap(needle)).toBe(false);
  });

  it('holds the value a sealByDefault constructor was handed as a string', () => {
    // The limitation the roadmap states and `fromBuffer` exists to remove: a
    // string passed to the constructor is not the library's to erase.
    setSealing({ sealByDefault: true });

    let needle!: Buffer;

    const build = (): SensitiveString<'credential'> => {
      const canary = flatCanary();
      needle = Buffer.from(canary, 'utf8');
      return new SensitiveString(canary, 'credential', 'probe');
    };

    const sealed = build();
    collect();

    expect(sealed.isSealed).toBe(true);
    // Absent, because the constructor's argument was dropped and collected. The
    // dump instrument disagrees, which is the finding.
    expect(presentInHeap(needle)).toBe(false);
    resetSealing();
  });
});

describe('what a process dump holds', () => {
  // Decided in a hook rather than by a top-level `await`, which the root
  // type-check rejects in a file it compiles as CommonJS. Every case skips
  // rather than returns, so a machine that cannot scan reports skips and never
  // a pass for a measurement it did not take.
  let canScan: boolean | undefined;

  beforeEach(async (context) => {
    canScan ??= await scannerWorks();
    if (!canScan) {
      context.skip();
    }
  });

  it('finds nothing in a child that built nothing', async () => {
    // The floor. Every count below is read against this, and a non-zero control
    // would mean the scanner is finding the needle where nobody put it.
    expect(await copiesInProcessMemory('control')).toBe(0);
  });

  it('still holds a string that was dropped and collected', async () => {
    // The disagreement between the two instruments, stated as a measurement.
    // A heap snapshot calls this absent; the machine still has it, and will
    // until something else reuses the page.
    expect(await copiesInProcessMemory('dropped-string')).toBeGreaterThanOrEqual(1);
  });

  it('does not hold a Buffer that was zeroed', async () => {
    // The only operation measured anywhere here that erases anything, and it is
    // available only to a byte-oriented store.
    expect(await copiesInProcessMemory('live-buffer')).toBeGreaterThanOrEqual(1);
    expect(await copiesInProcessMemory('zeroed-buffer')).toBe(0);
  });

  it('holds nothing for a sealed value built from bytes and never revealed', async () => {
    expect(await copiesInProcessMemory('sealed')).toBe(0);
  });

  it('holds the constructor argument of a sealed value built from a string', async () => {
    // Why `fromBuffer` is part of this feature rather than a convenience: for a
    // dump, the string handed to the constructor is permanent.
    expect(await copiesInProcessMemory('sealed-from-string')).toBeGreaterThanOrEqual(1);
    expect(await copiesInProcessMemory('unsealed')).toBeGreaterThanOrEqual(1);
  });

  it('holds nothing after clear() on a sealed value', async () => {
    // `clear()` on a sealed value zeroes the box, so this is an erase rather
    // than a dropped reference. That is what sealing does for memory hygiene.
    expect(await copiesInProcessMemory('sealed-cleared')).toBe(0);
  });

  it('holds nothing after a thousand byte-returning reveals', async () => {
    expect(await copiesInProcessMemory('sealed-revealbytes-1000')).toBe(0);
  });

  it('holds nothing after a thousand comparisons of two sealed values', async () => {
    expect(await copiesInProcessMemory('sealed-equals-sealed-1000')).toBe(0);
  });

  it('holds only the caller comparand after a thousand comparisons against a string', async () => {
    // One copy, and it is the caller's own string rather than anything
    // `equals()` produced. The library can only ever release the library's copy.
    expect(await copiesInProcessMemory('sealed-equals-string-1000')).toBeLessThanOrEqual(2);
  });

  it('accumulates one copy per string-returning reveal, which is the documented cost', async () => {
    // This asserts a weakness on purpose. The exact number is
    // environment-dependent, so the assertion is that it grows: a later change
    // that quietly made `reveal()` cache its plaintext would fix this number and
    // break the invariant that a sealed value holds no plaintext string between
    // operations, and it would fail here.
    const once = await copiesInProcessMemory('sealed-reveal-1');
    const thousand = await copiesInProcessMemory('sealed-reveal-1000');

    expect(once).toBeGreaterThanOrEqual(1);
    expect(thousand).toBeGreaterThan(100 * Math.max(once, 1));
  });

  it('leaves one copy for a thousand reveals of an unsealed value, for the contrast', async () => {
    // The trade, in one comparison: an unsealed value returns the same string
    // object every time, so repeated reading is free. Sealing turns it into
    // cumulative exposure, and that is the single most important thing in this
    // feature's documentation.
    const sealedReveals = await copiesInProcessMemory('sealed-reveal-1000');
    const unsealedReveals = await copiesInProcessMemory('unsealed-reveal-1000');

    expect(unsealedReveals).toBeLessThanOrEqual(4);
    expect(sealedReveals).toBeGreaterThan(50 * Math.max(unsealedReveals, 1));
  });
});
