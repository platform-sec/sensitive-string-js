import { describe, it, expect, vi, afterEach } from 'vitest';

// Static imports, not `await import`. `vi.mock` is hoisted above them, so these
// already see the replaced `node:fs`, and a top-level `await` would make this
// file an ES module that the repository's CommonJS-emitting `tsc` rejects.
import { loadEnv } from './load.js';
import { kernelCopyNames } from './remove.js';

/**
 * The `'unknown'` contract, tested on every platform rather than only where
 * there is no `/proc`.
 *
 * `kernelCopyNames` answers `'unknown'` when it cannot read the kernel's copy,
 * and never an empty array, which would be a false all-clear. On Linux that
 * branch is unreachable without making the read fail, so the read is what this
 * file replaces. CI runs on Linux, so without this the invariant would be
 * asserted only on a machine nobody runs the suite on.
 */

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>();

  return {
    ...actual,
    readFileSync: vi.fn((path: string, ...rest: unknown[]) => {
      if (path === '/proc/self/environ') {
        const error = new Error("ENOENT: no such file or directory, open '/proc/self/environ'");
        (error as NodeJS.ErrnoException).code = 'ENOENT';
        throw error;
      }

      return (actual.readFileSync as (...args: unknown[]) => unknown)(path, ...rest);
    }),
  };
});

afterEach(() => {
  delete process.env['SENSITIVE_ENV_UNKNOWN_PROBE'];
});

describe('kernelCopyNames where the kernel copy cannot be read', () => {
  it("answers 'unknown' rather than an empty array", () => {
    expect(kernelCopyNames(['PATH'])).toBe('unknown');
  });

  it("answers 'unknown' even for a name that is in no environment at all", () => {
    // The distinction matters: an empty array means "checked, nothing found",
    // and this platform checked nothing.
    expect(kernelCopyNames(['SENSITIVE_ENV_NEVER_SET'])).toBe('unknown');
  });

  it("answers 'unknown' for an empty request, rather than an empty array", () => {
    expect(kernelCopyNames([])).toBe('unknown');
  });

  it('reaches loadEnv, so a caller sees the same answer through the record', () => {
    process.env['SENSITIVE_ENV_UNKNOWN_PROBE'] = 'value';

    const record = loadEnv(
      { fields: { SENSITIVE_ENV_UNKNOWN_PROBE: 'credential' }, fallback: 'plain' },
      { checkKernelCopy: true }
    );

    expect(record.kernelCopy).toBe('unknown');
  });

  it('leaves removal working, since the two are independent', () => {
    process.env['SENSITIVE_ENV_UNKNOWN_PROBE'] = 'value';

    const record = loadEnv(
      { fields: { SENSITIVE_ENV_UNKNOWN_PROBE: 'credential' }, fallback: 'plain' },
      { checkKernelCopy: true, removeFromProcessEnv: true }
    );

    expect(record.removed).toEqual(['SENSITIVE_ENV_UNKNOWN_PROBE']);
    expect(record.kernelCopy).toBe('unknown');
    expect(process.env['SENSITIVE_ENV_UNKNOWN_PROBE']).toBeUndefined();
  });
});
