import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { describe, it, expect, beforeAll, afterAll } from 'vitest';

/**
 * The test that keeps section 1 of the design honest across Node and kernel
 * versions.
 *
 * A child is spawned with the canary exported in its environment, the child
 * deletes the variable and reads `/proc/self/environ`, and both halves are
 * asserted: `process.env` no longer has it, and the file still does. A second
 * case runs the child with `--env-file` and asserts the opposite.
 *
 * It skips with a recorded reason on a platform with no `/proc`. The design's
 * table was measured under WSL2, and `procfs` semantics are the one place a
 * different sandbox could differ, so this runs wherever the suite runs rather
 * than being asserted once and written down.
 */

const CANARY = 'LEAKED_SECRET_abc123xyz';
const onLinux = process.platform === 'linux';

let dir: string;

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'sensitive-env-kernel-'));
});

afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

/** What a child reports about one variable, in `process.env` and in the kernel copy. */
interface Probe {
  readonly inProcessEnvBefore: boolean;
  readonly inProcessEnvAfter: boolean;
  readonly inKernelCopy: boolean;
  readonly kernelNames: string[];
}

const PROBE_SOURCE = `
  const { readFileSync } = require('node:fs');
  const NAME = 'SENSITIVE_ENV_KERNEL_PROBE';

  const inProcessEnvBefore = Object.hasOwn(process.env, NAME);
  delete process.env[NAME];
  const inProcessEnvAfter = Object.hasOwn(process.env, NAME);

  const buffer = readFileSync('/proc/self/environ');
  const kernelNames = [];
  let start = 0;
  for (let i = 0; i <= buffer.length; i++) {
    if (i !== buffer.length && buffer[i] !== 0) continue;
    if (i > start) {
      const eq = buffer.indexOf(0x3d, start);
      if (eq !== -1 && eq < i) kernelNames.push(buffer.toString('utf8', start, eq));
    }
    start = i + 1;
  }

  process.stdout.write(JSON.stringify({
    inProcessEnvBefore,
    inProcessEnvAfter,
    inKernelCopy: kernelNames.includes(NAME),
    kernelNames,
  }));
`;

function probe(args: readonly string[], env: NodeJS.ProcessEnv): Probe {
  const out = execFileSync(process.execPath, [...args, '-e', PROBE_SOURCE], {
    env,
    encoding: 'utf8',
  });

  return JSON.parse(out) as Probe;
}

describe.skipIf(!onLinux)('the kernel copy', () => {
  it('keeps a variable exported before exec, after it is deleted', () => {
    const result = probe([], {
      ...process.env,
      SENSITIVE_ENV_KERNEL_PROBE: CANARY,
    });

    expect(result.inProcessEnvBefore).toBe(true);
    expect(result.inProcessEnvAfter).toBe(false);
    // Deleting removed the copy JavaScript can see. The kernel's copy is still
    // there, and stays there for the life of the process.
    expect(result.inKernelCopy).toBe(true);
  });

  it('has no copy at all for a variable Node loaded from --env-file', () => {
    const envFile = join(dir, 'kernel.env');
    writeFileSync(envFile, `SENSITIVE_ENV_KERNEL_PROBE=${CANARY}\n`);

    const clean = { ...process.env };
    delete clean['SENSITIVE_ENV_KERNEL_PROBE'];

    const result = probe([`--env-file=${envFile}`], clean);

    expect(result.inProcessEnvBefore).toBe(true);
    expect(result.inProcessEnvAfter).toBe(false);
    // Node set the variable after exec, so deletion is complete.
    expect(result.inKernelCopy).toBe(false);
  });

  it('reports names only, never a value, from the buffer scan', () => {
    const result = probe([], { ...process.env, SENSITIVE_ENV_KERNEL_PROBE: CANARY });

    expect(result.kernelNames).toContain('SENSITIVE_ENV_KERNEL_PROBE');
    expect(result.kernelNames.join('\n')).not.toContain(CANARY);
  });
});

describe.skipIf(onLinux)('the kernel copy, elsewhere', () => {
  it('is skipped because this platform has no /proc/self/environ', () => {
    expect(process.platform).not.toBe('linux');
  });
});
