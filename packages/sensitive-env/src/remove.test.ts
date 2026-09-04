import { describe, it, expect, afterEach } from 'vitest';

import { kernelCopyNames, removeFromProcessEnv } from './remove.js';
import { loadEnv } from './load.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';
const NAMES = ['SENSITIVE_ENV_SECRET', 'SENSITIVE_ENV_PLAIN', 'SENSITIVE_ENV_OTHER'] as const;

afterEach(() => {
  for (const name of NAMES) {
    delete process.env[name];
  }
});

describe('removeFromProcessEnv', () => {
  it('deletes the names it was given and reports them', () => {
    process.env['SENSITIVE_ENV_SECRET'] = CANARY;

    expect(removeFromProcessEnv(['SENSITIVE_ENV_SECRET'])).toEqual(['SENSITIVE_ENV_SECRET']);
    expect(process.env['SENSITIVE_ENV_SECRET']).toBeUndefined();
    expect(Object.hasOwn(process.env, 'SENSITIVE_ENV_SECRET')).toBe(false);
  });

  it('reports only what was actually there', () => {
    expect(removeFromProcessEnv(['SENSITIVE_ENV_SECRET'])).toEqual([]);
  });

  it('leaves every other variable alone', () => {
    process.env['SENSITIVE_ENV_SECRET'] = CANARY;
    process.env['SENSITIVE_ENV_PLAIN'] = 'keep me';

    removeFromProcessEnv(['SENSITIVE_ENV_SECRET']);

    expect(process.env['SENSITIVE_ENV_PLAIN']).toBe('keep me');
  });
});

describe('loadEnv with removeFromProcessEnv', () => {
  it('deletes only the names it wrapped', () => {
    process.env['SENSITIVE_ENV_SECRET'] = CANARY;
    process.env['SENSITIVE_ENV_PLAIN'] = 'keep me';

    const record = loadEnv(
      { fields: { SENSITIVE_ENV_SECRET: 'credential' }, fallback: 'plain' },
      { removeFromProcessEnv: true }
    );

    expect(record.removed).toContain('SENSITIVE_ENV_SECRET');
    expect(record.removed).not.toContain('SENSITIVE_ENV_PLAIN');
    expect(process.env['SENSITIVE_ENV_SECRET']).toBeUndefined();
    expect(process.env['SENSITIVE_ENV_PLAIN']).toBe('keep me');
  });

  it('keeps the value available through the record after deleting it', () => {
    process.env['SENSITIVE_ENV_SECRET'] = CANARY;

    const record = loadEnv(
      { fields: { SENSITIVE_ENV_SECRET: 'credential' }, fallback: 'plain' },
      { removeFromProcessEnv: true }
    );

    expect(record.fields.get('SENSITIVE_ENV_SECRET')?.reveal()).toBe(CANARY);
  });

  it('does not touch process.env when the option is off', () => {
    process.env['SENSITIVE_ENV_SECRET'] = CANARY;

    const record = loadEnv({ fields: { SENSITIVE_ENV_SECRET: 'credential' }, fallback: 'plain' });

    expect(record.removed).toEqual([]);
    expect(process.env['SENSITIVE_ENV_SECRET']).toBe(CANARY);
  });

  it('does not delete a name that came only from a file', () => {
    const record = loadEnv(
      { fields: { SENSITIVE_ENV_OTHER: 'credential' }, fallback: 'plain' },
      { source: { SENSITIVE_ENV_OTHER: CANARY }, removeFromProcessEnv: true }
    );

    // The name was wrapped from a caller-supplied source, so there was nothing
    // in `process.env` to delete and nothing is claimed.
    expect(record.removed).toEqual([]);
  });
});

describe('kernelCopyNames', () => {
  const onLinux = process.platform === 'linux';

  it.skipIf(!onLinux)('finds a name the parent exported before exec', () => {
    // The runner's own environment was exported before this process started, so
    // one of its names is a guaranteed hit without spawning anything.
    const exported = Object.keys(process.env).find((name) => name === 'PATH' || name === 'HOME');
    expect(exported).toBeDefined();

    expect(kernelCopyNames([exported!])).toEqual([exported]);
  });

  it.skipIf(!onLinux)('does not find a name this process set itself', () => {
    process.env['SENSITIVE_ENV_SECRET'] = CANARY;

    expect(kernelCopyNames(['SENSITIVE_ENV_SECRET'])).toEqual([]);
  });

  it.skipIf(!onLinux)('still finds a name after it was deleted from process.env', () => {
    const exported = 'PATH';
    const saved = process.env[exported];

    try {
      delete process.env[exported];

      expect(process.env[exported]).toBeUndefined();
      expect(kernelCopyNames([exported])).toEqual([exported]);
    } finally {
      if (saved !== undefined) {
        process.env[exported] = saved;
      }
    }
  });

  it.skipIf(!onLinux)('reports nothing for a name that is in neither place', () => {
    expect(kernelCopyNames(['SENSITIVE_ENV_NEVER_SET'])).toEqual([]);
  });

  it.skipIf(onLinux)("answers 'unknown' where there is no /proc", () => {
    expect(kernelCopyNames(['PATH'])).toBe('unknown');
  });

  it('never returns a value, only names', () => {
    const result = kernelCopyNames(Object.keys(process.env));

    if (result === 'unknown') {
      return;
    }

    for (const name of result) {
      expect(Object.keys(process.env)).toContain(name);
    }
  });
});

describe('loadEnv with checkKernelCopy', () => {
  it.skipIf(process.platform !== 'linux')('names the variables deletion cannot reach', () => {
    const record = loadEnv(
      { fields: { PATH: 'credential' }, fallback: 'plain' },
      { checkKernelCopy: true }
    );

    expect(record.kernelCopy).toEqual(['PATH']);
  });

  it.skipIf(process.platform !== 'linux')('reports nothing for a variable it set itself', () => {
    process.env['SENSITIVE_ENV_SECRET'] = CANARY;

    const record = loadEnv(
      { fields: { SENSITIVE_ENV_SECRET: 'credential' }, fallback: 'plain' },
      { checkKernelCopy: true, removeFromProcessEnv: true }
    );

    expect(record.removed).toEqual(['SENSITIVE_ENV_SECRET']);
    expect(record.kernelCopy).toEqual([]);
  });
});
