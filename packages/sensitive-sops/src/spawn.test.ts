import { describe, it, expect, afterEach } from 'vitest';
import { readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';

import { SopsError, checkVersion, childEnv, decryptArgs, decryptContext, run } from './spawn.js';
import { AGE_KEY, FAKE_SOPS, ageIdentity, encryptedYaml, scratch } from './__tests__/fixtures.js';

const dirs: string[] = [];

afterEach(() => {
  for (const dir of dirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
  delete process.env['SOPS_AGE_KEY'];
});

function dir(): string {
  const made = scratch();
  dirs.push(made);

  return made;
}

describe('decryptArgs', () => {
  it('asks for JSON, which is what keeps the YAML parser off the plaintext', () => {
    expect(decryptArgs('/etc/app/secrets.enc.yaml')).toEqual([
      '--decrypt',
      '--output-type',
      'json',
      '/etc/app/secrets.enc.yaml',
    ]);
  });

  it('puts the path in its own argv slot, so a path is never shell syntax', () => {
    const args = decryptArgs('/etc/app/my secrets; rm -rf /.enc.yaml');

    expect(args[args.length - 1]).toBe('/etc/app/my secrets; rm -rf /.enc.yaml');
  });
});

describe('childEnv', () => {
  const options = {
    binary: FAKE_SOPS,
    args: [],
    context: decryptContext(),
    timeoutMs: 1_000,
  };

  it('puts the age key in the child environment', () => {
    const env = childEnv({ ...options, ageKey: ageIdentity() });

    expect(env['SOPS_AGE_KEY']).toBe(AGE_KEY);
  });

  it('leaves the parent environment alone', () => {
    childEnv({ ...options, ageKey: ageIdentity() });

    expect(process.env['SOPS_AGE_KEY']).toBeUndefined();
  });

  it('passes no key at all where the backend is KMS', () => {
    const env = childEnv(options);

    expect('SOPS_AGE_KEY' in env).toBe(false);
  });

  it('carries the parent environment through, since sops needs PATH and cloud credentials', () => {
    const env = childEnv(options);

    expect(env['PATH']).toBe(process.env['PATH']);
  });

  it('carries extra environment a caller supplied', () => {
    const env = childEnv({ ...options, env: { AWS_PROFILE: 'prod' } });

    expect(env['AWS_PROFILE']).toBe('prod');
  });
});

describe('run', () => {
  it('collects stdout and the exit code', async () => {
    const scratchDir = dir();
    const path = encryptedYaml(scratchDir);

    const result = await run({
      binary: FAKE_SOPS,
      args: decryptArgs(path),
      ageKey: ageIdentity(),
      context: decryptContext(),
      timeoutMs: 5_000,
    });

    expect(result.code).toBe(0);
    expect(JSON.parse(result.stdout)).toMatchObject({ database: { host: 'db.internal' } });
  });

  it('hands the age key to the child and never to the parent', async () => {
    const scratchDir = dir();
    const path = encryptedYaml(scratchDir);
    const report = join(scratchDir, 'report.json');

    await run({
      binary: FAKE_SOPS,
      args: decryptArgs(path),
      ageKey: ageIdentity(),
      context: decryptContext(),
      timeoutMs: 5_000,
      env: { FAKE_SOPS_REPORT: report },
    });

    const seen = JSON.parse(readFileSync(report, 'utf8')) as {
      sawAgeKey: boolean;
      ageKey: string;
    };

    expect(seen.sawAgeKey).toBe(true);
    expect(seen.ageKey).toBe(AGE_KEY);
    expect(process.env['SOPS_AGE_KEY']).toBeUndefined();
  });

  it('collects stderr and a non-zero exit code', async () => {
    const scratchDir = dir();
    const path = encryptedYaml(scratchDir);

    const result = await run({
      binary: FAKE_SOPS,
      args: decryptArgs(path),
      context: decryptContext(),
      timeoutMs: 5_000,
      env: { FAKE_SOPS_FAIL: '1' },
    });

    expect(result.code).toBe(128);
    expect(result.stderr).toContain('identity did not match any of the recipients');
  });

  it('rejects when the binary is not there', async () => {
    await expect(
      run({
        binary: '/definitely/not/a/binary',
        args: ['--version'],
        context: decryptContext(),
        timeoutMs: 5_000,
      })
    ).rejects.toThrow();
  });
});

describe('checkVersion', () => {
  it('returns the version string', async () => {
    expect(await checkVersion(FAKE_SOPS, 5_000)).toContain('sops 3.9.4');
  });

  it('names the requirement when the binary is missing', async () => {
    await expect(checkVersion('/definitely/not/a/binary', 5_000)).rejects.toThrow(
      /shells out to sops/
    );
  });

  it('reports a non-zero version check as a SopsError', async () => {
    await expect(checkVersion(join(FAKE_SOPS, 'nope'), 5_000)).rejects.toBeInstanceOf(SopsError);
  });
});
