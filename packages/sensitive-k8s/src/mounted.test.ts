import { describe, it, expect, afterEach } from 'vitest';
import { mkdirSync, mkdtempSync, renameSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { describeLabelDisclosure } from '@platform-sec/sensitive-string-secrets';
import type { FileWatcher, MultiSecretRecord } from '@platform-sec/sensitive-string-secrets';

import { K8sMountedSource } from './mounted.js';
import { k8sSecretTypeSpec } from './types.js';
import { jwt } from './__tests__/fake-api.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';
const CERT = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----';

const dirs: string[] = [];
const watchers: FileWatcher[] = [];

afterEach(() => {
  for (const watcher of watchers.splice(0)) {
    watcher.close();
  }
  for (const dir of dirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function scratch(): string {
  const dir = mkdtempSync(join(tmpdir(), 'sensitive-k8s-mount-'));
  dirs.push(dir);

  return dir;
}

/**
 * A mount shaped the way the kubelet shapes one.
 *
 * A timestamped data directory, a `..data` symlink pointing at it, and one
 * symlink per key pointing through `..data`. Reading it naively reports every
 * secret twice, once under its own name and once under a directory name that
 * changes on every update.
 */
function kubeletMount(
  dir: string,
  data: Readonly<Record<string, string>>,
  stamp = '..2026_09_03_00_00_00.111'
): void {
  const dataDir = join(dir, stamp);
  mkdirSync(dataDir, { recursive: true });

  for (const [key, value] of Object.entries(data)) {
    writeFileSync(join(dataDir, key), value);
  }

  const link = join(dir, '..data');
  const staging = join(dir, '..data_tmp');
  symlinkSync(stamp, staging);
  renameSync(staging, link);

  for (const key of Object.keys(data)) {
    const target = join(dir, key);

    try {
      rmSync(target, { force: true });
    } catch {
      // First write. Nothing to remove.
    }

    symlinkSync(join('..data', key), target);
  }
}

async function until(predicate: () => boolean, timeoutMs = 3_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;

  while (!predicate()) {
    if (Date.now() > deadline) {
      throw new Error('condition was not met in time');
    }

    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

describe('K8sMountedSource', () => {
  it('reads a mount and wraps under the mount name', async () => {
    const dir = scratch();
    kubeletMount(dir, { username: 'app', password: CANARY });

    const source = new K8sMountedSource({ cache: { ttl: 0 } });
    const record = await source.getAll(dir, { fallback: 'credential' });

    expect(record.fields.get('password')).toBeInstanceOf(SensitiveString);
    expect(record.fields.get('password')?.reveal({ name: 'test' })).toBe(CANARY);
    expect(describeLabelDisclosure(record.fields.get('password')?.label ?? '')).toEqual([]);
  });

  it('skips the kubelet bookkeeping, so no secret is reported twice', async () => {
    const dir = scratch();
    kubeletMount(dir, { password: CANARY });

    const source = new K8sMountedSource({ cache: { ttl: 0 } });
    const record = await source.getAll(dir, { fallback: 'credential' });

    expect(record.keys).toEqual(['password']);
  });

  it('can be told to include them, for a mount that is not a kubelet one', async () => {
    const dir = scratch();
    writeFileSync(join(dir, '..hidden'), 'value');
    writeFileSync(join(dir, 'password'), CANARY);

    const source = new K8sMountedSource({ cache: { ttl: 0 }, includeHiddenEntries: true });
    const record = await source.getAll(dir, { fallback: 'credential' });

    expect([...record.keys].sort()).toEqual(['..hidden', 'password']);
  });

  it('keeps a certificate plain under the tls spec', async () => {
    const dir = scratch();
    kubeletMount(dir, { 'tls.crt': CERT, 'tls.key': CANARY });

    const source = new K8sMountedSource({ cache: { ttl: 0 } });
    const record = await source.getAll(dir, k8sSecretTypeSpec('kubernetes.io/tls'));

    expect(record.plain.get('tls.crt')).toBe(CERT);
    expect(record.fields.get('tls.key')?.klass).toBe('credential');
  });

  it('reports an absent mount as absent', async () => {
    const source = new K8sMountedSource({ cache: { ttl: 0 } });

    expect(await source.getOptional('/definitely/not/a/mount')).toBeNull();
  });

  it('says what is missing when a relative ref has no base to resolve against', async () => {
    const source = new K8sMountedSource({ cache: { ttl: 0 } });

    await expect(source.getAll('db-creds', { fallback: 'credential' })).rejects.toThrow(
      /needs a directory to resolve/
    );
  });

  it('resolves a relative ref against basePath', async () => {
    const parent = scratch();
    mkdirSync(join(parent, 'db-creds'));
    kubeletMount(join(parent, 'db-creds'), { password: CANARY });

    const source = new K8sMountedSource({ basePath: parent, cache: { ttl: 0 } });
    const record = await source.getAll('db-creds', { fallback: 'credential' });

    expect(record.fields.get('password')?.label).toBe('db-creds#password');
    expect(record.fields.get('password')?.reveal({ name: 'test' })).toBe(CANARY);
  });

  it('binds a projected token exp when asked', async () => {
    const dir = scratch();
    const exp = Math.floor(Date.now() / 1000) + 3600;
    kubeletMount(dir, { token: jwt({ exp }), 'ca.crt': CERT, namespace: 'payments' });

    const source = new K8sMountedSource({ cache: { ttl: 0 }, readTokenExpiry: true });
    const record = await source.getAll(
      dir,
      k8sSecretTypeSpec('kubernetes.io/service-account-token')
    );

    expect(record.fields.get('token')?.expiresAt).toEqual(new Date(exp * 1000));
    expect(record.plain.get('namespace')).toBe('payments');
  });
});

describe('K8sMountedSource.watch', () => {
  it('re-reads when the kubelet swaps the mount, and produces new instances', async () => {
    const dir = scratch();
    kubeletMount(dir, { password: 'first' });

    const source = new K8sMountedSource({ cache: { ttl: 0 } });
    const initial = await source.getAll(dir, { fallback: 'credential' });
    const seen: MultiSecretRecord[] = [];

    watchers.push(
      source.watch(
        dir,
        { fallback: 'credential' },
        {
          debounceMs: 20,
          onChange: (next) => seen.push(next),
        }
      )
    );

    kubeletMount(dir, { password: CANARY }, '..2026_09_03_00_01_00.222');
    await until(() => seen.length > 0);

    expect(seen[0]?.fields.get('password')?.reveal({ name: 'test' })).toBe(CANARY);
    // The instance handed out before the swap still works. Nothing can reach
    // it, so an in-flight request finishes with the credential it started with.
    expect(initial.fields.get('password')?.reveal({ name: 'test' })).toBe('first');
    expect(seen[0]?.fields.get('password')).not.toBe(initial.fields.get('password'));
  });
});
