import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, rmSync, renameSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SensitiveString } from '@platform-sec/sensitive-string-core';

import { watchFile } from './watch.js';
import type { FileWatcher } from './watch.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

const open: FileWatcher[] = [];
const dirs: string[] = [];

afterEach(() => {
  for (const watcher of open.splice(0)) {
    watcher.close();
  }
  for (const dir of dirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function scratch(): string {
  const dir = mkdtempSync(join(tmpdir(), 'sensitive-watch-'));
  dirs.push(dir);

  return dir;
}

function track(watcher: FileWatcher): FileWatcher {
  open.push(watcher);

  return watcher;
}

/** Wait for a condition, so a filesystem event does not need a fixed sleep. */
async function until(predicate: () => boolean, timeoutMs = 2_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;

  while (!predicate()) {
    if (Date.now() > deadline) {
      throw new Error('condition was not met in time');
    }

    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

describe('watchFile', () => {
  it('re-reads on a change and hands the previous value to onChange', async () => {
    const dir = scratch();
    const path = join(dir, 'secret.json');
    writeFileSync(path, JSON.stringify({ password: 'first' }));

    const read = async (): Promise<SensitiveString<'credential'>> => {
      const { readFile } = await import('node:fs/promises');
      const parsed = JSON.parse(await readFile(path, 'utf8')) as { password: string };

      return new SensitiveString(parsed.password, 'credential', 'secret.json#password');
    };

    const changes: { next: string; previous: string | undefined }[] = [];
    const initial = await read();

    track(
      watchFile(
        path,
        read,
        {
          debounceMs: 10,
          onChange: (next, previous) => {
            changes.push({
              next: next.reveal({ name: 'test' }),
              previous: previous?.reveal({ name: 'test' }),
            });
          },
        },
        initial
      )
    );

    writeFileSync(path, JSON.stringify({ password: CANARY }));
    await until(() => changes.length > 0);

    expect(changes[0]?.next).toBe(CANARY);
    expect(changes[0]?.previous).toBe('first');
  });

  it('produces a new instance rather than mutating the previous one', async () => {
    const dir = scratch();
    const path = join(dir, 'secret.txt');
    writeFileSync(path, 'first');

    const read = async (): Promise<SensitiveString<'credential'>> => {
      const { readFile } = await import('node:fs/promises');

      return new SensitiveString(await readFile(path, 'utf8'), 'credential');
    };

    const seen: SensitiveString<'credential'>[] = [];
    const initial = await read();

    track(
      watchFile(
        path,
        read,
        {
          debounceMs: 10,
          onChange: (next, previous) => {
            seen.push(next);

            if (previous !== undefined) {
              seen.push(previous);
            }
          },
        },
        initial
      )
    );

    writeFileSync(path, CANARY);
    await until(() => seen.length >= 2);

    expect(seen[0]).not.toBe(seen[1]);
    // The instance handed out before the change still works. Nothing can reach
    // it, so a rotation does not invalidate an in-flight request.
    expect(initial.reveal({ name: 'test' })).toBe('first');
  });

  it('collapses the several filesystem events of one atomic rename', async () => {
    const dir = scratch();
    const path = join(dir, 'secret.txt');
    const staging = join(dir, 'secret.next');
    writeFileSync(path, 'first');

    let reads = 0;
    const read = async (): Promise<string> => {
      reads += 1;
      const { readFile } = await import('node:fs/promises');

      return await readFile(path, 'utf8');
    };

    const changes: string[] = [];
    track(
      watchFile(path, read, {
        debounceMs: 50,
        onChange: (next) => changes.push(next),
      })
    );

    writeFileSync(staging, CANARY);
    renameSync(staging, path);

    await until(() => changes.length > 0);
    await new Promise((resolve) => setTimeout(resolve, 120));

    expect(changes[0]).toBe(CANARY);
    expect(reads).toBe(1);
  });

  it('keeps the previous value in service while a read keeps failing', async () => {
    const dir = scratch();
    const path = join(dir, 'secret.txt');
    writeFileSync(path, 'first');

    let attempts = 0;
    const errors: unknown[] = [];
    const changes: string[] = [];

    track(
      watchFile(
        path,
        () => {
          attempts += 1;

          // Stands in for a partially written file: the decoder throws for a
          // state that resolves itself in milliseconds.
          return Promise.reject(new Error('unexpected end of input'));
        },
        {
          debounceMs: 5,
          maxRetries: 2,
          retryBackoffMs: 5,
          onChange: (next: string) => changes.push(next),
          onError: (error) => errors.push(error),
        },
        'first'
      )
    );

    writeFileSync(path, CANARY);
    await until(() => errors.length > 0);

    expect(attempts).toBe(3);
    expect(changes).toEqual([]);
  });

  it('recovers once the file settles', async () => {
    const dir = scratch();
    const path = join(dir, 'secret.txt');
    writeFileSync(path, 'first');

    let attempts = 0;
    const changes: string[] = [];

    track(
      watchFile(
        path,
        async () => {
          attempts += 1;

          if (attempts === 1) {
            throw new Error('unexpected end of input');
          }

          const { readFile } = await import('node:fs/promises');

          return await readFile(path, 'utf8');
        },
        {
          debounceMs: 5,
          maxRetries: 3,
          retryBackoffMs: 5,
          onChange: (next: string) => changes.push(next),
        },
        'first'
      )
    );

    writeFileSync(path, CANARY);
    await until(() => changes.length > 0);

    expect(changes[0]).toBe(CANARY);
  });

  it('notices a change through polling where fs.watch is not trusted', async () => {
    const dir = scratch();
    const path = join(dir, 'secret.txt');
    writeFileSync(path, 'first');

    const changes: string[] = [];
    const watcher = track(
      watchFile(
        path,
        async () => {
          const { readFile } = await import('node:fs/promises');

          return await readFile(path, 'utf8');
        },
        {
          mode: 'poll',
          pollIntervalMs: 10,
          debounceMs: 5,
          onChange: (next: string) => changes.push(next),
        },
        'first'
      )
    );

    expect(watcher.polling).toBe(true);

    await new Promise((resolve) => setTimeout(resolve, 20));
    writeFileSync(path, CANARY);
    await until(() => changes.length > 0);

    expect(changes[0]).toBe(CANARY);
  });

  it('stops calling back after close', async () => {
    const dir = scratch();
    const path = join(dir, 'secret.txt');
    writeFileSync(path, 'first');

    const changes: string[] = [];
    const watcher = watchFile(path, () => Promise.resolve('next'), {
      debounceMs: 5,
      onChange: (next: string) => changes.push(next),
    });

    watcher.close();
    watcher.close();
    writeFileSync(path, CANARY);
    await new Promise((resolve) => setTimeout(resolve, 60));

    expect(changes).toEqual([]);
  });
});

describe('watch modes', () => {
  it('propagates a setup failure under an explicit watch mode', () => {
    expect(() =>
      watchFile('/definitely/not/a/path', () => Promise.resolve('x'), {
        mode: 'watch',
        onChange: () => undefined,
      })
    ).toThrow();
  });

  it('falls back to polling under auto when fs.watch cannot start', () => {
    const watcher = track(
      watchFile('/definitely/not/a/path', () => Promise.resolve('x'), {
        mode: 'auto',
        pollIntervalMs: 10_000,
        onChange: () => undefined,
      })
    );

    expect(watcher.polling).toBe(true);
  });

  it('uses fs.watch under auto where the file exists', () => {
    const dir = scratch();
    const path = join(dir, 'secret.txt');
    writeFileSync(path, 'first');

    const watcher = track(
      watchFile(path, () => Promise.resolve('x'), { onChange: () => undefined })
    );

    expect(watcher.polling).toBe(false);
  });
});
