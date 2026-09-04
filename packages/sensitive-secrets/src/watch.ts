import { watch as fsWatch, statSync } from 'node:fs';
import type { FSWatcher } from 'node:fs';

/**
 * The file watcher.
 *
 * Two of the sources in this row are files that change underneath a running
 * process: a Kubernetes mounted volume, which the kubelet rewrites when the
 * Secret changes, and a SOPS document, which a deployment replaces. Both want
 * the same behaviour, so it lives here and neither provider implements it.
 *
 * A change produces a new value. Instances are immutable, and a watcher that
 * mutated one would defeat the gate every read goes through. The previous
 * instance stays valid: nothing can reach the values already handed out, so
 * after a rotation an in-flight request holding the old credential continues
 * with the old credential until the far side stops accepting it. `onChange`
 * receives the previous value so the caller can drain with it.
 */

export interface WatchOptions<T> {
  /** Called with each successfully re-read value, and the one it replaces. */
  onChange(next: T, previous: T | undefined): void;
  /**
   * Called when a re-read keeps failing past the retry budget.
   *
   * A single failure is not reported: an atomic rename and the kubelet's
   * write-then-swap both leave a moment where the file is absent or half
   * written, and a state that resolves itself in milliseconds is not an error
   * to propagate.
   */
  onError?(error: unknown): void;
  /**
   * Milliseconds to wait for the filesystem to settle before re-reading.
   *
   * One logical change produces more than one filesystem event, and a
   * re-decrypt per event is wasteful for an encrypted document and racy for
   * anything.
   */
  debounceMs?: number;
  /**
   * How to notice a change.
   *
   * `fs.watch` is unreliable on some platforms and container filesystems, so
   * polling is the fallback and is the right default where the source is a bind
   * mount. `'auto'` uses `fs.watch` and falls back to polling if it errors.
   */
  mode?: 'watch' | 'poll' | 'auto';
  /** Poll interval in milliseconds, used by `'poll'` and by a fallback from `'auto'`. */
  pollIntervalMs?: number;
  /** How many times a failed re-read is retried before `onError` is called. */
  maxRetries?: number;
  /** Base backoff in milliseconds, doubled per retry. */
  retryBackoffMs?: number;
}

export interface FileWatcher {
  /** Stop watching. Safe to call more than once. */
  close(): void;
  /** Whether polling is in use, so a README's claim about the mode can be checked. */
  readonly polling: boolean;
}

const DEFAULTS = {
  debounceMs: 100,
  pollIntervalMs: 5_000,
  maxRetries: 5,
  retryBackoffMs: 50,
};

/** A fingerprint that changes when the file does, without reading its contents. */
function fingerprint(path: string): string | undefined {
  try {
    const stats = statSync(path);

    return `${stats.mtimeMs}:${stats.size}:${String(stats.ino)}`;
  } catch {
    return undefined;
  }
}

/**
 * Re-read a file whenever it changes, keeping the previous value in service
 * while a change is still landing.
 *
 * @param path - The file to watch.
 * @param read - Produces the value. It decodes, classifies and wraps, so a
 *   partially written file surfaces here as a decode failure rather than a value.
 * @param initial - The value the first `onChange` compares against, normally
 *   the one the caller already loaded.
 */
export function watchFile<T>(
  path: string,
  read: () => Promise<T>,
  options: WatchOptions<T>,
  initial?: T
): FileWatcher {
  const debounceMs = options.debounceMs ?? DEFAULTS.debounceMs;
  const pollIntervalMs = options.pollIntervalMs ?? DEFAULTS.pollIntervalMs;
  const maxRetries = options.maxRetries ?? DEFAULTS.maxRetries;
  const retryBackoffMs = options.retryBackoffMs ?? DEFAULTS.retryBackoffMs;
  const mode = options.mode ?? 'auto';

  let current = initial;
  let closed = false;
  let polling = mode === 'poll';
  let pending: NodeJS.Timeout | undefined;
  let watcher: FSWatcher | undefined;
  let poller: NodeJS.Timeout | undefined;
  let seen = fingerprint(path);

  function clearPending(): void {
    if (pending !== undefined) {
      clearTimeout(pending);
      pending = undefined;
    }
  }

  async function attempt(remaining: number, delay: number): Promise<void> {
    if (closed) {
      return;
    }

    try {
      const next = await read();

      if (closed) {
        return;
      }

      const previous = current;
      current = next;
      seen = fingerprint(path);
      options.onChange(next, previous);
    } catch (error) {
      if (closed) {
        return;
      }

      // A partially written file is a decode failure, not a value. Keep serving
      // the previous instance and try again rather than propagating an error
      // for a state that resolves itself in milliseconds.
      if (remaining <= 0) {
        options.onError?.(error);

        return;
      }

      const timer = setTimeout(() => {
        void attempt(remaining - 1, delay * 2);
      }, delay);
      timer.unref?.();
    }
  }

  function schedule(): void {
    clearPending();
    pending = setTimeout(() => {
      pending = undefined;
      void attempt(maxRetries, retryBackoffMs);
    }, debounceMs);
    pending.unref?.();
  }

  function startPolling(): void {
    polling = true;
    poller = setInterval(() => {
      const now = fingerprint(path);

      if (now !== seen) {
        seen = now;
        schedule();
      }
    }, pollIntervalMs);
    poller.unref?.();
  }

  if (mode === 'poll') {
    startPolling();
  } else {
    try {
      watcher = fsWatch(path, () => {
        schedule();
      });
      watcher.on('error', () => {
        watcher?.close();
        watcher = undefined;

        if (mode === 'auto' && !closed) {
          startPolling();
        }
      });
    } catch (error) {
      if (mode === 'auto') {
        startPolling();
      } else {
        throw error;
      }
    }
  }

  return {
    get polling(): boolean {
      return polling;
    },
    close(): void {
      closed = true;
      clearPending();
      watcher?.close();
      watcher = undefined;

      if (poller !== undefined) {
        clearInterval(poller);
        poller = undefined;
      }
    },
  };
}
