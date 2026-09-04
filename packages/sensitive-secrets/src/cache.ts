import type { SensitivityClass, SensitiveString } from '@platform-sec/sensitive-string-core';

import type { CacheOptions, SecretRef } from './types.js';

/** Any wrapped value, whatever its class. */
type AnySensitive = SensitiveString<SensitivityClass>;

/**
 * The instance cache.
 *
 * It holds `SensitiveString` instances, never raw strings, which is what makes
 * a cache in this library safe to hold and safe to inspect: an entry that
 * reaches a log line renders as markers.
 */

/** What a cached load produced, and everything needed to decide whether to serve it. */
interface Entry {
  readonly value: unknown;
  /** Wall clock deadline for this entry, already aligned with what it holds. */
  readonly expiresAt: number;
  /** The instances the entry holds, so expiry can be checked before serving. */
  readonly instances: readonly AnySensitive[];
}

/**
 * The key an entry is filed under.
 *
 * The requested version is part of it, so `latest` and a pinned version are
 * different entries and a pin never serves whatever `latest` last resolved to.
 * The separator is NUL, which no provider accepts in a path, so a path ending
 * in the separator cannot collide with a version.
 */
export function refPrefix(ref: SecretRef): string {
  return `${ref.path}\u0000${ref.version ?? ''}\u0000`;
}

/**
 * The full key, which is the ref plus the shape of the call that produced the
 * entry.
 *
 * Two reads of one path under different classifications produce differently
 * wrapped instances, and serving one for the other would hand back a value
 * classified by a spec the caller never wrote. The shape half keeps them apart;
 * `refPrefix` is what a refresh evicts, so it takes out every shape at once.
 */
export function cacheKey(ref: SecretRef, shape: string): string {
  return refPrefix(ref) + shape;
}

const DEFAULT_TTL = 60_000;

export class SecretCache {
  readonly #entries = new Map<string, Entry>();
  readonly #inFlight = new Map<string, Promise<unknown>>();
  readonly #ttl: number;
  readonly #staleOnError: boolean;

  constructor(options: CacheOptions = {}) {
    this.#ttl = options.ttl ?? DEFAULT_TTL;
    this.#staleOnError = options.staleOnError ?? false;
  }

  get enabled(): boolean {
    return this.#ttl > 0;
  }

  /** Whether a live entry exists, without serving it. */
  has(key: string): boolean {
    return this.#live(key) !== undefined;
  }

  /**
   * Serve a cached value, or run the loader.
   *
   * Concurrent calls for one uncached key share a single loader run, so a cold
   * start with fifty callers makes one provider call and produces one instance
   * rather than fifty. Failures are not cached and the in-flight entry is
   * cleared, so the next caller retries rather than inheriting a rejection.
   *
   * @param instances - Pulls the `SensitiveString` instances out of a loaded
   *   value, so entry lifetime can be capped by what the entry holds.
   */
  async load<V>(
    key: string,
    loader: () => Promise<V>,
    instances: (value: V) => readonly AnySensitive[]
  ): Promise<V> {
    if (!this.enabled) {
      return loader();
    }

    const live = this.#live(key);

    if (live !== undefined) {
      return live.value as V;
    }

    const pending = this.#inFlight.get(key);

    if (pending !== undefined) {
      return pending as Promise<V>;
    }

    const run = loader()
      .then((value) => {
        this.#store(key, value, instances(value));

        return value;
      })
      .catch((error: unknown) => {
        const stale = this.#stale(key);

        if (this.#staleOnError && stale !== undefined) {
          return stale.value as V;
        }

        // Neither the failure nor the provider's error object is retained: an
        // SDK error may hold response data, and a cached failure outlives the
        // outage that caused it.
        throw error;
      })
      .finally(() => {
        this.#inFlight.delete(key);
      });

    this.#inFlight.set(key, run);

    return run;
  }

  /**
   * Whether the entry filed for this ref is past its own deadline.
   *
   * Read after a `load` that resolved, to tell a served-stale result from a
   * fresh one, so the load event can say `cached: true` and a provider outage
   * stays visible in the audit trail.
   */
  servedStale(key: string): boolean {
    const entry = this.#entries.get(key);

    return entry !== undefined && entry.expiresAt <= Date.now();
  }

  /** Evict every entry for a ref, whatever shape of call produced it. */
  deletePrefix(prefix: string): void {
    for (const key of [...this.#entries.keys()]) {
      if (key.startsWith(prefix)) {
        this.#entries.delete(key);
      }
    }

    for (const key of [...this.#inFlight.keys()]) {
      if (key.startsWith(prefix)) {
        this.#inFlight.delete(key);
      }
    }
  }

  clear(): void {
    this.#entries.clear();
    this.#inFlight.clear();
  }

  #store(key: string, value: unknown, instances: readonly AnySensitive[]): void {
    // Entry lifetime is the shorter of the configured cache TTL and the
    // shortest remaining lifetime of what it holds. A cache must not outlive
    // what it holds.
    const now = Date.now();
    let expiresAt = now + this.#ttl;

    for (const instance of instances) {
      const remaining = instance.ttlRemaining();

      if (remaining !== undefined) {
        expiresAt = Math.min(expiresAt, now + remaining);
      }
    }

    this.#entries.set(key, { value, expiresAt, instances });
  }

  /** An entry that may be served: not past its own deadline and holding nothing expired. */
  #live(key: string): Entry | undefined {
    const entry = this.#entries.get(key);

    if (entry === undefined) {
      return undefined;
    }

    if (entry.expiresAt <= Date.now()) {
      return undefined;
    }

    // Core's gate would throw on the eventual reveal anyway. Checking here
    // means the caller gets a fresh value rather than a thrown one.
    if (entry.instances.some((instance) => instance.isExpired())) {
      this.#entries.delete(key);

      return undefined;
    }

    return entry;
  }

  /**
   * An entry whose own deadline has passed but whose values are still live.
   *
   * This is the only sanctioned staleness, and serving it is opt-in through
   * `staleOnError`. Defaulting it on would make a provider outage invisible.
   */
  #stale(key: string): Entry | undefined {
    const entry = this.#entries.get(key);

    if (entry === undefined) {
      return undefined;
    }

    if (entry.instances.some((instance) => instance.isExpired())) {
      this.#entries.delete(key);

      return undefined;
    }

    return entry;
  }
}
