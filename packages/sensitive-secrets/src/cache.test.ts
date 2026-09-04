import { describe, it, expect, vi } from 'vitest';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import type { SensitivityClass } from '@platform-sec/sensitive-string-core';

import { SecretCache, cacheKey, refPrefix } from './cache.js';
import type { SecretLoadEvent } from './types.js';
import { FakeSecretSource } from './__tests__/fake-source.js';

type AnySensitive = SensitiveString<SensitivityClass>;

const CANARY = 'LEAKED_SECRET_abc123xyz';

function instance(value = CANARY, ttl?: number): AnySensitive {
  return new SensitiveString(value, 'credential', 'test', ttl === undefined ? undefined : { ttl });
}

describe('cacheKey', () => {
  it('separates a pinned version from an alias', () => {
    expect(cacheKey({ path: 'a', version: 'latest' }, 's')).not.toBe(
      cacheKey({ path: 'a', version: '7' }, 's')
    );
  });

  it('separates two shapes of call for one ref', () => {
    expect(cacheKey({ path: 'a' }, 'get')).not.toBe(cacheKey({ path: 'a' }, 'json'));
  });

  it('cannot be collided by a path that ends in the separator character', () => {
    expect(cacheKey({ path: 'a', version: 'b' }, '')).not.toBe(cacheKey({ path: 'a b' }, ''));
  });

  it('shares a prefix with every shape for one ref', () => {
    expect(cacheKey({ path: 'a' }, 'get').startsWith(refPrefix({ path: 'a' }))).toBe(true);
    expect(cacheKey({ path: 'a' }, 'json').startsWith(refPrefix({ path: 'a' }))).toBe(true);
  });
});

describe('SecretCache', () => {
  it('serves a second read without running the loader', async () => {
    const cache = new SecretCache({ ttl: 60_000 });
    const loader = vi.fn(() => Promise.resolve(instance()));

    await cache.load('k', loader, (value) => [value]);
    await cache.load('k', loader, (value) => [value]);

    expect(loader).toHaveBeenCalledTimes(1);
  });

  it('is disabled by a ttl of zero', async () => {
    const cache = new SecretCache({ ttl: 0 });
    const loader = vi.fn(() => Promise.resolve(instance()));

    await cache.load('k', loader, (value) => [value]);
    await cache.load('k', loader, (value) => [value]);

    expect(cache.enabled).toBe(false);
    expect(loader).toHaveBeenCalledTimes(2);
  });

  it('runs one loader for concurrent reads of one key', async () => {
    const cache = new SecretCache({ ttl: 60_000 });
    const loader = vi.fn(
      () => new Promise<AnySensitive>((resolve) => setTimeout(() => resolve(instance()), 10))
    );

    const results = await Promise.all(
      Array.from({ length: 50 }, () => cache.load('k', loader, (value) => [value]))
    );

    expect(loader).toHaveBeenCalledTimes(1);
    // One provider call and one instance, not fifty of each.
    expect(new Set(results).size).toBe(1);
  });

  it('caps entry lifetime by what the entry holds', async () => {
    vi.useFakeTimers();

    try {
      const cache = new SecretCache({ ttl: 60_000 });
      const loader = vi.fn(() => Promise.resolve(instance(CANARY, 1_000)));

      await cache.load('k', loader, (value) => [value]);
      vi.advanceTimersByTime(1_500);
      await cache.load('k', loader, (value) => [value]);

      expect(loader).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it('does not serve an entry holding an expired value', async () => {
    const expired = new SensitiveString(CANARY, 'credential', 'test', {
      expiresAt: new Date(Date.now() - 1),
    });
    const cache = new SecretCache({ ttl: 60_000 });
    const loader = vi.fn(() => Promise.resolve(expired));

    await cache.load('k', loader, (value) => [value]);
    await cache.load('k', loader, (value) => [value]);

    expect(loader).toHaveBeenCalledTimes(2);
  });

  it('does not cache a failure', async () => {
    const cache = new SecretCache({ ttl: 60_000 });
    const loader = vi
      .fn<() => Promise<AnySensitive>>()
      .mockRejectedValueOnce(new Error('provider is down'))
      .mockResolvedValueOnce(instance());

    await expect(cache.load('k', loader, (value) => [value])).rejects.toThrow('provider is down');
    await expect(cache.load('k', loader, (value) => [value])).resolves.toBeInstanceOf(
      SensitiveString
    );
    expect(loader).toHaveBeenCalledTimes(2);
  });

  describe('staleOnError', () => {
    it('is off by default, so a provider outage stays visible', async () => {
      vi.useFakeTimers();

      try {
        const cache = new SecretCache({ ttl: 1_000 });
        const loader = vi
          .fn<() => Promise<AnySensitive>>()
          .mockResolvedValueOnce(instance())
          .mockRejectedValue(new Error('provider is down'));

        await cache.load('k', loader, (value) => [value]);
        vi.advanceTimersByTime(1_500);

        await expect(cache.load('k', loader, (value) => [value])).rejects.toThrow(
          'provider is down'
        );
      } finally {
        vi.useRealTimers();
      }
    });

    it('serves a stale entry whose value has not expired', async () => {
      vi.useFakeTimers();

      try {
        const cache = new SecretCache({ ttl: 1_000, staleOnError: true });
        const held = instance(CANARY, 60_000);
        const loader = vi
          .fn<() => Promise<AnySensitive>>()
          .mockResolvedValueOnce(held)
          .mockRejectedValue(new Error('provider is down'));

        await cache.load('k', loader, (value) => [value]);
        vi.advanceTimersByTime(1_500);

        await expect(cache.load('k', loader, (value) => [value])).resolves.toBe(held);
        expect(cache.servedStale('k')).toBe(true);
      } finally {
        vi.useRealTimers();
      }
    });

    it('does not serve a stale entry whose value has expired', async () => {
      vi.useFakeTimers();

      try {
        const cache = new SecretCache({ ttl: 1_000, staleOnError: true });
        const loader = vi
          .fn<() => Promise<AnySensitive>>()
          .mockResolvedValueOnce(instance(CANARY, 1_200))
          .mockRejectedValue(new Error('provider is down'));

        await cache.load('k', loader, (value) => [value]);
        vi.advanceTimersByTime(1_500);

        await expect(cache.load('k', loader, (value) => [value])).rejects.toThrow(
          'provider is down'
        );
      } finally {
        vi.useRealTimers();
      }
    });
  });

  it('evicts every shape for a ref through the prefix', async () => {
    const cache = new SecretCache({ ttl: 60_000 });
    const loader = vi.fn(() => Promise.resolve(instance()));

    await cache.load(cacheKey({ path: 'a' }, 'get'), loader, (value) => [value]);
    await cache.load(cacheKey({ path: 'a' }, 'json'), loader, (value) => [value]);
    cache.deletePrefix(refPrefix({ path: 'a' }));
    await cache.load(cacheKey({ path: 'a' }, 'get'), loader, (value) => [value]);

    expect(loader).toHaveBeenCalledTimes(3);
  });

  it('holds instances rather than raw strings', async () => {
    const cache = new SecretCache({ ttl: 60_000 });

    await cache.load(
      'k',
      () => Promise.resolve(instance()),
      (value) => [value]
    );
    const served = await cache.load(
      'k',
      () => Promise.resolve(instance()),
      (value) => [value]
    );

    expect(served).toBeInstanceOf(SensitiveString);
    expect(String(served)).not.toContain(CANARY);
  });
});

describe('the cache under a source', () => {
  it('makes one provider call for fifty concurrent gets', async () => {
    const source = FakeSecretSource.of(
      { 'prod/db': { payload: { kind: 'string', value: CANARY } } },
      {},
      5
    );

    const records = await Promise.all(Array.from({ length: 50 }, () => source.get('prod/db')));

    expect(source.calls).toHaveLength(1);
    expect(new Set(records.map((record) => record.value)).size).toBe(1);
  });

  it('does not serve a value past its own deadline', async () => {
    const source = FakeSecretSource.of({
      'prod/db': { payload: { kind: 'string', value: CANARY }, lifetime: { ttl: 20 } },
    });

    const first = await source.get('prod/db');
    await new Promise((resolve) => setTimeout(resolve, 40));
    const second = await source.get('prod/db');

    expect(first.value.isExpired()).toBe(true);
    expect(second.value.isExpired()).toBe(false);
    expect(source.calls).toHaveLength(2);
  });

  it('reports a served-stale read as cached in the audit trail', async () => {
    const events: SecretLoadEvent[] = [];
    const source = FakeSecretSource.of(
      { 'prod/db': { payload: { kind: 'string', value: CANARY }, lifetime: { ttl: 60_000 } } },
      { onLoad: (event) => events.push(event), cache: { ttl: 20, staleOnError: true } }
    );

    await source.get('prod/db');
    source.set('prod/db', new Error('provider is down'));
    await new Promise((resolve) => setTimeout(resolve, 40));
    await source.get('prod/db');

    expect(events.map((event) => event.cached)).toEqual([false, true]);
  });
});
