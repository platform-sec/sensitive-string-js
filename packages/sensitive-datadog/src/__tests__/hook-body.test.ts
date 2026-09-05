import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { mergeScrubPolicy, resolveScrubPolicy } from '@platform-sec/sensitive-string-scrub';
import { describe, expect, it, vi } from 'vitest';

import {
  buildManualScrubber,
  buildRequestHook,
  canEnumerateTags,
  readTags,
  type DatadogSpan,
} from '../hooks.js';
import { DATADOG_POLICY, projectHeaderPaths } from '../paths.js';

/**
 * The hook body, driven directly.
 *
 * `hooks.test.ts` and `canary.test.ts` run this against the real agent, which
 * means in a child process, where the branches are invisible to this process's
 * coverage. These are the shapes a healthy request does not produce and the
 * ones a stand-in span reaches more precisely than a real one: an unreadable
 * tag bag, a tag whose getter throws, a URL that turns out to have nothing
 * denied in it, and the write-back rule.
 */

function policy(overrides = {}) {
  const merged = mergeScrubPolicy(DATADOG_POLICY, overrides);
  const first = resolveScrubPolicy(merged);

  return resolveScrubPolicy({
    ...merged,
    denyPaths: [...(merged.denyPaths ?? []), ...projectHeaderPaths(first.denyKeys)],
  });
}

/** A span stand-in over a tag bag the caller supplies. */
function spanOver(tags: Record<string, unknown>, context?: object): DatadogSpan {
  return {
    setTag(key: string, value: unknown) {
      tags[key] = value;

      return undefined;
    },
    context: () => context ?? { getTags: () => tags },
  };
}

describe('readTags', () => {
  it('prefers getTags', () => {
    expect(readTags(spanOver({}, { getTags: () => ({ a: 1 }) }))).toEqual({ a: 1 });
  });

  it('falls back to the private field behind it', () => {
    expect(readTags(spanOver({}, { _tags: { a: 1 } }))).toEqual({ a: 1 });
  });

  it('answers null when neither is there', () => {
    expect(readTags(spanOver({}, {}))).toBeNull();
  });

  it('answers null when getTags returns something that is not a bag', () => {
    expect(readTags(spanOver({}, { getTags: () => 'no' }))).toBeNull();
  });

  it('answers null when context() throws', () => {
    const span = {
      setTag: () => undefined,
      context: () => {
        throw new Error('no');
      },
    } as unknown as DatadogSpan;

    expect(readTags(span)).toBeNull();
  });
});

describe('canEnumerateTags', () => {
  it('is the same question readTags answers', () => {
    expect(canEnumerateTags(spanOver({}, { getTags: () => ({}) }))).toBe(true);
    expect(canEnumerateTags(spanOver({}, {}))).toBe(false);
  });
});

describe('the hook over a bag it cannot read', () => {
  it('does nothing rather than throwing', () => {
    const span = spanOver({}, {});

    expect(() => buildRequestHook(policy())(span)).not.toThrow();
  });

  it('does nothing when the bag refuses enumeration', () => {
    const hostile = new Proxy(
      {},
      {
        ownKeys() {
          throw new Error('no keys');
        },
      }
    );

    expect(() =>
      buildRequestHook(policy())(spanOver({}, { getTags: () => hostile }))
    ).not.toThrow();
  });

  it('skips a tag whose getter throws and keeps scrubbing the rest', () => {
    const tags: Record<string, unknown> = {};

    Object.defineProperty(tags, 'probe.hostile', {
      enumerable: true,
      get() {
        throw new Error('no read');
      },
    });
    tags['probe.password'] = 'raw';

    buildRequestHook(policy())(spanOver(tags, { getTags: () => tags }));

    expect(tags['probe.password']).toBe('[SCRUBBED]');
  });
});

describe('the write-back rule', () => {
  it('writes only what changed', () => {
    const tags: Record<string, unknown> = { 'probe.password': 'raw', 'probe.plain': 'keep-me' };
    const written: string[] = [];

    const span: DatadogSpan = {
      setTag(key: string, value: unknown) {
        written.push(key);
        tags[key] = value;

        return undefined;
      },
      context: () => ({ getTags: () => tags }),
    };

    buildRequestHook(policy())(span);

    expect(written).toEqual(['probe.password']);
  });

  it('writes nothing at all for a span with no candidate tag', () => {
    const tags: Record<string, unknown> = { 'http.method': 'POST', 'probe.plain': 'keep-me' };
    const setTag = vi.fn();

    buildRequestHook(policy())({
      setTag,
      context: () => ({ getTags: () => tags }),
    });

    expect(setTag).not.toHaveBeenCalled();
  });

  it('does not report a span it found nothing in', () => {
    const onScrub = vi.fn();
    const tags: Record<string, unknown> = { 'http.method': 'POST' };

    buildRequestHook(policy({ onScrub }))(spanOver(tags));

    expect(onScrub).not.toHaveBeenCalled();
  });
});

describe('the URL branch', () => {
  it('rewrites the denied parameters and keeps the route', () => {
    const tags: Record<string, unknown> = {
      'http.url': 'https://api.test/v1/pay?cookie=SECRET&page=2',
    };

    buildRequestHook(policy())(spanOver(tags));

    expect(tags['http.url']).toBe('https://api.test/v1/pay?cookie=[SCRUBBED]&page=2');
  });

  it('leaves a URL with nothing denied byte for byte alone', () => {
    const url = 'https://api.test/v1/pay?page=2';
    const tags: Record<string, unknown> = { 'http.url': url, 'probe.password': 'raw' };

    buildRequestHook(policy())(spanOver(tags));

    expect(tags['http.url']).toBe(url);
  });

  it('names the replaced parameters in the report', () => {
    const onScrub = vi.fn();
    const tags: Record<string, unknown> = {
      'http.url': 'https://api.test/pay?cookie=SECRET&page=2',
    };

    buildRequestHook(policy({ onScrub }))(spanOver(tags));

    expect(onScrub.mock.calls[0]?.[0]).toMatchObject({ deniedKeys: ['cookie'] });
  });
});

describe('the marker rule', () => {
  it('keeps the marker stage 1 wrote rather than censoring over it', () => {
    // `[REDACTED:credential]` and the censor are equally safe and the marker
    // says which class stood there. The shared walk applies the same rule.
    const secret = new SensitiveString('x', 'credential');
    const tags: Record<string, unknown> = { 'probe.password': secret };

    buildRequestHook(policy())(spanOver(tags));

    expect(tags['probe.password']).toBe('[REDACTED:credential]');
  });
});

describe('the manual span scrubber', () => {
  it('scrubs a span the hooks never see', () => {
    const tags: Record<string, unknown> = { 'probe.password': 'raw' };

    buildManualScrubber(policy())(spanOver(tags));

    expect(tags['probe.password']).toBe('[SCRUBBED]');
  });

  it('skips a span a hook already scrubbed, so one span is one report', () => {
    const onScrub = vi.fn();
    const tags: Record<string, unknown> = { 'probe.password': 'raw' };
    const resolved = policy({ onScrub });
    const span = spanOver(tags);

    buildRequestHook(resolved)(span);
    buildManualScrubber(resolved)(span);

    expect(onScrub).toHaveBeenCalledTimes(1);
  });

  it('scrubs a frozen span twice rather than not at all', () => {
    // `Object.defineProperty` fails on a frozen span, so the mark does not
    // stick. Scrubbing twice is harmless; only the report doubles.
    const tags: Record<string, unknown> = { 'probe.password': 'raw' };
    const span = Object.freeze(spanOver(tags));

    expect(() => buildManualScrubber(policy())(span)).not.toThrow();
    expect(tags['probe.password']).toBe('[SCRUBBED]');
  });
});

describe('a caller hook', () => {
  it('receives every argument the agent passed', () => {
    const user = vi.fn();
    const span = spanOver({});

    buildRequestHook(policy(), user)(span, 'req', 'res');

    expect(user).toHaveBeenCalledWith(span, 'req', 'res');
  });

  it('runs even when there is no span to scrub', () => {
    const user = vi.fn();

    buildRequestHook(policy(), user)(undefined);

    expect(user).toHaveBeenCalledTimes(1);
  });
});

describe('casing, which this vendor is insensitive to', () => {
  /**
   * The mirror of the New Relic package's problem, and the reason it is not
   * one here. Every matcher on this path lowercases the subject, so a tag
   * written in camelCase matches a denylist entry written in any casing.
   */
  it.each(['probe.accessToken', 'probe.ACCESSTOKEN', 'probe.accesstoken'])('censors %s', (key) => {
    const tags: Record<string, unknown> = { [key]: 'raw' };

    buildRequestHook(policy())(spanOver(tags));

    expect(tags[key]).toBe('[SCRUBBED]');
  });

  it('censors a header tag whatever casing the header arrived in', () => {
    const tags: Record<string, unknown> = {
      'http.request.headers.Authorization': 'Bearer raw',
    };

    buildRequestHook(policy())(spanOver(tags));

    expect(tags['http.request.headers.Authorization']).toBe('[SCRUBBED]');
  });
});
