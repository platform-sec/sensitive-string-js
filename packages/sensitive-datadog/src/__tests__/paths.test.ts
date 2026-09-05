import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { mergeScrubPolicy, resolveScrubPolicy } from '@platform-sec/sensitive-string-scrub';
import { describe, expect, it } from 'vitest';

import {
  DATADOG_POLICY,
  DATADOG_URL_KEYS,
  REQUEST_HEADER_PREFIX,
  RESPONSE_HEADER_PREFIX,
  classifyTag,
  isCandidate,
  isReservedTag,
  projectHeaderPaths,
  tagKeyName,
} from '../paths.js';

/**
 * The tag-level matcher.
 *
 * A tag bag is flat, so `probe.password` is one key with a dot in it rather
 * than a path of two segments, and the shared denylist, written for nested
 * payloads, tests exactly that string and finds nothing. This file is about
 * the translation that closes that gap, and about the fast path that keeps a
 * hook running on every span of every request from allocating when there is
 * nothing to do.
 */

function policy(overrides = {}) {
  const merged = mergeScrubPolicy(DATADOG_POLICY, overrides);
  const first = resolveScrubPolicy(merged);

  return resolveScrubPolicy({
    ...merged,
    denyPaths: [...(merged.denyPaths ?? []), ...projectHeaderPaths(first.denyKeys)],
  });
}

const resolved = policy();

describe('tagKeyName', () => {
  it('is the last dotted segment', () => {
    expect(tagKeyName('http.request.headers.authorization')).toBe('authorization');
    expect(tagKeyName('probe.password')).toBe('password');
  });

  it('is the whole key when there is no dot', () => {
    expect(tagKeyName('password')).toBe('password');
  });
});

describe('classifyTag', () => {
  it.each([
    `${REQUEST_HEADER_PREFIX}authorization`,
    `${REQUEST_HEADER_PREFIX}cookie`,
    `${RESPONSE_HEADER_PREFIX}set-cookie`,
    'probe.password',
    'password',
    'probe.api_key',
  ])('denies %s', (key) => {
    expect(classifyTag(key, resolved)).toBe('deny');
  });

  it.each(['http.url', 'probe.url', 'url.full', 'http.target'])(
    'treats %s as a URL position',
    (key) => {
      expect(classifyTag(key, resolved)).toBe('url');
    }
  );

  it.each(['http.method', 'http.status_code', 'probe.plain', `${REQUEST_HEADER_PREFIX}x-trace`])(
    'leaves %s to the walk',
    (key) => {
      expect(classifyTag(key, resolved)).toBe('walk');
    }
  );

  it('matches a header name whatever its casing', () => {
    expect(classifyTag(`${REQUEST_HEADER_PREFIX}Authorization`, resolved)).toBe('deny');
  });

  it('denies a whole path a plugin writes as one blob', () => {
    expect(classifyTag('elasticsearch.body', resolved)).toBe('deny');
  });

  it('takes a caller denyKeys entry containing a dot', () => {
    expect(classifyTag('my.custom.tag', policy({ denyKeys: ['my.custom.tag'] }))).toBe('deny');
  });

  it('honours allowKeys', () => {
    const allowed = policy({
      allowKeys: [{ key: 'cookie', reason: 'opaque routing hint on this service' }],
    });

    expect(classifyTag(`${REQUEST_HEADER_PREFIX}cookie`, allowed)).toBe('walk');
  });
});

describe('projectHeaderPaths', () => {
  it('covers a header name that itself contains a dot, which the last segment cannot', () => {
    const withDot = policy({ denyKeys: ['x-foo.bar'] });

    expect(tagKeyName(`${REQUEST_HEADER_PREFIX}x-foo.bar`)).toBe('bar');
    expect(classifyTag(`${REQUEST_HEADER_PREFIX}x-foo.bar`, withDot)).toBe('deny');
  });

  it('emits both header directions for every key', () => {
    expect(projectHeaderPaths(['authorization'])).toEqual([
      `${REQUEST_HEADER_PREFIX}authorization`,
      `${RESPONSE_HEADER_PREFIX}authorization`,
    ]);
  });
});

describe('isReservedTag', () => {
  it.each(['_dd.p.tid', '_dd.rc.client_id', 'service', 'service.name', 'resource.name', 'error'])(
    'leaves %s to the agent',
    (key) => {
      expect(isReservedTag(key)).toBe(true);
    }
  );

  it('does not reserve an application tag', () => {
    expect(isReservedTag('probe.password')).toBe(false);
  });

  it('does not reserve an error message, which is application data', () => {
    expect(isReservedTag('error.message')).toBe(false);
  });
});

describe('isCandidate, the fast path', () => {
  it('skips a reserved tag whatever its value', () => {
    expect(isCandidate('_dd.p.tid', { anything: 1 }, resolved)).toBe(false);
  });

  it('takes any structure, since only a structure can be a wrapped value', () => {
    expect(isCandidate('probe.anything', new SensitiveString('x', 'credential'), resolved)).toBe(
      true
    );
    expect(isCandidate('probe.anything', { nested: 1 }, resolved)).toBe(true);
  });

  it('takes a denied key', () => {
    expect(isCandidate('probe.password', 'x', resolved)).toBe(true);
  });

  it('takes a URL only when it actually carries something denied', () => {
    expect(isCandidate('http.url', 'https://api.test/pay?token=x', resolved)).toBe(true);
    expect(isCandidate('http.url', 'https://api.test/pay?page=2', resolved)).toBe(false);
  });

  it('skips a plain string when no value recognizer is on', () => {
    expect(isCandidate('probe.plain', 'keep-me', resolved)).toBe(false);
  });

  it('takes a plain string once a caller opts into value recognizers', () => {
    expect(isCandidate('probe.plain', 'keep-me', policy({ denyValues: ['jwt'] }))).toBe(true);
  });

  it('skips a number and a boolean', () => {
    expect(isCandidate('probe.count', 3, resolved)).toBe(false);
    expect(isCandidate('probe.ok', true, resolved)).toBe(false);
  });
});

describe('DATADOG_URL_KEYS', () => {
  it('carries the OpenTelemetry spellings a bridged span uses', () => {
    expect(DATADOG_URL_KEYS).toContain('url.full');
    expect(DATADOG_URL_KEYS).toContain('url.query');
  });

  it("carries the agent's own name", () => {
    expect(DATADOG_URL_KEYS).toContain('http.url');
  });
});
