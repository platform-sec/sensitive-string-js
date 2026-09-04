import Rollbar from 'rollbar';
import { describe, expect, it } from 'vitest';
import {
  DEFAULT_DENY_KEYS,
  DEFAULT_DENY_PATHS,
  denied,
  isUrlPosition,
  pathDenied,
  scrubUrl,
} from './deny.js';
import { resolveScrubPolicy } from './policy.js';

const policy = resolveScrubPolicy();
const CANARY = 'LEAKED_SECRET_deny_4f1a';

describe('DEFAULT_DENY_KEYS', () => {
  // TEST-SCRUB-DENY-SUPERSET
  it('is a superset of the lists the installed rollbar actually ships', () => {
    // Reproduced rather than imported so the Sentry and Bugsnag packages do
    // not depend on a Rollbar install. This is what keeps the reproduction
    // from going stale: a vendor adding a name fails here.
    const client = new Rollbar({
      accessToken: 'x'.repeat(32),
      captureUncaught: false,
      captureUnhandledRejections: false,
    });

    const shipped = client.options as unknown as {
      scrubFields: string[];
      scrubHeaders: string[];
    };

    const covered = new Set([
      ...DEFAULT_DENY_KEYS.map((key) => key.toLowerCase()),
      ...DEFAULT_DENY_PATHS.map((path) => path.toLowerCase()),
    ]);

    for (const name of [...shipped.scrubFields, ...shipped.scrubHeaders]) {
      expect(covered.has(name.toLowerCase()), `rollbar ships '${name}' and we do not`).toBe(true);
    }
  });

  it('carries the three names the measured leak turns on', () => {
    // authorization and cookie headers, and a `token` query parameter.
    // Goal 1 of the design is that these close with no configuration.
    const keys = new Set(DEFAULT_DENY_KEYS.map((key) => key.toLowerCase()));

    expect(keys.has('authorization')).toBe(true);
    expect(keys.has('cookie')).toBe(true);
    expect(keys.has('token')).toBe(true);
  });

  it('holds no duplicates once lowered', () => {
    const lowered = DEFAULT_DENY_KEYS.map((key) => key.toLowerCase());

    expect(new Set(lowered).size).toBe(lowered.length);
  });
});

describe('key matching', () => {
  it('matches case-insensitively', () => {
    expect(
      denied('Authorization', 'headers.Authorization', policy.denyKeys, policy.denyPaths)
    ).toBe(true);
    expect(denied('AUTHORIZATION', 'AUTHORIZATION', policy.denyKeys, policy.denyPaths)).toBe(true);
  });

  it('matches at any depth', () => {
    expect(denied('token', 'a.b.c.d.e.token', policy.denyKeys, policy.denyPaths)).toBe(true);
  });

  it('does not match a key that merely contains a denied name', () => {
    // Substring matching would censor `tokenCount` and `password_hint`, and a
    // scrubber that hides values an engineer needed is one they turn off.
    expect(denied('tokenCount', 'tokenCount', policy.denyKeys, policy.denyPaths)).toBe(false);
    expect(denied('authorization_scheme', 'x', policy.denyKeys, policy.denyPaths)).toBe(false);
  });
});

describe('path matching', () => {
  it('matches a whole path and not a segment of one', () => {
    expect(pathDenied('request.cookies', policy.denyPaths)).toBe(true);
    // `request.cookie` is denied as a path. A `cookies` key three levels into
    // a body is a different thing and is left to the key list.
    expect(pathDenied('extra.request.cookies', policy.denyPaths)).toBe(false);
  });

  it('matches case-insensitively', () => {
    expect(pathDenied('Request.Cookies', policy.denyPaths)).toBe(true);
  });

  it('treats a * segment as exactly one segment', () => {
    const wildcarded = resolveScrubPolicy({ denyPaths: ['breadcrumbs.*.data.card'] });

    expect(pathDenied('breadcrumbs.0.data.card', wildcarded.denyPaths)).toBe(true);
    expect(pathDenied('breadcrumbs.12.data.card', wildcarded.denyPaths)).toBe(true);
    expect(pathDenied('breadcrumbs.data.card', wildcarded.denyPaths)).toBe(false);
    expect(pathDenied('breadcrumbs.0.1.data.card', wildcarded.denyPaths)).toBe(false);
  });

  it('reports no match when nothing is denied', () => {
    expect(pathDenied('anything', new Set())).toBe(false);
  });
});

describe('isUrlPosition', () => {
  const urls = resolveScrubPolicy({ urlKeys: ['request.url', 'url', 'http.url'] });

  it('matches a whole dotted path', () => {
    expect(isUrlPosition('url', 'request.url', urls.urlKeys)).toBe(true);
  });

  it('matches a terminal key name at any depth', () => {
    expect(isUrlPosition('url', 'breadcrumbs.0.data.url', urls.urlKeys)).toBe(true);
  });

  it('matches a key that itself contains a dot', () => {
    // `http.url` is one span-attribute key, not a path of two segments.
    expect(isUrlPosition('http.url', 'data.http.url', urls.urlKeys)).toBe(true);
  });

  it('does not match an unrelated position', () => {
    expect(isUrlPosition('href', 'request.href', urls.urlKeys)).toBe(false);
  });
});

describe('scrubUrl', () => {
  it('replaces a denied query parameter and keeps the route', () => {
    const result = scrubUrl(
      `https://api.example.com/pay/42?token=${CANARY}&page=2`,
      policy.denyKeys,
      '[SCRUBBED]'
    );

    expect(result).not.toBeNull();
    expect(result?.value).toContain('/pay/42');
    expect(result?.value).toContain('page=2');
    expect(result?.value).not.toContain(CANARY);
    expect(result?.replaced).toEqual(['token']);
  });

  it('handles a bare query string, which is what request.query_string holds', () => {
    const result = scrubUrl(`token=${CANARY}&page=2`, policy.denyKeys, '[SCRUBBED]');

    expect(result?.value).not.toContain(CANARY);
    expect(result?.value).toContain('page=2');
  });

  it('keeps a leading question mark when the subject had one', () => {
    const result = scrubUrl(`?token=${CANARY}`, policy.denyKeys, '[SCRUBBED]');

    expect(result?.value.startsWith('?')).toBe(true);
  });

  it('replaces a password in the userinfo component', () => {
    // No key name names it, and a URL carrying one carries a credential by
    // construction.
    const result = scrubUrl(`https://user:${CANARY}@example.com/x`, policy.denyKeys, '[SCRUBBED]');

    expect(result?.value).not.toContain(CANARY);
    expect(result?.value).toContain('user');
    expect(result?.replaced).toContain('url.password');
  });

  it('replaces every occurrence of a repeated denied parameter', () => {
    const result = scrubUrl(
      `https://x.test/?token=${CANARY}&token=${CANARY}`,
      policy.denyKeys,
      '[S]'
    );

    expect(result?.value).not.toContain(CANARY);
  });

  it('leaves a string alone when it is neither a URL nor a query string with a denied name', () => {
    // `URLSearchParams` accepts anything, so an arbitrary string parses as one
    // empty-valued key. Rewriting that would corrupt it.
    expect(scrubUrl('not a url at all', policy.denyKeys, '[S]')).toBeNull();
    expect(scrubUrl('', policy.denyKeys, '[S]')).toBeNull();
  });

  it('leaves a URL with no denied parameter otherwise intact', () => {
    const result = scrubUrl('https://api.example.com/pay?page=2', policy.denyKeys, '[S]');

    expect(result?.replaced).toEqual([]);
    expect(result?.value).toContain('page=2');
  });
});
