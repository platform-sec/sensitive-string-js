import { describe, expect, it } from 'vitest';

import {
  InsecureTransportError,
  RedirectHostNotAllowedError,
  TooManyRedirectsError,
} from './errors.js';
import {
  assertHopAllowed,
  assertTransport,
  hostAllowed,
  isLoopback,
  isRedirect,
  redirectMethod,
  resolveRedirectPolicy,
  headersWithout,
  isCrossOrigin,
} from './redirect.js';

describe('assertTransport', () => {
  it('allows https, always', () => {
    expect(() => assertTransport(new URL('https://api.example.com/x'), true, false)).not.toThrow();
  });

  it('allows plaintext when no credential is in the request', () => {
    expect(() => assertTransport(new URL('http://api.example.com/x'), false, false)).not.toThrow();
  });

  it('refuses a credential over plaintext to a non-loopback host', () => {
    expect(() => assertTransport(new URL('http://api.example.com/x'), true, false)).toThrow(
      InsecureTransportError
    );
  });

  it('names the URL without its query string', () => {
    try {
      assertTransport(new URL('http://api.example.com/x?token=abc'), true, false);
      expect.unreachable();
    } catch (error) {
      expect((error as InsecureTransportError).message).not.toContain('token=abc');
      expect((error as InsecureTransportError).url).toBe('http://api.example.com/x');
    }
  });

  it('allows loopback, where plaintext is a sidecar rather than a mistake', () => {
    for (const host of ['localhost', '127.0.0.1', '127.0.0.5', '[::1]']) {
      expect(() => assertTransport(new URL(`http://${host}:8080/x`), true, false)).not.toThrow();
    }
  });

  it('allows the opt-out, which is named to be unpleasant to type', () => {
    expect(() => assertTransport(new URL('http://api.example.com/x'), true, true)).not.toThrow();
  });
});

describe('resolveRedirectPolicy', () => {
  it('leaves the client alone when every credential is in a header the platform strips', () => {
    expect(resolveRedirectPolicy(undefined, false)).toBe('client');
  });

  it('refuses redirects by default once a credential sits outside that set', () => {
    expect(resolveRedirectPolicy(undefined, true)).toBe(false);
  });

  it('lets an explicit list win either way', () => {
    expect(resolveRedirectPolicy(['a.example.com'], true)).toEqual(['a.example.com']);
    expect(resolveRedirectPolicy(false, false)).toBe(false);
  });
});

describe('assertHopAllowed', () => {
  const list = ['api.example.com'];

  it('accepts an in-list host, by host and by hostname', () => {
    expect(() => assertHopAllowed(new URL('https://api.example.com/x'), 1, list, 5)).not.toThrow();
    expect(() =>
      assertHopAllowed(new URL('https://api.example.com:443/x'), 1, ['api.example.com'], 5)
    ).not.toThrow();
  });

  it('refuses an out-of-list host and names the hop', () => {
    try {
      assertHopAllowed(new URL('https://evil.example.net/x'), 3, list, 5);
      expect.unreachable();
    } catch (error) {
      expect(error).toBeInstanceOf(RedirectHostNotAllowedError);
      expect((error as RedirectHostNotAllowedError).hop).toBe(3);
      expect((error as RedirectHostNotAllowedError).host).toBe('evil.example.net');
    }
  });

  it('refuses every hop when the policy is false, and explains the Fetch rule', () => {
    expect(() => assertHopAllowed(new URL('https://api.example.com/x'), 1, false, 5)).toThrow(
      /Fetch specification's stripping set/
    );
  });

  it('refuses past the hop budget', () => {
    expect(() => assertHopAllowed(new URL('https://api.example.com/x'), 6, list, 5)).toThrow(
      TooManyRedirectsError
    );
  });
});

describe('hop mechanics', () => {
  it('recognizes the redirect statuses clients follow', () => {
    expect([301, 302, 303, 307, 308].every(isRedirect)).toBe(true);
    expect(isRedirect(200)).toBe(false);
    expect(isRedirect(304)).toBe(false);
  });

  it('rewrites the method the way the Fetch specification requires', () => {
    expect(redirectMethod(303, 'POST')).toEqual({ method: 'GET', keepBody: false });
    expect(redirectMethod(302, 'POST')).toEqual({ method: 'GET', keepBody: false });
    expect(redirectMethod(302, 'GET')).toEqual({ method: 'GET', keepBody: true });
    expect(redirectMethod(307, 'POST')).toEqual({ method: 'POST', keepBody: true });
    expect(redirectMethod(308, 'PUT')).toEqual({ method: 'PUT', keepBody: true });
  });

  it('matches hosts case-insensitively', () => {
    expect(hostAllowed(new URL('https://API.Example.com/x'), ['api.example.com'])).toBe(true);
    expect(hostAllowed(new URL('https://api.example.com.evil.net/x'), ['api.example.com'])).toBe(
      false
    );
  });

  it('knows loopback from everything else', () => {
    expect(isLoopback('127.0.0.1')).toBe(true);
    expect(isLoopback('::1')).toBe(true);
    expect(isLoopback('api.example.com')).toBe(false);
  });
});

describe('isCrossOrigin', () => {
  const at = (u: string): URL => new URL(u);

  it('treats a different host as crossing, whatever the case', () => {
    expect(isCrossOrigin(at('https://a.example'), at('https://b.example'))).toBe(true);
    expect(isCrossOrigin(at('https://A.example'), at('https://a.example'))).toBe(false);
  });

  it('treats a different port as crossing, normalizing the implied one', () => {
    expect(isCrossOrigin(at('https://a.example'), at('https://a.example:8443'))).toBe(true);
    expect(isCrossOrigin(at('https://a.example'), at('https://a.example:443'))).toBe(false);
    expect(isCrossOrigin(at('http://a.example'), at('http://a.example:80'))).toBe(false);
  });

  it('allows an http to https upgrade on the same host', () => {
    // The one exception, and the reason it is safe: same server, strictly more
    // protected than the hop that carried the credential in.
    expect(isCrossOrigin(at('http://a.example'), at('https://a.example'))).toBe(false);
  });

  it('never allows the downgrade, which is the same pair backwards', () => {
    expect(isCrossOrigin(at('https://a.example'), at('http://a.example'))).toBe(true);
  });

  it('refuses the upgrade when either side names a non-default port', () => {
    // A non-default port is a different service on the same machine as often as
    // it is the same one, so the upgrade allowance does not extend to it.
    expect(isCrossOrigin(at('http://a.example:8080'), at('https://a.example'))).toBe(true);
    expect(isCrossOrigin(at('http://a.example'), at('https://a.example:8443'))).toBe(true);
  });
});

describe('headersWithout', () => {
  const headers = { Authorization: 'Bearer x', 'X-Api-Key': 'k', 'X-Trace': 't' };

  it('drops the named headers whatever casing either side used', () => {
    // The plan records lowercased names and the caller wrote mixed case, which
    // is the exact mismatch that caused the disclosure this mode answers.
    expect(headersWithout(headers, ['authorization', 'x-api-key'])).toEqual({
      'X-Trace': 't',
    });
    expect(headersWithout(headers, ['AUTHORIZATION'])).not.toHaveProperty('Authorization');
  });

  it('keeps everything when nothing is dropped', () => {
    expect(headersWithout(headers, [])).toEqual(headers);
  });

  it('passes undefined through rather than inventing an object', () => {
    expect(headersWithout(undefined, ['authorization'])).toBeUndefined();
  });

  it('ignores a name that is not present', () => {
    expect(headersWithout(headers, ['x-not-here'])).toEqual(headers);
  });

  it('does not mutate the headers it was given', () => {
    const original = { ...headers };
    headersWithout(headers, ['authorization']);
    expect(headers).toEqual(original);
  });
});
