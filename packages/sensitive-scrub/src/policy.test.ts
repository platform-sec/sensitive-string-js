import { describe, expect, it } from 'vitest';
import {
  DEFAULT_CENSOR,
  ScrubPolicyError,
  mergeScrubPolicy,
  resolveScrubPolicy,
} from './policy.js';
import { DEFAULT_DENY_KEYS, DEFAULT_DENY_PATHS } from './deny.js';

describe('resolveScrubPolicy', () => {
  it('folds the defaults in and lowercases every key', () => {
    const resolved = resolveScrubPolicy();

    for (const key of DEFAULT_DENY_KEYS) {
      expect(resolved.denyKeys.has(key.toLowerCase())).toBe(true);
    }

    // `X-Rollbar-Access-Token` ships mixed case; matching is case-insensitive,
    // so the compiled set holds the lowered form and nothing else.
    expect(resolved.denyKeys.has('x-rollbar-access-token')).toBe(true);
    expect(resolved.denyKeys.has('X-Rollbar-Access-Token')).toBe(false);
  });

  it('adds caller keys to the defaults rather than replacing them', () => {
    const resolved = resolveScrubPolicy({ denyKeys: ['x-internal-signature'] });

    expect(resolved.denyKeys.has('x-internal-signature')).toBe(true);
    expect(resolved.denyKeys.has('authorization')).toBe(true);
    expect(resolved.denyKeys.size).toBe(DEFAULT_DENY_KEYS.length + 1);
  });

  it('seeds the default paths', () => {
    const resolved = resolveScrubPolicy({ denyPaths: ['request.data.card'] });

    for (const path of DEFAULT_DENY_PATHS) {
      expect(resolved.denyPaths.has(path)).toBe(true);
    }

    expect(resolved.denyPaths.has('request.data.card')).toBe(true);
  });

  it('applies the documented defaults for the single-valued fields', () => {
    const resolved = resolveScrubPolicy();

    expect(resolved.censor).toBe(DEFAULT_CENSOR);
    expect(resolved.onMarker).toBe('tag');
    expect(resolved.reportLabels).toBe(false);
    expect(resolved.onScrub).toBeUndefined();
  });

  it('does not censor with the library marker, so a sighting stays distinguishable', () => {
    // A censor of `[REDACTED]` would be indistinguishable from the marker the
    // walk reports as evidence that another integration failed.
    expect(DEFAULT_CENSOR).not.toContain('REDACTED');
  });
});

describe('allowKeys', () => {
  it('removes a default key when given a reason', () => {
    const resolved = resolveScrubPolicy({
      allowKeys: [{ key: 'token', reason: 'opaque request id, not a credential' }],
    });

    expect(resolved.denyKeys.has('token')).toBe(false);
    expect(resolved.denyKeys.has('access_token')).toBe(true);
  });

  it('matches the key to remove case-insensitively', () => {
    const resolved = resolveScrubPolicy({
      allowKeys: [{ key: 'AUTHORIZATION', reason: 'proxied to a test double only' }],
    });

    expect(resolved.denyKeys.has('authorization')).toBe(false);
  });

  // TEST-SCRUB-POLICY-REASON
  it('refuses an allowance with no reason', () => {
    expect(() =>
      resolveScrubPolicy({
        allowKeys: [{ key: 'token' } as unknown as { key: string; reason: string }],
      })
    ).toThrow(ScrubPolicyError);
  });

  it('refuses an allowance whose reason is only whitespace', () => {
    expect(() => resolveScrubPolicy({ allowKeys: [{ key: 'token', reason: '   ' }] })).toThrow(
      /needs a reason/
    );
  });

  it('names the key in the refusal, so the config line is findable', () => {
    expect(() => resolveScrubPolicy({ allowKeys: [{ key: 'oauth_token', reason: '' }] })).toThrow(
      /oauth_token/
    );
  });

  it('refuses a key that is both denied and allowed', () => {
    expect(() =>
      resolveScrubPolicy({
        denyKeys: ['token'],
        allowKeys: [{ key: 'token', reason: 'contradicts the line above' }],
      })
    ).toThrow(/both denyKeys and allowKeys/);
  });

  it('throws at resolution rather than on the error path', () => {
    // Resolution is an install-time call. The point of throwing here is that
    // the stack trace points at the caller's init, not at an event six hours
    // later, and that nothing on the error path does list arithmetic at all.
    expect(() => resolveScrubPolicy({ allowKeys: [{ key: 'pw', reason: '' }] })).toThrow(
      ScrubPolicyError
    );
  });
});

describe('mergeScrubPolicy', () => {
  it('unions the list fields with the caller last', () => {
    const merged = mergeScrubPolicy(
      { denyKeys: ['x-vendor'], denyPaths: ['request.cookies'], urlKeys: ['request.url'] },
      { denyKeys: ['x-caller'], denyPaths: ['extra.card'], urlKeys: ['url'] }
    );

    expect(merged.denyKeys).toEqual(['x-vendor', 'x-caller']);
    expect(merged.denyPaths).toEqual(['request.cookies', 'extra.card']);
    expect(merged.urlKeys).toEqual(['request.url', 'url']);
  });

  it('lets the caller win on the single-valued fields', () => {
    const merged = mergeScrubPolicy(
      { censor: '[VENDOR]', onMarker: 'tag', reportLabels: false },
      { censor: '[CALLER]', onMarker: 'ignore', reportLabels: true }
    );

    expect(merged.censor).toBe('[CALLER]');
    expect(merged.onMarker).toBe('ignore');
    expect(merged.reportLabels).toBe(true);
  });

  it('omits absent optional fields rather than setting them undefined', () => {
    // `exactOptionalPropertyTypes` is on across the repository, so an absent
    // field has to be absent.
    const merged = mergeScrubPolicy({}, {});

    expect('allowKeys' in merged).toBe(false);
    expect('onScrub' in merged).toBe(false);
  });

  it('keeps allowKeys as the caller"s alone', () => {
    const allowance = [{ key: 'token', reason: 'request id' }];
    const merged = mergeScrubPolicy({}, { allowKeys: allowance });

    expect(merged.allowKeys).toBe(allowance);
  });
});
