import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { RedirectHostNotAllowedError, apiKey, bearer } from '@platform-sec/sensitive-string-http';

import { createSensitiveGot } from '../client.js';
import { CANARY, instance, startRecordingServer, token } from './fixtures.js';
import type { RecordingServer } from './fixtures.js';

/**
 * Section 2.4, for got.
 *
 * got is the one client where the wrapper does not run its own hop loop: got
 * exposes `beforeRedirect`, and its redirect handling has semantics worth
 * keeping. The check is installed there instead, and got wraps anything a hook
 * throws in a `RequestError`, so the wrapper unwraps `cause` to make the
 * refusal arrive as itself.
 */

let origin: RecordingServer;
let second: RecordingServer;

beforeEach(async () => {
  origin = await startRecordingServer();
  second = await startRecordingServer();
});

afterEach(async () => {
  await Promise.all([origin.close(), second.close()]);
});

describe('cross-origin redirects', () => {
  it('a bare got forwards x-api-key verbatim and strips Authorization', async () => {
    origin.reply({ status: 302, headers: { location: `${second.origin}/landing` } });

    await instance(origin).get('redirect', {
      headers: { 'x-api-key': CANARY, authorization: `Bearer ${CANARY}` },
    });

    expect(second.requests[0]?.headers['x-api-key']).toBe(CANARY);
    expect(second.requests[0]?.headers['authorization']).toBeUndefined();
  });

  it('the wrapper refuses the hop by default when a credential is in x-api-key', async () => {
    origin.reply({ status: 302, headers: { location: `${second.origin}/landing` } });

    const api = createSensitiveGot(instance(origin), { allowInsecureTransport: true });

    const error = await api
      .get('/redirect', { headers: { 'x-api-key': apiKey(token()) } })
      .catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(RedirectHostNotAllowedError);
    expect(second.requests).toHaveLength(0);
  });

  it('follows a hop to a host the caller named', async () => {
    origin.reply({ status: 302, headers: { location: `${second.origin}/landing` } });

    const api = createSensitiveGot(instance(origin), {
      allowInsecureTransport: true,
      allowedHosts: [second.host],
    });

    await api.get('/redirect', { headers: { 'x-api-key': apiKey(token()) } });

    expect(second.requests[0]?.headers['x-api-key']).toBe(CANARY);
  });

  it('refuses a hop to a host the caller did not name', async () => {
    origin.reply({ status: 302, headers: { location: `${second.origin}/landing` } });

    const api = createSensitiveGot(instance(origin), {
      allowInsecureTransport: true,
      allowedHosts: ['api.example.com'],
    });

    await expect(
      api.get('/redirect', { headers: { 'x-api-key': apiKey(token()) } })
    ).rejects.toThrow(/not in allowedHosts/);

    expect(second.requests).toHaveLength(0);
  });

  it("leaves got's own redirect handling alone when only Authorization carries a credential", async () => {
    origin.reply({ status: 302, headers: { location: `${second.origin}/landing` } });

    const api = createSensitiveGot(instance(origin), { allowInsecureTransport: true });

    await api.get('/redirect', { headers: { authorization: bearer(token()) } });

    expect(second.requests).toHaveLength(1);
    expect(second.transcript).not.toContain(CANARY);
  });
});
