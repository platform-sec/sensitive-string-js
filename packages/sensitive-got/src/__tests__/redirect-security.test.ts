import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  RedirectHostNotAllowedError,
  RedirectWouldResendCredentialError,
  apiKey,
  bearer,
} from '@platform-sec/sensitive-string-http';

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

describe('allowedHosts: strip', () => {
  it('follows a cross-origin hop with the credential removed', async () => {
    // The third answer. Refusing breaks a provider that redirects downloads to
    // storage the caller cannot name; naming hosts is impossible for the same
    // reason. This drops the credential at the boundary and lets the request
    // finish, which is what the leak this mode was written for actually needed.
    origin.reply({ status: 302, headers: { location: `${second.origin}/landing` } });

    const api = createSensitiveGot(instance(origin), {
      allowInsecureTransport: true,
      allowedHosts: 'strip',
    });

    await api.get('/redirect', { headers: { 'x-api-key': apiKey(token()) } });

    expect(second.transcript).not.toContain(CANARY);
    expect(second.requests[0]?.headers['x-api-key']).toBeUndefined();
    expect(second.requests).toHaveLength(1);
  });

  it('keeps the credential on a same-origin hop', async () => {
    // Stripping every hop would be a different bug: a redirect inside one
    // origin discloses the credential to nobody new.
    origin.replyOnce({ status: 302, headers: { location: `${origin.origin}/landing` } });

    const api = createSensitiveGot(instance(origin), {
      allowInsecureTransport: true,
      allowedHosts: 'strip',
    });

    await api.get('/redirect', { headers: { 'x-api-key': apiKey(token()) } });

    expect(origin.requests[1]?.headers['x-api-key']).toBe(CANARY);
  });

  it('strips a credential that came from the instance defaults, not just the call', async () => {
    // `got.extend({ headers })` is how an instance gets its credential, and
    // got merges it in at send time. Measured before this was handled: a
    // wrapped value there reached both origins as the redaction marker,
    // revealed nowhere and stripped by nothing.
    origin.reply({ status: 302, headers: { location: `${second.origin}/landing` } });

    // got's own header type takes strings, so the descriptor is cast past it
    // the way the undici wire test hands a raw instance to a bare client.
    const api = createSensitiveGot(
      instance(origin).extend({ headers: { 'x-api-key': apiKey(token()) as unknown as string } }),
      { allowInsecureTransport: true, allowedHosts: 'strip' }
    );

    await api.get('/redirect');

    expect(origin.requests[0]?.headers['x-api-key']).toBe(CANARY);
    expect(second.requests).toHaveLength(1);
    expect(second.requests[0]?.headers['x-api-key']).toBeUndefined();
    expect(second.transcript).not.toContain(CANARY);
    expect(origin.transcript).not.toContain('[REDACTED');
    expect(origin.transcript).not.toContain('[object Object]');
  });

  it('refuses a cross-origin 307 that would re-send a body carrying a credential', async () => {
    // got keeps the body across a 307 and hands it to `beforeRedirect` as
    // `json`. A body cannot be stripped in part, so the hop is refused; got
    // wraps the throw and the wrapper unwraps it.
    origin.reply({ status: 307, headers: { location: `${second.origin}/landing` } });

    const api = createSensitiveGot(instance(origin), {
      allowInsecureTransport: true,
      allowedHosts: 'strip',
    });

    const error = await api
      .post('/redirect', { secret: token() }, { headers: { 'x-api-key': apiKey(token()) } })
      .catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(RedirectWouldResendCredentialError);
    expect((error as RedirectWouldResendCredentialError).paths).toEqual(['secret']);
    expect(second.requests).toHaveLength(0);
  });

  it('follows a cross-origin 302 from a POST, which drops the body on its own', async () => {
    origin.reply({ status: 302, headers: { location: `${second.origin}/landing` } });

    const api = createSensitiveGot(instance(origin), {
      allowInsecureTransport: true,
      allowedHosts: 'strip',
    });

    await api.post('/redirect', { secret: token() }, { headers: { 'x-api-key': apiKey(token()) } });

    expect(second.requests).toHaveLength(1);
    expect(second.requests[0]?.method).toBe('GET');
    expect(second.transcript).not.toContain(CANARY);
  });
});
