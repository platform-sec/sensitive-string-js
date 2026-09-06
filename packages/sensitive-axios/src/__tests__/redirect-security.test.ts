import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  RedirectHostNotAllowedError,
  RedirectWouldResendCredentialError,
  apiKey,
  bearer,
} from '@platform-sec/sensitive-string-http';

import { createSensitiveAxios } from '../client.js';
import { CANARY, instance, startRecordingServer, token } from './fixtures.js';
import type { RecordingServer } from './fixtures.js';

/**
 * Section 2.4: a custom auth header survives a cross-origin redirect.
 *
 * The bare-client assertion runs first so the suite records the platform
 * behaviour it is compensating for, and fails if axios ever fixes it.
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

function redirectTo(target: string): void {
  origin.reply({ status: 302, headers: { location: target }, body: '' });
}

describe('cross-origin redirects', () => {
  it('a bare axios forwards x-api-key verbatim to a host the caller never named', async () => {
    redirectTo(`${second.origin}/landing`);

    await instance(origin).get('/redirect', { headers: { 'x-api-key': CANARY } });

    expect(second.transcript).toContain(CANARY);
  });

  it('a bare axios does strip Authorization, which is why the default trusts it', async () => {
    redirectTo(`${second.origin}/landing`);

    await instance(origin).get('/redirect', { headers: { Authorization: `Bearer ${CANARY}` } });

    expect(second.transcript).not.toContain(CANARY);
  });

  it('the wrapper refuses the hop by default when a credential is in x-api-key', async () => {
    redirectTo(`${second.origin}/landing`);

    const api = createSensitiveAxios(instance(origin), { allowInsecureTransport: true });

    await expect(
      api.get('/redirect', { headers: { 'x-api-key': apiKey(token()) } })
    ).rejects.toThrow(RedirectHostNotAllowedError);

    expect(second.requests).toHaveLength(0);
  });

  it('follows a hop to a host the caller named, and refuses one to a host they did not', async () => {
    redirectTo(`${second.origin}/landing`);

    const allowed = createSensitiveAxios(instance(origin), {
      allowInsecureTransport: true,
      allowedHosts: [second.host],
    });

    await allowed.get('/redirect', { headers: { 'x-api-key': apiKey(token()) } });

    expect(second.requests).toHaveLength(1);
    expect(second.requests[0]?.headers['x-api-key']).toBe(CANARY);

    origin.reset();
    second.reset();
    redirectTo(`${second.origin}/landing`);

    const refused = createSensitiveAxios(instance(origin), {
      allowInsecureTransport: true,
      allowedHosts: ['api.example.com'],
    });

    await expect(
      refused.get('/redirect', { headers: { 'x-api-key': apiKey(token()) } })
    ).rejects.toThrow(/not in allowedHosts/);

    expect(second.requests).toHaveLength(0);
  });

  it('refuses at hop 3 as readily as at hop 1', async () => {
    origin.replyOnce({ status: 302, headers: { location: `${origin.origin}/two` } });
    origin.replyOnce({ status: 302, headers: { location: `${origin.origin}/three` } });
    origin.replyOnce({ status: 302, headers: { location: `${second.origin}/landing` } });

    const api = createSensitiveAxios(instance(origin), {
      allowInsecureTransport: true,
      allowedHosts: [origin.host],
    });

    const error = await api
      .get('/one', { headers: { 'x-api-key': apiKey(token()) } })
      .catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(RedirectHostNotAllowedError);
    expect((error as RedirectHostNotAllowedError).hop).toBe(3);
    expect(second.requests).toHaveLength(0);
  });

  it('stops at the hop budget rather than looping', async () => {
    origin.reply({ status: 302, headers: { location: `${origin.origin}/again` } });

    const api = createSensitiveAxios(instance(origin), {
      allowInsecureTransport: true,
      allowedHosts: [origin.host],
      maxRedirects: 2,
    });

    await expect(api.get('/one', { headers: { 'x-api-key': apiKey(token()) } })).rejects.toThrow(
      /more than 2 redirects/
    );
  });

  it("leaves axios's own redirect handling alone when only Authorization carries a credential", async () => {
    redirectTo(`${second.origin}/landing`);

    const api = createSensitiveAxios(instance(origin), { allowInsecureTransport: true });

    await api.get('/redirect', { headers: { Authorization: bearer(token()) } });

    // axios followed it, and stripped the header on the way, which is the
    // behaviour the default is deliberately trusting.
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
    redirectTo(`${second.origin}/landing`);

    const api = createSensitiveAxios(instance(origin), {
      allowInsecureTransport: true,
      allowedHosts: 'strip',
    });

    await api.get('/redirect', { headers: { 'x-api-key': apiKey(token()) } });

    expect(second.transcript).not.toContain(CANARY);
    expect(second.requests[0]?.headers['x-api-key']).toBeUndefined();
    expect(second.requests).toHaveLength(1);
  });

  it('strips a credential that came from the instance defaults, not just the call', async () => {
    // `withDefaultHeaders` merges `client.defaults.headers` into what gets
    // revealed, and those may hold a wrapped value too. A strip that narrowed
    // only the per-request headers would drop the call site's credential and
    // forward the instance's, which is worse than not stripping at all because
    // it looks like it worked.
    redirectTo(`${second.origin}/landing`);

    const bare = instance(origin);
    (bare.defaults.headers as unknown as Record<string, Record<string, unknown>>)['common'] = {
      'x-api-key': apiKey(token()),
    };

    const api = createSensitiveAxios(bare, {
      allowInsecureTransport: true,
      allowedHosts: 'strip',
    });

    await api.get('/redirect');

    expect(second.transcript).not.toContain(CANARY);
    expect(second.requests[0]?.headers['x-api-key']).toBeUndefined();
    expect(origin.requests[0]?.headers['x-api-key']).toBe(CANARY);
  });

  it('keeps the credential on a same-origin hop', async () => {
    // Stripping every hop would be a different bug: a redirect inside one
    // origin discloses the credential to nobody new.
    origin.replyOnce({ status: 302, headers: { location: `${origin.origin}/landing` }, body: '' });

    const api = createSensitiveAxios(instance(origin), {
      allowInsecureTransport: true,
      allowedHosts: 'strip',
    });

    await api.get('/redirect', { headers: { 'x-api-key': apiKey(token()) } });

    expect(origin.requests[1]?.headers['x-api-key']).toBe(CANARY);
  });

  it("sends the caller's query on the first hop only", async () => {
    // Found by verification: every hop re-merged `params` onto the URL the
    // server named, so a wrapped query credential reached the second origin
    // that `'strip'` had just removed it from the headers of.
    redirectTo(`${second.origin}/landing`);

    const api = createSensitiveAxios(instance(origin), {
      allowInsecureTransport: true,
      allowedHosts: 'strip',
    });

    await api.get('/redirect', {
      params: { token: token() },
      headers: { 'x-api-key': apiKey(token()) },
    });

    expect(origin.requests[0]?.target).toContain(CANARY);
    expect(second.requests).toHaveLength(1);
    expect(second.requests[0]?.target).not.toContain(CANARY);
    expect(second.transcript).not.toContain(CANARY);
  });

  it('refuses a cross-origin 307 that would re-send a body carrying a credential', async () => {
    // A header can be dropped at the boundary; a body cannot be dropped in
    // part. Refused before anything is revealed for the hop.
    origin.reply({ status: 307, headers: { location: `${second.origin}/landing` }, body: '' });

    const api = createSensitiveAxios(instance(origin), {
      allowInsecureTransport: true,
      allowedHosts: 'strip',
    });

    const error = await api
      .post('/redirect', { secret: token() }, { headers: { 'x-api-key': apiKey(token()) } })
      .catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(RedirectWouldResendCredentialError);
    expect((error as RedirectWouldResendCredentialError).paths).toEqual(['secret']);
    expect(second.requests).toHaveLength(0);
    expect(String((error as Error).message)).not.toContain(CANARY);
  });

  it('follows a cross-origin 302 from a POST, which drops the body on its own', async () => {
    redirectTo(`${second.origin}/landing`);

    const api = createSensitiveAxios(instance(origin), {
      allowInsecureTransport: true,
      allowedHosts: 'strip',
    });

    await api.post('/redirect', { secret: token() }, { headers: { 'x-api-key': apiKey(token()) } });

    expect(second.requests).toHaveLength(1);
    expect(second.requests[0]?.method).toBe('GET');
    expect(second.transcript).not.toContain(CANARY);
  });
});
