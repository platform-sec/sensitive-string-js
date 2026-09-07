import { inspect } from 'node:util';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { withRevealContext } from '@platform-sec/sensitive-string-core';
import {
  MarkerLeakError,
  RedirectHostNotAllowedError,
  RedirectWouldResendCredentialError,
  ResponseDecodeError,
  apiKey,
  basic,
  bearer,
} from '@platform-sec/sensitive-string-http';
import { findMarker, startRecordingServer } from '@platform-sec/sensitive-string-http/testing';
import { findRawValue } from '@platform-sec/sensitive-string-testing';

import { createSensitiveKy } from '../client.js';
import { CANARY, instance, token } from './fixtures.js';
import type { RecordingServer } from './fixtures.js';

let server: RecordingServer;
let second: RecordingServer;

beforeEach(async () => {
  server = await startRecordingServer();
  second = await startRecordingServer();
});

afterEach(async () => {
  await Promise.all([server.close(), second.close()]);
});

function api(extra = {}) {
  return createSensitiveKy(instance(), {
    prefix: server.origin,
    allowInsecureTransport: true,
    ...extra,
  });
}

describe('what reaches the wire', () => {
  it('reveals the header, the query and the body, and leaves no marker behind', async () => {
    await api().post(
      '/charges',
      { amount: 100, card: { number: token() } },
      {
        headers: { authorization: bearer(token()) },
        searchParams: { trace: token() },
      }
    );

    const recorded = server.requests[0];

    expect(recorded?.headers['authorization']).toBe(`Bearer ${CANARY}`);
    expect(recorded?.body).toBe(`{"amount":100,"card":{"number":"${CANARY}"}}`);
    expect(recorded?.target).toContain(`trace=${encodeURIComponent(CANARY)}`);
    expect(findMarker(server.transcript)).toBeUndefined();
  });

  it('builds a Basic header and a form body itself', async () => {
    await api().post('/token', undefined, {
      headers: { authorization: basic('svc', token()) },
      form: { grant_type: 'client_credentials', secret: token() },
    });

    expect(server.requests[0]?.headers['authorization']).toBe(
      `Basic ${Buffer.from(`svc:${CANARY}`).toString('base64')}`
    );
    expect(findMarker(server.transcript)).toBeUndefined();
  });

  it('refuses the template-literal footgun before a byte is written', async () => {
    await expect(
      // Interpolating an instance is the footgun under test: exactly what a
      // caller does by accident, and exactly what the guard has to catch.
      // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
      api().get('/x', { headers: { authorization: `Bearer ${token()}` } })
    ).rejects.toThrow(MarkerLeakError);

    expect(server.requests).toHaveLength(0);
  });

  it('audits once per attempt, on the path ky rejects from by default', async () => {
    const auditReveal = vi.fn();

    server.reply({ status: 500, body: '{"e":1}' });

    await withRevealContext({ name: 'sync', auditReveal }, async () => {
      await expect(
        api({ retries: 2 }).get('/x', { headers: { authorization: bearer(token()) } })
      ).rejects.toThrow();
    });

    expect(server.requests).toHaveLength(3);
    expect(auditReveal).toHaveBeenCalledTimes(3);
  });
});

describe('the error is a second wire, and the response is not', () => {
  beforeEach(() => {
    server.reply({ status: 401, body: '{"e":1}' });
  });

  it("a bare ky discloses the credential through the HTTPError's Request", async () => {
    const error = await instance()
      .get(`${server.origin}/x`, { headers: { authorization: `Bearer ${CANARY}` } })
      .catch((caught: unknown) => caught);

    expect(inspect(error, { depth: 8 })).toContain(CANARY);
  });

  it('the wrapper sets the named headers on the Request to their markers', async () => {
    const error = await api()
      .get('/x', { headers: { authorization: bearer(token()) } })
      .catch((caught: unknown) => caught);

    expect(inspect(error, { depth: 8 })).not.toContain(CANARY);
    expect(findRawValue(error, CANARY)).toBeUndefined();
    expect((error as { request: Request }).request.headers.get('authorization')).toBe(
      '[REDACTED:credential]'
    );
  });

  it('replaces the Request wholesale when the plan names a body path or a query key', async () => {
    const error = await api()
      .post('/x', { card: token() }, { searchParams: { trace: token() } })
      .catch((caught: unknown) => caught);

    expect(findRawValue(error, CANARY)).toBeUndefined();
    expect((error as { request: Request }).request.body).toBeNull();
  });

  it('returns the client response unchanged on the success path, as measured', async () => {
    server.reply({ status: 200, body: '{"ok":true}' });

    const response = await api().get('/x', { headers: { authorization: bearer(token()) } });

    expect(response).toBeInstanceOf(Response);
    expect(findRawValue(response, CANARY)).toBeUndefined();
  });
});

describe('the response decoder', () => {
  it('a bare ky propagates JSON.parse’s quoted body', async () => {
    server.reply({
      status: 200,
      headers: { 'content-type': 'application/json' },
      body: 'sk_live_abc123',
    });

    const error = await instance()
      .get(`${server.origin}/keys`)
      .json()
      .catch((caught: unknown) => caught);

    expect((error as Error).message).toContain('sk_live_abc123');
  });

  it('the wrapper names the request and quotes nothing', async () => {
    server.reply({
      status: 200,
      headers: { 'content-type': 'application/json' },
      body: 'sk_live_abc123',
    });

    const error = await api()
      .get('/keys')
      .json()
      .catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(ResponseDecodeError);
    expect((error as Error).message).not.toContain('sk_live_abc123');
    expect((error as Error).cause).toBeUndefined();
  });

  it('wraps the configured response paths', async () => {
    server.reply({
      status: 200,
      body: JSON.stringify({ token: 'sk_live_abc123', customer: { email: 'a@example.com' } }),
    });

    const body = await api({ responseFields: { token: 'credential' } })
      .get<{ token: unknown }>('/keys')
      .json();

    expect(String(body.token)).toBe('[REDACTED:credential]');
  });
});

describe('cross-origin redirects', () => {
  it('the platform forwards x-api-key and strips Authorization', async () => {
    server.reply({ status: 302, headers: { location: `${second.origin}/landing` } });

    await instance().get(`${server.origin}/redirect`, {
      headers: { 'x-api-key': CANARY, authorization: `Bearer ${CANARY}` },
    });

    expect(second.requests[0]?.headers['x-api-key']).toBe(CANARY);
    expect(second.requests[0]?.headers['authorization']).toBeUndefined();
  });

  it('the wrapper refuses the hop by default when a credential is in x-api-key', async () => {
    server.reply({ status: 302, headers: { location: `${second.origin}/landing` } });

    await expect(
      api().get('/redirect', { headers: { 'x-api-key': apiKey(token()) } })
    ).rejects.toThrow(RedirectHostNotAllowedError);

    expect(second.requests).toHaveLength(0);
  });

  it('refuses the hop by default when the credential came from the headers option', async () => {
    // The option is merged before the policy is settled, so a credential there
    // flips the default the same way one in the call does.
    server.reply({ status: 302, headers: { location: `${second.origin}/landing` } });

    await expect(
      api({ headers: { 'x-api-key': apiKey(token()) } }).get('/redirect')
    ).rejects.toThrow(RedirectHostNotAllowedError);

    expect(second.requests).toHaveLength(0);
  });

  it('follows a hop to a host the caller named', async () => {
    server.reply({ status: 302, headers: { location: `${second.origin}/landing` } });

    await api({ allowedHosts: [second.host] }).get('/redirect', {
      headers: { 'x-api-key': apiKey(token()) },
    });

    expect(second.requests[0]?.headers['x-api-key']).toBe(CANARY);
  });
});

describe('allowedHosts: strip', () => {
  it('follows a cross-origin hop with the credential removed', async () => {
    // The third answer. Refusing breaks a provider that redirects downloads to
    // storage the caller cannot name; naming hosts is impossible for the same
    // reason. This drops the credential at the boundary and lets the request
    // finish, which is what the leak this mode was written for actually needed.
    server.reply({ status: 302, headers: { location: `${second.origin}/landing` } });

    await api({ allowedHosts: 'strip' }).get('/redirect', {
      headers: { 'x-api-key': apiKey(token()) },
    });

    expect(second.transcript).not.toContain(CANARY);
    expect(second.requests[0]?.headers['x-api-key']).toBeUndefined();
    expect(second.requests).toHaveLength(1);
  });

  it('strips a credential set on the headers option and does not refill it on a later hop', async () => {
    // ky does not expose an extended instance's defaults, so this option is
    // where an instance credential goes, and it is merged before the
    // dropped-name accounting: once the name is removed at the first boundary
    // it stays removed when a later hop rebuilds the request from the option.
    server.replyOnce({ status: 302, headers: { location: `${second.origin}/bounce` } });
    second.reply({ status: 302, headers: { location: `${server.origin}/landing` } });

    await api({ allowedHosts: 'strip', headers: { 'x-api-key': apiKey(token()) } }).get(
      '/redirect'
    );

    expect(server.requests[0]?.headers['x-api-key']).toBe(CANARY);
    expect(second.requests[0]?.headers['x-api-key']).toBeUndefined();
    expect(server.requests[1]?.headers['x-api-key']).toBeUndefined();
    expect(server.requests).toHaveLength(2);
    expect(second.transcript).not.toContain(CANARY);
  });

  it('keeps the credential on a same-origin hop', async () => {
    // Stripping every hop would be a different bug: a redirect inside one
    // origin discloses the credential to nobody new.
    server.replyOnce({ status: 302, headers: { location: `${server.origin}/landing` } });

    await api({ allowedHosts: 'strip' }).get('/redirect', {
      headers: { 'x-api-key': apiKey(token()) },
    });

    expect(server.requests[1]?.headers['x-api-key']).toBe(CANARY);
  });

  it("sends the caller's query on the first hop only", async () => {
    // Found by verification: every hop re-merged `searchParams` onto the URL
    // the server named, so a wrapped query credential reached the second
    // origin that `'strip'` had just removed it from the headers of.
    server.reply({ status: 302, headers: { location: `${second.origin}/landing` } });

    await api({ allowedHosts: 'strip' }).get('/redirect', {
      searchParams: { token: token() },
      headers: { 'x-api-key': apiKey(token()) },
    });

    expect(server.requests[0]?.target).toContain(CANARY);
    expect(second.requests).toHaveLength(1);
    expect(second.requests[0]?.target).not.toContain(CANARY);
    expect(second.transcript).not.toContain(CANARY);
  });

  it('refuses a cross-origin 307 that would re-send a body carrying a credential', async () => {
    server.reply({ status: 307, headers: { location: `${second.origin}/landing` } });

    const error = await api({ allowedHosts: 'strip' })
      .post('/redirect', { secret: token() }, { headers: { 'x-api-key': apiKey(token()) } })
      .catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(RedirectWouldResendCredentialError);
    expect((error as RedirectWouldResendCredentialError).paths).toEqual(['secret']);
    expect(second.requests).toHaveLength(0);
  });
});
