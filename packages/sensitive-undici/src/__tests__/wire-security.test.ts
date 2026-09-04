import { inspect } from 'node:util';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Agent, request as undiciRequest, setGlobalDispatcher } from 'undici';
import { SensitiveString, withRevealContext } from '@platform-sec/sensitive-string-core';
import {
  MarkerLeakError,
  RedirectHostNotAllowedError,
  ResponseDecodeError,
  apiKey,
  basic,
  bearer,
} from '@platform-sec/sensitive-string-http';
import { findMarker, startRecordingServer } from '@platform-sec/sensitive-string-http/testing';
import type { RecordingServer } from '@platform-sec/sensitive-string-http/testing';
import { findRawValue } from '@platform-sec/sensitive-string-testing';

import { sensitiveRequest } from '../client.js';
import { markerGuard } from '../interceptor.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

function token(): SensitiveString<'credential'> {
  return new SensitiveString(CANARY, 'credential', 'api_token');
}

let server: RecordingServer;
let second: RecordingServer;

beforeEach(async () => {
  server = await startRecordingServer();
  second = await startRecordingServer();
});

afterEach(async () => {
  await Promise.all([server.close(), second.close()]);
});

describe('undici already fails closed, which is the rule the other four reproduce', () => {
  it('rejects an unrevealed instance in a header rather than stringifying it', async () => {
    // The measurement this row is built on: alone among the five clients,
    // undici refuses rather than sending `[REDACTED:credential]`.
    await expect(
      undiciRequest(`${server.origin}/x`, {
        headers: { 'x-secret': token() as unknown as string },
      })
    ).rejects.toThrow(/invalid/i);

    expect(server.requests).toHaveLength(0);
  });

  it('names the header and not the value when it refuses', async () => {
    const error = await undiciRequest(`${server.origin}/x`, {
      headers: { 'x-secret': token() as unknown as string },
    }).catch((caught: unknown) => caught);

    expect((error as Error).message).not.toContain(CANARY);
  });
});

describe('what reaches the wire', () => {
  it('reveals the header, the query and the JSON body, and leaves no marker', async () => {
    const response = await sensitiveRequest(`${server.origin}/charges`, {
      method: 'POST',
      headers: { authorization: bearer(token()) },
      query: { trace: token() },
      json: { amount: 100, card: { number: token() } },
      allowInsecureTransport: true,
    });

    await response.body.dump();

    const recorded = server.requests[0];

    expect(recorded?.headers['authorization']).toBe(`Bearer ${CANARY}`);
    expect(recorded?.body).toBe(`{"amount":100,"card":{"number":"${CANARY}"}}`);
    expect(recorded?.target).toContain(`trace=${encodeURIComponent(CANARY)}`);
    expect(findMarker(server.transcript)).toBeUndefined();
  });

  it('builds a Basic header and a form body itself', async () => {
    const response = await sensitiveRequest(`${server.origin}/token`, {
      method: 'POST',
      headers: { authorization: basic('svc', token()) },
      form: { grant_type: 'client_credentials', secret: token() },
      allowInsecureTransport: true,
    });

    await response.body.dump();

    expect(server.requests[0]?.headers['authorization']).toBe(
      `Basic ${Buffer.from(`svc:${CANARY}`).toString('base64')}`
    );
    expect(findMarker(server.transcript)).toBeUndefined();
  });

  it('refuses the template-literal footgun before a byte is written', async () => {
    await expect(
      sensitiveRequest(`${server.origin}/x`, {
        // Interpolating an instance is the footgun under test: exactly what a
        // caller does by accident, and exactly what the guard has to catch.
        // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
        headers: { authorization: `Bearer ${token()}` },
        allowInsecureTransport: true,
      })
    ).rejects.toThrow(MarkerLeakError);

    expect(server.requests).toHaveLength(0);
  });

  it('refuses a credential over plaintext to a non-loopback host, before revealing', async () => {
    const auditReveal = vi.fn();

    await withRevealContext({ name: 'checkout', auditReveal }, async () => {
      await expect(
        sensitiveRequest('http://api.example.invalid/x', {
          headers: { 'x-api-key': apiKey(token()) },
        })
      ).rejects.toThrow(/plaintext http/);
    });

    expect(auditReveal).not.toHaveBeenCalled();
  });

  it('keeps a query credential out of a failed request’s error', async () => {
    const error = await sensitiveRequest('https://127.0.0.1:1/x', {
      query: { token: token() },
      headers: { authorization: bearer(token()) },
    }).catch((caught: unknown) => caught);

    expect(inspect(error, { depth: 8 })).not.toContain(CANARY);
    expect(findRawValue(error, CANARY)).toBeUndefined();
  });
});

describe('the response decoder', () => {
  it('names the request and quotes none of the body', async () => {
    server.reply({
      status: 200,
      headers: { 'content-type': 'application/json' },
      body: 'sk_live_abc123',
    });

    const response = await sensitiveRequest(`${server.origin}/keys`, {
      allowInsecureTransport: true,
    });

    const error = await response.json().catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(ResponseDecodeError);
    expect((error as Error).message).not.toContain('sk_live_abc123');
    expect((error as Error).cause).toBeUndefined();
  });

  it('wraps the configured response paths', async () => {
    server.reply({ status: 200, body: JSON.stringify({ token: 'sk_live_abc123' }) });

    const response = await sensitiveRequest<{ token: unknown }>(`${server.origin}/keys`, {
      allowInsecureTransport: true,
      responseFields: { token: 'credential' },
    });

    expect(String((await response.json()).token)).toBe('[REDACTED:credential]');
  });
});

describe('redirects, which undici does not follow on its own', () => {
  it('refuses the hop by default when a credential is in x-api-key', async () => {
    server.reply({ status: 302, headers: { location: `${second.origin}/landing` } });

    await expect(
      sensitiveRequest(`${server.origin}/redirect`, {
        headers: { 'x-api-key': apiKey(token()) },
        allowInsecureTransport: true,
      })
    ).rejects.toThrow(RedirectHostNotAllowedError);

    expect(second.requests).toHaveLength(0);
  });

  it('follows a hop to a host the caller named', async () => {
    server.replyOnce({ status: 302, headers: { location: `${second.origin}/landing` } });

    const response = await sensitiveRequest(`${server.origin}/redirect`, {
      headers: { 'x-api-key': apiKey(token()) },
      allowedHosts: [second.host],
      allowInsecureTransport: true,
    });

    await response.body.dump();

    expect(second.requests[0]?.headers['x-api-key']).toBe(CANARY);
  });
});

describe('markerGuard', () => {
  it('refuses a marker a caller produced without this package', async () => {
    const guarded = new Agent().compose(markerGuard());
    const previous = new Agent();

    setGlobalDispatcher(guarded);

    try {
      await expect(
        undiciRequest(`${server.origin}/x`, {
          headers: { 'x-api-key': String(token()) },
        })
      ).rejects.toThrow(MarkerLeakError);

      expect(server.requests).toHaveLength(0);

      const clean = await undiciRequest(`${server.origin}/x`, {
        headers: { 'x-api-key': 'sk_live_real' },
      });

      await clean.body.dump();

      expect(server.requests).toHaveLength(1);
    } finally {
      setGlobalDispatcher(previous);
    }
  });

  it('refuses a percent-encoded marker in the request path', async () => {
    const guarded = new Agent().compose(markerGuard());
    const previous = new Agent();

    setGlobalDispatcher(guarded);

    try {
      await expect(
        undiciRequest(`${server.origin}/x?token=${encodeURIComponent(String(token()))}`)
      ).rejects.toThrow(MarkerLeakError);
    } finally {
      setGlobalDispatcher(previous);
    }
  });
});
