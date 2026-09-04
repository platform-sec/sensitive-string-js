import { inspect } from 'node:util';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
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

import { sensitiveFetch, sensitiveHeaders } from '../client.js';

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

describe('what reaches the wire', () => {
  it('reveals the header, the query and the JSON body, and leaves no marker', async () => {
    await sensitiveFetch(`${server.origin}/charges`, {
      method: 'POST',
      headers: { authorization: bearer(token()) },
      searchParams: { trace: token() },
      sensitiveJson: { amount: 100, card: { number: token() } },
      allowInsecureTransport: true,
    });

    const recorded = server.requests[0];

    expect(recorded?.headers['authorization']).toBe(`Bearer ${CANARY}`);
    expect(recorded?.headers['content-type']).toBe('application/json');
    expect(recorded?.body).toBe(`{"amount":100,"card":{"number":"${CANARY}"}}`);
    expect(recorded?.target).toContain(`trace=${encodeURIComponent(CANARY)}`);
    expect(findMarker(server.transcript)).toBeUndefined();
  });

  it('builds a Basic header and a form body itself', async () => {
    await sensitiveFetch(`${server.origin}/token`, {
      method: 'POST',
      headers: { authorization: basic('svc', token()) },
      form: { grant_type: 'client_credentials', secret: token() },
      allowInsecureTransport: true,
    });

    expect(server.requests[0]?.headers['content-type']).toBe('application/x-www-form-urlencoded');
    expect(server.requests[0]?.body).toBe(
      `grant_type=client_credentials&secret=${encodeURIComponent(CANARY)}`
    );
    expect(findMarker(server.transcript)).toBeUndefined();
  });

  it('scans an already-serialized body rather than rebuilding it', async () => {
    await expect(
      sensitiveFetch(`${server.origin}/x`, {
        method: 'POST',
        body: JSON.stringify({ token: String(token()) }),
        allowInsecureTransport: true,
      })
    ).rejects.toThrow(MarkerLeakError);

    expect(server.requests).toHaveLength(0);
  });

  it('refuses the template-literal footgun before a byte is written', async () => {
    await expect(
      sensitiveFetch(`${server.origin}/x`, {
        // Interpolating an instance is the footgun under test: exactly what a
        // caller does by accident, and exactly what the guard has to catch.
        // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
        headers: { authorization: `Bearer ${token()}` },
        allowInsecureTransport: true,
      })
    ).rejects.toThrow(MarkerLeakError);
  });

  it('refuses a credential over plaintext to a non-loopback host, before revealing', async () => {
    const auditReveal = vi.fn();

    await withRevealContext({ name: 'checkout', auditReveal }, async () => {
      await expect(
        sensitiveFetch('http://api.example.invalid/x', {
          headers: { 'x-api-key': apiKey(token()) },
        })
      ).rejects.toThrow(/plaintext http/);
    });

    expect(auditReveal).not.toHaveBeenCalled();
  });

  it('audits under a context naming the sink and the host', async () => {
    const auditReveal = vi.fn();

    await withRevealContext({ name: 'checkout', auditReveal }, async () => {
      await sensitiveFetch(`${server.origin}/x`, {
        headers: { authorization: bearer(token()) },
        allowInsecureTransport: true,
      });
    });

    expect(auditReveal).toHaveBeenCalledTimes(1);
  });
});

describe('both settlement paths', () => {
  it('returns the platform Response unchanged, because it carries no request headers', async () => {
    const response = await sensitiveFetch(`${server.origin}/x`, {
      headers: { authorization: bearer(token()) },
      allowInsecureTransport: true,
    });

    expect(response).toBeInstanceOf(Response);
    expect(inspect(response, { depth: 8 })).not.toContain(CANARY);
    expect(findRawValue(response, CANARY)).toBeUndefined();
  });

  it('keeps a query credential out of a network failure’s message', async () => {
    const error = await sensitiveFetch('https://127.0.0.1:1/x', {
      searchParams: { token: token() },
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

    const error = await sensitiveFetch(`${server.origin}/keys`, { allowInsecureTransport: true })
      .json()
      .catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(ResponseDecodeError);
    expect((error as Error).message).not.toContain('sk_live_abc123');
    expect((error as Error).cause).toBeUndefined();
  });

  it('wraps the configured response paths', async () => {
    server.reply({ status: 200, body: JSON.stringify({ token: 'sk_live_abc123' }) });

    const body = await sensitiveFetch<{ token: unknown }>(`${server.origin}/keys`, {
      allowInsecureTransport: true,
      responseFields: { token: 'credential' },
    }).json();

    expect(String(body.token)).toBe('[REDACTED:credential]');
  });
});

describe('cross-origin redirects', () => {
  it('refuses the hop by default when a credential is in x-api-key', async () => {
    server.reply({ status: 302, headers: { location: `${second.origin}/landing` } });

    await expect(
      sensitiveFetch(`${server.origin}/redirect`, {
        headers: { 'x-api-key': apiKey(token()) },
        allowInsecureTransport: true,
      })
    ).rejects.toThrow(RedirectHostNotAllowedError);

    expect(second.requests).toHaveLength(0);
  });

  it('follows a hop to a host the caller named', async () => {
    server.reply({ status: 302, headers: { location: `${second.origin}/landing` } });

    await sensitiveFetch(`${server.origin}/redirect`, {
      headers: { 'x-api-key': apiKey(token()) },
      allowedHosts: [second.host],
      allowInsecureTransport: true,
    });

    expect(second.requests[0]?.headers['x-api-key']).toBe(CANARY);
  });
});

describe('sensitiveHeaders', () => {
  it('reveals and guards, and hands back plaintext the caller now owns', () => {
    const headers = sensitiveHeaders({
      authorization: bearer(token()),
      'x-api-key': token(),
      'x-trace': 'abc',
      'x-absent': undefined,
    });

    expect(headers.get('authorization')).toBe(`Bearer ${CANARY}`);
    expect(headers.get('x-api-key')).toBe(CANARY);
    expect(headers.get('x-trace')).toBe('abc');
    expect(headers.has('x-absent')).toBe(false);
  });

  it('refuses a marker rather than building a broken header', () => {
    // Interpolating an instance is the footgun under test: exactly what a
    // caller does by accident, and exactly what the guard has to catch.
    // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
    expect(() => sensitiveHeaders({ authorization: `Bearer ${token()}` })).toThrow(MarkerLeakError);
  });
});
