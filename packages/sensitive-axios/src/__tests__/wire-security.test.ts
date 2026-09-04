import { inspect } from 'node:util';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { withRevealContext } from '@platform-sec/sensitive-string-core';
import { MarkerLeakError, apiKey, basic, bearer } from '@platform-sec/sensitive-string-http';
import { findMarker } from '@platform-sec/sensitive-string-http/testing';

import { createSensitiveAxios } from '../client.js';
import { CANARY, instance, startRecordingServer, token } from './fixtures.js';
import type { RecordingServer } from './fixtures.js';

/**
 * Bytes, not the client's view of them.
 *
 * The server records the raw request line, header block and body, so an
 * assertion here is about what crossed the socket rather than about what axios
 * remembers having been told.
 */

let server: RecordingServer;

beforeEach(async () => {
  server = await startRecordingServer();
});

afterEach(async () => {
  await server.close();
});

describe('what reaches the wire', () => {
  it('sends the revealed token in an Authorization header and no marker anywhere', async () => {
    const api = createSensitiveAxios(instance(server), { allowInsecureTransport: true });

    await api.post(
      '/charges',
      { amount: 100, card: { number: token() } },
      {
        headers: { Authorization: bearer(token()) },
        params: { trace: token() },
      }
    );

    const recorded = server.requests[0];

    expect(recorded?.headers['authorization']).toBe(`Bearer ${CANARY}`);
    expect(recorded?.body).toBe(`{"amount":100,"card":{"number":"${CANARY}"}}`);
    expect(recorded?.target).toContain(`trace=${encodeURIComponent(CANARY)}`);
    expect(findMarker(server.transcript)).toBeUndefined();
  });

  it('sends a Basic header the package encoded, from components it checked as plain text', async () => {
    const api = createSensitiveAxios(instance(server), { allowInsecureTransport: true });

    await api.get('/x', { headers: { Authorization: basic('svc', token()) } });

    expect(server.requests[0]?.headers['authorization']).toBe(
      `Basic ${Buffer.from(`svc:${CANARY}`).toString('base64')}`
    );
    expect(findMarker(server.transcript)).toBeUndefined();
  });

  it('reveals a credential on defaults.headers.common, which the caller never repeats', async () => {
    const client = instance(server);
    (client.defaults.headers.common as Record<string, unknown>)['x-api-key'] = token();

    const api = createSensitiveAxios(client, { allowInsecureTransport: true });

    await api.get('/x');

    expect(server.requests[0]?.headers['x-api-key']).toBe(CANARY);
    expect(findMarker(server.transcript)).toBeUndefined();
  });

  it('sends a form body the package built, percent-encoded and marker-free', async () => {
    const api = createSensitiveAxios(instance(server), { allowInsecureTransport: true });

    await api.post('/token', undefined, {
      form: { grant_type: 'client_credentials', secret: token() },
    });

    expect(server.requests[0]?.body).toBe(
      `grant_type=client_credentials&secret=${encodeURIComponent(CANARY)}`
    );
    expect(findMarker(server.transcript)).toBeUndefined();
  });

  it('refuses the template-literal footgun before a byte is written', async () => {
    const api = createSensitiveAxios(instance(server), { allowInsecureTransport: true });

    await expect(
      // Interpolating an instance is the footgun under test: exactly what a
      // caller does by accident, and exactly what the guard has to catch.
      // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
      api.get('/x', { headers: { Authorization: `Bearer ${token()}` } })
    ).rejects.toThrow(MarkerLeakError);

    expect(server.requests).toHaveLength(0);
  });

  it('sends byte-identical requests to a bare axios when nothing is sensitive', async () => {
    const client = instance(server);
    const api = createSensitiveAxios(client, { allowInsecureTransport: true });

    await api.post('/adopt', { amount: 100 }, { headers: { 'x-trace': 'abc' } });
    await client.post('/adopt', { amount: 100 }, { headers: { 'x-trace': 'abc' } });

    const [wrapped, bare] = server.requests;

    expect(wrapped?.target).toBe(bare?.target);
    expect(wrapped?.body).toBe(bare?.body);
    expect(wrapped?.headers['content-type']).toBe(bare?.headers['content-type']);
    expect(wrapped?.headers['x-trace']).toBe(bare?.headers['x-trace']);
    expect(wrapped?.headers['accept']).toBe(bare?.headers['accept']);
  });

  it('audits every reveal under a context naming the sink, the host and the attempt', async () => {
    const auditReveal = vi.fn();
    const api = createSensitiveAxios(instance(server), { allowInsecureTransport: true });

    await withRevealContext({ name: 'checkout', auditReveal }, async () => {
      await api.post(
        '/charges',
        { card: token() },
        { headers: { Authorization: bearer(token()) } }
      );
    });

    expect(auditReveal).toHaveBeenCalledTimes(2);

    for (const [value] of auditReveal.mock.calls) {
      expect(inspect(value, { depth: 8 })).not.toContain(CANARY);
    }
  });

  it('refuses a credential over plaintext to a non-loopback host, before revealing', async () => {
    const auditReveal = vi.fn();
    const api = createSensitiveAxios(instance(server));

    await withRevealContext({ name: 'checkout', auditReveal }, async () => {
      await expect(
        api.get('http://api.example.invalid/x', { headers: { 'x-api-key': apiKey(token()) } })
      ).rejects.toThrow(/plaintext http/);
    });

    expect(auditReveal).not.toHaveBeenCalled();
    expect(server.requests).toHaveLength(0);
  });
});
