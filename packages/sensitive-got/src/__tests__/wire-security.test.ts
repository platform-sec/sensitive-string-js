import { inspect } from 'node:util';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { withRevealContext } from '@platform-sec/sensitive-string-core';
import { MarkerLeakError, apiKey, basic, bearer } from '@platform-sec/sensitive-string-http';
import { findMarker } from '@platform-sec/sensitive-string-http/testing';

import { createSensitiveGot } from '../client.js';
import { CANARY, instance, startRecordingServer, token } from './fixtures.js';
import type { RecordingServer } from './fixtures.js';

let server: RecordingServer;

beforeEach(async () => {
  server = await startRecordingServer();
});

afterEach(async () => {
  await server.close();
});

function api(extra = {}) {
  return createSensitiveGot(instance(server), { allowInsecureTransport: true, ...extra });
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

  it('reveals a query value into a primitive, which got’s own validator demands', async () => {
    // Measured: got rejects a non-primitive `searchParams` value outright, with
    // "Expected values which are string, number, boolean, null, or undefined".
    // It is one of the two clients that fail closed, and the wrapper keeps it
    // that way by revealing before got ever validates.
    await api().get('/x', { searchParams: { token: token() } });

    expect(server.requests[0]?.target).toBe(`/x?token=${encodeURIComponent(CANARY)}`);
  });

  it('builds a Basic header and a form body itself', async () => {
    await api().post('/token', undefined, {
      headers: { authorization: basic('svc', token()) },
      form: { grant_type: 'client_credentials', secret: token() },
    });

    const recorded = server.requests[0];

    expect(recorded?.headers['authorization']).toBe(
      `Basic ${Buffer.from(`svc:${CANARY}`).toString('base64')}`
    );
    expect(recorded?.body).toBe(
      `grant_type=client_credentials&secret=${encodeURIComponent(CANARY)}`
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

  it('audits once per attempt, so the count matches the socket writes', async () => {
    const auditReveal = vi.fn();

    server.reply({ status: 500, body: '{"e":1}' });

    await withRevealContext({ name: 'sync', auditReveal }, async () => {
      await expect(
        api({ retries: 2 }).get('/x', { headers: { authorization: bearer(token()) } })
      ).rejects.toThrow();
    });

    expect(server.requests).toHaveLength(3);
    expect(auditReveal).toHaveBeenCalledTimes(3);

    for (const [value] of auditReveal.mock.calls) {
      expect(inspect(value, { depth: 8 })).not.toContain(CANARY);
    }
  });

  it('refuses a credential over plaintext to a non-loopback host, before revealing', async () => {
    const auditReveal = vi.fn();

    await withRevealContext({ name: 'sync', auditReveal }, async () => {
      const client = createSensitiveGot(instance(server));

      await expect(
        client.get('http://api.example.invalid/x', { headers: { 'x-api-key': apiKey(token()) } })
      ).rejects.toThrow(/plaintext http/);
    });

    expect(auditReveal).not.toHaveBeenCalled();
    expect(server.requests).toHaveLength(0);
  });
});
