import { inspect } from 'node:util';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ResponseDecodeError, bearer } from '@platform-sec/sensitive-string-http';
import { findRawValue } from '@platform-sec/sensitive-string-testing';

import { createSensitiveGot } from '../client.js';
import { CANARY, instance, startRecordingServer, token } from './fixtures.js';
import type { RecordingServer } from './fixtures.js';

/** The section 2.3, 2.5 and 2.6 regression suites, for got. */

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

function everywhere(value: unknown): string {
  return [(value as Error).message, JSON.stringify(value), inspect(value, { depth: 8 })].join('\n');
}

describe('the error is a second wire', () => {
  beforeEach(() => {
    server.reply({ status: 401, body: '{"error":"unauthorized"}' });
  });

  it('a bare got discloses the credential in options and under inspect', async () => {
    const error = await instance(server)
      .get('x', { headers: { authorization: `Bearer ${CANARY}` } })
      .catch((caught: unknown) => caught);

    expect(everywhere(error)).toContain(CANARY);
    expect(
      (error as { options?: { headers?: Record<string, string> } }).options?.headers?.[
        'authorization'
      ]
    ).toBe(`Bearer ${CANARY}`);
  });

  it('the wrapper leaves nothing in message, JSON or inspect', async () => {
    const error = await api()
      .get('/x', { headers: { authorization: bearer(token()) } })
      .catch((caught: unknown) => caught);

    expect(error).toBeDefined();
    expect(everywhere(error)).not.toContain(CANARY);

    // Stronger than `util.inspect`, which stops at a depth and skips symbols.
    // got keeps the outgoing header block as raw text on the `ClientRequest`,
    // and this is the assertion that found it.
    expect(findRawValue(error, CANARY)).toBeUndefined();
  });

  it('scrubs a body field and a query value the same way', async () => {
    const error = await api()
      .post('/x', { card: { number: token() } }, { searchParams: { trace: token() } })
      .catch((caught: unknown) => caught);

    expect(everywhere(error)).not.toContain(CANARY);
    expect(findRawValue(error, CANARY)).toBeUndefined();
  });

  it('returns the client error untouched when the request carried nothing sensitive', async () => {
    const error = await api()
      .get('/x')
      .catch((caught: unknown) => caught);

    expect((error as { options?: unknown }).options).toBeDefined();
  });
});

describe('the success path retains it too', () => {
  it('a bare got discloses the credential from a 200 response object', async () => {
    const response = await instance(server).get('x', {
      headers: { authorization: `Bearer ${CANARY}` },
    });

    expect(inspect(response, { depth: 8 })).toContain(CANARY);
  });

  it('the wrapper scrubs response.request.options', async () => {
    const response = await api().get('/x', { headers: { authorization: bearer(token()) } });

    expect(inspect(response, { depth: 8 })).not.toContain(CANARY);
    expect(findRawValue(response, CANARY)).toBeUndefined();
  });
});

describe('the response decoder', () => {
  beforeEach(() => {
    server.reply({
      status: 200,
      headers: { 'content-type': 'application/json' },
      body: 'sk_live_abc123',
    });
  });

  it('a bare got quotes the body and appends the request URL to it', async () => {
    const error = await instance(server)
      .get('keys')
      .json()
      .catch((caught: unknown) => caught);

    expect((error as Error).message).toContain('sk_live_abc123');
    expect((error as Error).message).toContain('http://');
  });

  it('the wrapper names the request and quotes nothing', async () => {
    const error = await api({ responseFields: { token: 'credential' } })
      .get('/keys')
      .catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(ResponseDecodeError);
    expect(everywhere(error)).not.toContain('sk_live_abc123');
    expect((error as Error).cause).toBeUndefined();
  });

  it('wraps the configured response paths before the await resolves', async () => {
    server.reply({
      status: 200,
      body: JSON.stringify({
        token: 'sk_live_abc123',
        customer: { email: 'a@example.com', id: 7 },
      }),
    });

    const response = await api({
      responseFields: { token: 'credential', 'customer.email': 'sensitive' },
    }).get<{ token: unknown; customer: { email: unknown; id: number } }>('/keys');

    expect(String(response.body.token)).toBe('[REDACTED:credential]');
    expect(String(response.body.customer.email)).toBe('[REDACTED:sensitive]');
    expect(response.body.customer.id).toBe(7);
  });
});
