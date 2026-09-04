import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { MARKER_NEEDLES, findMarker, startRecordingServer } from './testing.js';
import type { RecordingServer } from './testing.js';

/**
 * The harness every security assertion in this row rests on.
 *
 * If the recording server drops a header, joins the transcript wrongly, or
 * fails to record a request at all, every canary assertion in six packages
 * passes for the wrong reason. That is the one failure a leak suite must not
 * have, so the harness is tested rather than trusted.
 */

let server: RecordingServer;

beforeEach(async () => {
  server = await startRecordingServer();
});

afterEach(async () => {
  await server.close();
});

describe('startRecordingServer', () => {
  it('records the request line, the headers and the body', async () => {
    await fetch(`${server.origin}/charges?a=1`, {
      method: 'POST',
      headers: { 'x-trace': 'abc', 'content-type': 'application/json' },
      body: '{"amount":100}',
    });

    const recorded = server.requests[0];

    expect(recorded?.method).toBe('POST');
    expect(recorded?.target).toBe('/charges?a=1');
    expect(recorded?.headers['x-trace']).toBe('abc');
    expect(recorded?.body).toBe('{"amount":100}');
    expect(recorded?.raw).toContain('POST /charges?a=1');
    expect(recorded?.raw).toContain('x-trace: abc');
    expect(recorded?.raw).toContain('{"amount":100}');
  });

  it('joins every request into one transcript, which is what a canary check scans', async () => {
    await fetch(`${server.origin}/one`, { headers: { 'x-a': 'first' } });
    await fetch(`${server.origin}/two`, { headers: { 'x-b': 'second' } });

    expect(server.requests).toHaveLength(2);
    expect(server.transcript).toContain('first');
    expect(server.transcript).toContain('second');
  });

  it('serves a standing reply until it is replaced', async () => {
    server.reply({ status: 418, body: '{"tea":true}' });

    for (const _ of [0, 1]) {
      const response = await fetch(`${server.origin}/x`);

      expect(response.status).toBe(418);
      expect(await response.json()).toEqual({ tea: true });
    }
  });

  it('serves a queued reply once, then falls back to the standing one', async () => {
    server.reply({ status: 200, body: '{"standing":true}' });
    server.replyOnce({ status: 302, headers: { location: '/elsewhere' } });

    const first = await fetch(`${server.origin}/x`, { redirect: 'manual' });
    const second = await fetch(`${server.origin}/x`);

    expect(first.status).toBe(302);
    expect(first.headers.get('location')).toBe('/elsewhere');
    expect(second.status).toBe(200);
  });

  it('clears both the recording and the queue on reset', async () => {
    server.replyOnce({ status: 500 });
    server.reset();

    const response = await fetch(`${server.origin}/x`);

    expect(response.status).toBe(200);
    expect(server.requests).toHaveLength(1);
  });

  it('listens on loopback, so the transport check exempts it by design', () => {
    expect(server.origin.startsWith('http://127.0.0.1:')).toBe(true);
    expect(server.host.startsWith('127.0.0.1:')).toBe(true);
  });

  it('joins a repeated header rather than keeping only one of them', async () => {
    await fetch(`${server.origin}/x`, {
      headers: new Headers([
        ['x-multi', 'one'],
        ['x-multi', 'two'],
      ]),
    });

    expect(server.requests[0]?.headers['x-multi']).toContain('one');
    expect(server.requests[0]?.headers['x-multi']).toContain('two');
  });
});

describe('findMarker', () => {
  it('finds each encoding the guard covers, and nothing in clean bytes', () => {
    for (const needle of MARKER_NEEDLES) {
      expect(findMarker(`prefix ${needle} suffix`)).toBe(needle);
    }

    expect(findMarker('authorization: Bearer sk_live_real')).toBeUndefined();
    expect(findMarker('')).toBeUndefined();
  });
});
