import { afterEach, describe, expect, it } from 'vitest';
import {
  SensitiveString,
  registerPolicy,
  resetPolicies,
} from '@platform-sec/sensitive-string-core';

import { MarkerLeakError, UnserializableBodyError } from '../errors.js';
import { apiKey, bearer } from '../auth.js';
import { prepareRequest } from '../request.js';
import { findMarker } from '../testing.js';

/**
 * The guard, against the shapes section 2.1 of the design measured.
 *
 * Every row there is a way a marker reached the wire on a real client. The
 * assertions below are on the outgoing representation this package produces,
 * which is what the client is about to serialize, so a row that passes here is
 * a row that cannot reach a socket through the wrapper.
 */

const CANARY = 'LEAKED_SECRET_abc123xyz';
const base = { client: 'test', attempt: 1 } as const;

function token(): SensitiveString<'credential'> {
  return new SensitiveString(CANARY, 'credential');
}

/** What a caller does when they forget: interpolate, or hand the instance to a container. */
const marker = (): string => String(token());

afterEach(() => {
  resetPolicies();
});

describe('no marker survives preparation', () => {
  it('reveals every position section 2.1 measured, and the outgoing bytes hold no needle', () => {
    const prepared = prepareRequest(
      {
        method: 'POST',
        url: 'https://api.example.com/charges',
        headers: { Authorization: bearer(token()), 'x-api-key': apiKey(token()) },
        query: { token: token(), page: 2 },
        body: { amount: 100, card: { number: token() }, list: [token()] },
      },
      base
    );

    const wire = [
      prepared.url,
      Object.entries(prepared.headers)
        .map(([name, value]) => `${name}: ${value}`)
        .join('\n'),
      prepared.bodyText ?? '',
    ].join('\n');

    expect(findMarker(wire)).toBeUndefined();
    expect(wire).toContain(CANARY);
  });

  it.each([
    ['a header value', { headers: { Authorization: `Bearer ${marker()}` } }],
    ['a header set to the marker itself', { headers: { 'x-api-key': marker() } }],
    ['a JSON body field', { body: { token: marker() } }],
    ['an array body element', { body: [marker()] }],
    ['a query value', { query: { token: marker() } }],
    ['a form body field', { form: { token: marker() } }],
    ['a raw string body', { rawBody: marker() }],
    ['a Buffer body', { rawBody: Buffer.from(marker()) }],
    ['a caller-built URLSearchParams', { body: { p: new URLSearchParams({ token: marker() }) } }],
    ['a caller-built Headers', { body: { h: new Headers({ 'x-key': marker() }) } }],
  ])('refuses %s', (_name, part) => {
    expect(() =>
      prepareRequest({ method: 'POST', url: 'https://api.example.com/x', ...part }, base)
    ).toThrow(MarkerLeakError);
  });

  it('refuses a caller-built FormData part', () => {
    const form = new FormData();
    form.append('token', marker());

    expect(() =>
      prepareRequest({ method: 'POST', url: 'https://api.example.com/x', body: { form } }, base)
    ).toThrow(MarkerLeakError);
  });

  it('refuses a Map rather than shipping the empty object axios turns it into', () => {
    expect(() =>
      prepareRequest(
        { method: 'POST', url: 'https://api.example.com/x', body: { m: new Map([['t', 1]]) } },
        base
      )
    ).toThrow(UnserializableBodyError);
  });

  it('picks the marker up from a policy registered by the application', () => {
    registerPolicy(
      { name: 'credential', redact: () => '###hidden###', requireConstantTimeEquals: true },
      { overwrite: true }
    );

    expect(() =>
      prepareRequest(
        { method: 'POST', url: 'https://api.example.com/x', body: { token: '###hidden###' } },
        base
      )
    ).toThrow(MarkerLeakError);
  });

  it('reports a plaintext value that legitimately contains the marker, rather than sending it', () => {
    // A false positive is a thrown error naming the fix, never a silent send.
    // The value here is a bug report whose body quotes a redacted log line.
    expect(() =>
      prepareRequest(
        {
          method: 'POST',
          url: 'https://api.example.com/reports',
          body: { description: 'the log said [REDACTED:credential] and the call 401d' },
        },
        base
      )
    ).toThrow(/redaction marker/);
  });
});

describe('what the guard cannot see, asserted so the README stays honest', () => {
  it('does not read a stream body', async () => {
    const { Readable } = await import('node:stream');

    // Buffering an upload to scan it is not acceptable, so a stream passes
    // through unguarded. The gap is documented rather than papered over.
    const prepared = prepareRequest(
      {
        method: 'POST',
        url: 'https://api.example.com/upload',
        body: { file: Readable.from([marker()]) },
      },
      base
    );

    expect(prepared.plan.entries).toEqual([]);
  });

  it('does not see base64 the caller applied, unless asked', () => {
    const encoded = Buffer.from(marker()).toString('base64');

    expect(() =>
      prepareRequest(
        { method: 'POST', url: 'https://api.example.com/x', body: { blob: encoded } },
        base
      )
    ).not.toThrow();

    expect(() =>
      prepareRequest(
        { method: 'POST', url: 'https://api.example.com/x', body: { blob: encoded } },
        { ...base, scanBase64: true }
      )
    ).toThrow(MarkerLeakError);
  });
});
