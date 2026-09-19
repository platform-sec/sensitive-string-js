import { describe, expect, it, vi } from 'vitest';
import { DestinationRestrictedError, SensitiveString } from '@platform-sec/sensitive-string-core';

import { InsecureTransportError, MarkerLeakError } from './errors.js';
import { apiKey, basic, bearer } from './auth.js';
import { prepareRequest } from './request.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';
const base = { client: 'test', attempt: 1 } as const;

function token(): SensitiveString<'credential'> {
  return new SensitiveString(CANARY, 'credential');
}

describe('prepareRequest', () => {
  it('reveals a header, a query value and a body field into a fresh structure', () => {
    const prepared = prepareRequest(
      {
        method: 'post',
        url: 'https://api.example.com/charges',
        headers: { Authorization: bearer(token()) },
        query: { token: token() },
        body: { amount: 100, card: { number: token() } },
      },
      base
    );

    expect(prepared.method).toBe('POST');
    expect(prepared.headers['Authorization']).toBe(`Bearer ${CANARY}`);
    expect(new URL(prepared.url).searchParams.get('token')).toBe(CANARY);
    expect(prepared.bodyText).toBe(`{"amount":100,"card":{"number":"${CANARY}"}}`);
    expect(prepared.plan.headers).toEqual(['authorization']);
    expect(prepared.plan.queryKeys).toEqual(['token']);
    expect(prepared.plan.bodyPaths).toEqual(['card.number']);
  });

  it('reveals a host-bound credential toward its host and refuses it toward any other', () => {
    // The `host` tag this package writes per attempt is what core's destination
    // binding reads, so a value bound at construction works through every
    // client built on this layer with nothing configured here, and refuses
    // when the URL the program computed points somewhere else. The wrong host
    // below is the corpus's shape: the right host as a prefix of an attacker's.
    const bound = new SensitiveString(CANARY, 'credential', 'registry', {
      destinations: { hosts: ['api.example.com'] },
    });

    const prepared = prepareRequest(
      {
        method: 'GET',
        url: 'https://api.example.com/v2/',
        headers: { Authorization: bearer(bound) },
      },
      base
    );
    expect(prepared.headers['Authorization']).toBe(`Bearer ${CANARY}`);

    for (const url of [
      'https://api.example.com.attacker.net/v2/',
      'https://api.example.com:8443/v2/',
      'https://other.example.com/v2/',
    ]) {
      let thrown: unknown;
      try {
        prepareRequest({ method: 'GET', url, headers: { Authorization: bearer(bound) } }, base);
      } catch (error) {
        thrown = error;
      }

      expect(thrown, url).toBeInstanceOf(DestinationRestrictedError);
      expect(String(thrown), url).not.toContain(CANARY);
    }
  });

  it('builds a form body the guard can read in its percent encoding', () => {
    const prepared = prepareRequest(
      { method: 'POST', url: 'https://api.example.com/t', form: { token: token(), grant: 'x' } },
      base
    );

    expect(prepared.formText).toBe(`token=${encodeURIComponent(CANARY)}&grant=x`);
  });

  it('refuses a marker a caller interpolated into a header', () => {
    expect(() =>
      prepareRequest(
        {
          method: 'GET',
          url: 'https://api.example.com/x',
          // Interpolating an instance is the footgun under test: exactly what a
          // caller does by accident, and exactly what the guard has to catch.
          // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
          headers: { Authorization: `Bearer ${token()}` },
        },
        base
      )
    ).toThrow(MarkerLeakError);
  });

  it('refuses a marker inside a caller-built URLSearchParams in the body', () => {
    expect(() =>
      prepareRequest(
        {
          method: 'POST',
          url: 'https://api.example.com/x',
          body: { params: new URLSearchParams({ token: String(token()) }) },
        },
        base
      )
    ).toThrow(MarkerLeakError);
  });

  it('refuses a marker inside a caller-built Headers or FormData in the body', () => {
    const withHeaders = () =>
      prepareRequest(
        {
          method: 'POST',
          url: 'https://api.example.com/x',
          body: { h: new Headers({ 'x-api-key': String(token()) }) },
        },
        base
      );

    const form = new FormData();
    form.append('token', String(token()));

    const withForm = () =>
      prepareRequest({ method: 'POST', url: 'https://api.example.com/x', body: { form } }, base);

    expect(withHeaders).toThrow(MarkerLeakError);
    expect(withForm).toThrow(MarkerLeakError);
  });

  it('refuses a marker in a Buffer body', () => {
    expect(() =>
      prepareRequest(
        {
          method: 'POST',
          url: 'https://api.example.com/x',
          rawBody: Buffer.from(String(token())),
        },
        base
      )
    ).toThrow(MarkerLeakError);
  });

  it('refuses a credential over plaintext before it reveals anything', () => {
    const auditReveal = vi.fn();

    expect(() =>
      prepareRequest(
        {
          method: 'POST',
          url: 'http://api.example.com/charges',
          headers: { Authorization: bearer(token()) },
        },
        { ...base, context: { name: 'x', auditReveal } }
      )
    ).toThrow(InsecureTransportError);

    expect(auditReveal).not.toHaveBeenCalled();
  });

  it('defaults to refusing redirects once a credential sits in a non-standard header', () => {
    const prepared = prepareRequest(
      {
        method: 'GET',
        url: 'https://api.example.com/x',
        headers: { 'x-api-key': apiKey(token()) },
      },
      base
    );

    expect(prepared.redirects).toBe(false);
  });

  it("leaves the client's redirect handling alone when only Authorization carries one", () => {
    const prepared = prepareRequest(
      {
        method: 'GET',
        url: 'https://api.example.com/x',
        headers: { Authorization: bearer(token()) },
      },
      { ...base, client: 'axios' }
    );

    expect(prepared.redirects).toBe('client');
  });

  it('refuses redirects for an unmeasured client even in a header the spec strips', () => {
    // The exemption is a claim about an implementation somebody checked, and
    // the survey behind it found Node clients that forward `Authorization`
    // across origins. A wrapper for one of those, passing a name this package
    // does not know, must not inherit the exemption by default.
    const prepared = prepareRequest(
      {
        method: 'GET',
        url: 'https://api.example.com/x',
        headers: { Authorization: bearer(token()) },
      },
      { ...base, client: 'some-vendor-client' }
    );

    expect(prepared.redirects).toBe(false);
  });

  it('lets an explicit allowedHosts win for an unmeasured client', () => {
    // Naming the hosts is the caller saying they have thought about it, which
    // is the one thing that outranks the default either way.
    const prepared = prepareRequest(
      {
        method: 'GET',
        url: 'https://api.example.com/x',
        headers: { Authorization: bearer(token()) },
      },
      { ...base, client: 'some-vendor-client', allowedHosts: ['api.example.com'] }
    );

    expect(prepared.redirects).toEqual(['api.example.com']);
  });

  it('logs a redacted copy before anything is revealed', () => {
    const seen: unknown[] = [];

    prepareRequest(
      {
        method: 'POST',
        url: 'https://api.example.com/charges',
        headers: { Authorization: bearer(token()) },
        body: { card: { number: token() }, when: new Date(0), cycle: undefined },
      },
      { ...base, log: (redacted) => seen.push(redacted) }
    );

    const text = JSON.stringify(seen[0]);

    expect(text).not.toContain(CANARY);
    expect(text).toContain('[REDACTED:credential]');
  });

  it('drops an absent optional header rather than sending it empty', () => {
    const prepared = prepareRequest(
      {
        method: 'GET',
        url: 'https://api.example.com/x',
        headers: { 'x-trace': undefined, 'x-none': null },
      },
      base
    );

    expect(Object.keys(prepared.headers)).toEqual([]);
  });

  it('carries the plan and the context out for the client package to use', () => {
    const prepared = prepareRequest(
      {
        method: 'GET',
        url: 'https://api.example.com/x',
        headers: { Authorization: basic('svc', token()) },
      },
      { ...base, client: 'axios', reason: 'billing' }
    );

    expect(prepared.context.reason).toBe('billing');
    expect(prepared.context.tags).toMatchObject({ client: 'axios', sink: 'http', attempt: 1 });
    expect(prepared.plan.entries).toHaveLength(1);
  });

  it('keeps every value of a repeated query key, rather than only the last', () => {
    const prepared = prepareRequest(
      {
        method: 'GET',
        url: 'https://api.example.com/x',
        query: { tag: ['a', 'b', token()] },
      },
      base
    );

    // `URLSearchParams.set` replaces every existing value for the key, so an
    // earlier version of this sent `tag=<last>` alone and dropped the rest.
    expect(new URL(prepared.url).searchParams.getAll('tag')).toEqual(['a', 'b', CANARY]);
  });

  it('replaces a query key the caller already put in the URL, and keeps the others', () => {
    const prepared = prepareRequest(
      {
        method: 'GET',
        url: 'https://api.example.com/x?keep=1&token=stale',
        query: { token: token() },
      },
      base
    );

    const params = new URL(prepared.url).searchParams;

    expect(params.get('keep')).toBe('1');
    expect(params.getAll('token')).toEqual([CANARY]);
  });

  it('numbers the hop, so an audit record tells a redirect from a retry', () => {
    const prepared = prepareRequest(
      {
        method: 'GET',
        url: 'https://api.example.com/x',
        headers: { Authorization: bearer(token()) },
      },
      { ...base, attempt: 2, hop: 3 }
    );

    expect(prepared.context.tags).toMatchObject({ attempt: 2, hop: 3 });
    expect(prepared.descriptor.hop).toBe(3);
  });

  it('defaults the hop to 1 for the request the caller made', () => {
    const prepared = prepareRequest({ method: 'GET', url: 'https://api.example.com/x' }, base);

    expect(prepared.descriptor.hop).toBe(1);
  });

  it('produces an empty plan for a request that carried nothing sensitive', () => {
    const prepared = prepareRequest(
      { method: 'GET', url: 'https://api.example.com/x', headers: { 'x-trace': 'abc' } },
      base
    );

    expect(prepared.plan.entries).toEqual([]);
    expect(prepared.redirects).toBe('client');
  });
});
