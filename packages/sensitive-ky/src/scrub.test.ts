import { describe, expect, it } from 'vitest';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { PlanBuilder } from '@platform-sec/sensitive-string-http';
import type { ScrubPlan } from '@platform-sec/sensitive-string-http';

import { scrubError, scrubResponse } from './scrub.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

function planFor(sections: readonly ('header' | 'query' | 'body')[]): ScrubPlan {
  const builder = new PlanBuilder();
  const positions = { header: 'authorization', query: 'token', body: 'card.number' } as const;

  for (const section of sections) {
    builder.section(section).record(positions[section], new SensitiveString(CANARY, 'credential'));
  }

  return builder.build();
}

describe('scrubError', () => {
  it('sets the named header on the Request in place when nothing forces a rebuild', () => {
    const request = new Request('https://api.example.com/x', {
      headers: { authorization: `Bearer ${CANARY}` },
    });
    const error = { request };

    scrubError(error, planFor(['header']));

    expect(error.request).toBe(request);
    expect(error.request.headers.get('authorization')).toBe('[REDACTED:credential]');
  });

  it('replaces the Request wholesale when the plan names a body path', () => {
    const request = new Request('https://api.example.com/x', {
      method: 'POST',
      body: '{"card":{"number":"x"}}',
      headers: { authorization: `Bearer ${CANARY}` },
    });
    const error = { request };

    scrubError(error, planFor(['header', 'body']));

    expect(error.request).not.toBe(request);
    expect(error.request.body).toBeNull();
    expect(error.request.headers.get('authorization')).toBe('[REDACTED:credential]');
  });

  it("rebuilds from the scrubbed URL, since a Request's url has no setter", () => {
    const error = {
      request: new Request(`https://api.example.com/x?token=${CANARY}`),
    } as { request: Request; response?: unknown };

    scrubError(error, planFor(['query']));

    expect(error.request.url).not.toContain(CANARY);
  });

  it('drops the response when a query value was revealed, since Response.url is read-only', () => {
    const error = {
      request: new Request(`https://api.example.com/x?token=${CANARY}`),
      response: new Response('{}'),
    } as { request: Request; response?: unknown };

    scrubError(error, planFor(['query']));

    expect(error.response).toBeUndefined();
  });

  it("replaces ky's frozen options with a scrubbed copy", () => {
    const headers = new Headers({ authorization: `Bearer ${CANARY}` });
    const error = {
      options: Object.freeze({ headers, body: `{"card":{"number":"${CANARY}"}}`, method: 'POST' }),
    } as { options?: Record<string, unknown> };

    scrubError(error, planFor(['header', 'body']));

    expect(Object.isFrozen(error.options)).toBe(false);
    expect(error.options?.['body']).toBe('[REDACTED:body]');
    expect(error.options?.['method']).toBe('POST');
    expect(headers.get('authorization')).toBe('[REDACTED:credential]');
  });

  it('leaves options alone when the plan named no body path', () => {
    const error = { options: { headers: new Headers(), body: 'untouched' } };

    scrubError(error, planFor(['header']));

    expect(error.options.body).toBe('untouched');
  });

  it('returns an empty-plan error untouched, and ignores a non-object', () => {
    const request = new Request('https://api.example.com/x');
    const error = { request };

    expect(scrubError(error, new PlanBuilder().build())).toBe(error);
    expect(scrubError('a string', planFor(['header']))).toBe('a string');
    expect(scrubError(null, planFor(['header']))).toBeNull();
  });

  it('ignores an error whose request is not a Request', () => {
    const error = { request: { headers: {} }, options: undefined };

    expect(() => scrubError(error, planFor(['header']))).not.toThrow();
  });
});

describe('scrubResponse', () => {
  it('is a no-op by measurement: a Response carries no request headers', () => {
    const response = new Response('{}');

    expect(scrubResponse(response, planFor(['header']))).toBe(response);
  });
});
