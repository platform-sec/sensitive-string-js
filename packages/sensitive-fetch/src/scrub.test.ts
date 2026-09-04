import { describe, expect, it } from 'vitest';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { PlanBuilder, bearer, renderAuthHeader } from '@platform-sec/sensitive-string-http';
import type { ScrubPlan } from '@platform-sec/sensitive-string-http';

import { scrubError, scrubResponse } from './scrub.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';
const RAW_URL = `https://api.example.com/x?token=${CANARY}`;

function planFor(): ScrubPlan {
  const builder = new PlanBuilder();

  builder.section('header').record('authorization', new SensitiveString(CANARY, 'credential'));
  builder.section('query').record('token', new SensitiveString(CANARY, 'credential'));

  return builder.build();
}

describe('scrubError', () => {
  it('rewrites the URL out of the message and out of the cause', () => {
    const error = new TypeError(`fetch failed: ${RAW_URL}`);
    error.cause = new Error(`connect ECONNREFUSED for ${RAW_URL}`);

    scrubError(error, planFor(), RAW_URL);

    expect(error.message).not.toContain(CANARY);
    expect((error.cause as Error).message).not.toContain(CANARY);
  });

  it('rewrites the headers of a Request the error carries', () => {
    const builder = new PlanBuilder();
    const rendered = renderAuthHeader(
      bearer(new SensitiveString(CANARY, 'credential')),
      'authorization',
      { name: 'test' },
      builder.section('header')
    );

    const error = new Error('failed') as Error & { request?: Request };
    error.request = new Request('https://api.example.com/x', {
      headers: { authorization: rendered },
    });

    scrubError(error, builder.build(), 'https://api.example.com/x');

    expect(error.request.headers.get('authorization')).toBe('[REDACTED:credential]');
  });

  it('returns an empty-plan error untouched, so an unadopted call site is unaffected', () => {
    const error = new TypeError(`fetch failed: ${RAW_URL}`);

    expect(scrubError(error, new PlanBuilder().build(), RAW_URL)).toBe(error);
    expect(error.message).toContain(CANARY);
  });

  it('ignores a rejection that is not an object', () => {
    expect(scrubError('a string', planFor(), RAW_URL)).toBe('a string');
    expect(scrubError(null, planFor(), RAW_URL)).toBeNull();
  });

  it('ignores a cause that is not an object', () => {
    const error = new TypeError('failed') as TypeError & { cause?: unknown };
    error.cause = 'a string';

    expect(() => scrubError(error, planFor(), RAW_URL)).not.toThrow();
  });
});

describe('scrubResponse', () => {
  it('is a no-op by measurement: a Response carries no request headers', () => {
    const response = new Response('{}');

    expect(scrubResponse(response, planFor())).toBe(response);
  });
});
