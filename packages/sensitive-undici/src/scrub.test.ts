import { describe, expect, it } from 'vitest';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { PlanBuilder } from '@platform-sec/sensitive-string-http';
import type { ScrubPlan } from '@platform-sec/sensitive-string-http';

import { scrubError } from './scrub.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';
const RAW_URL = `https://api.example.com/x?token=${CANARY}`;

function planFor(): ScrubPlan {
  const builder = new PlanBuilder();

  builder.section('header').record('authorization', new SensitiveString(CANARY, 'credential'));
  builder.section('query').record('token', new SensitiveString(CANARY, 'credential'));

  return builder.build();
}

describe('scrubError', () => {
  it('rewrites the headers undici attached to the error', () => {
    const error = new Error('failed') as Error & { headers?: Record<string, string> };
    error.headers = { authorization: `Bearer ${CANARY}`, 'x-trace': 'abc' };

    scrubError(error, planFor(), RAW_URL);

    expect(error.headers['authorization']).toBe('[REDACTED:credential]');
    expect(error.headers['x-trace']).toBe('abc');
  });

  it('rewrites the URL out of the message and out of the cause', () => {
    const error = new Error(`request to ${RAW_URL} failed`) as Error & { cause?: unknown };
    error.cause = new Error(`socket hang up for ${RAW_URL}`);

    scrubError(error, planFor(), RAW_URL);

    expect(error.message).not.toContain(CANARY);
    expect((error.cause as Error).message).not.toContain(CANARY);
  });

  it('returns an empty-plan error untouched', () => {
    const error = new Error(`request to ${RAW_URL} failed`);

    expect(scrubError(error, new PlanBuilder().build(), RAW_URL)).toBe(error);
    expect(error.message).toContain(CANARY);
  });

  it('ignores a rejection that is not an object', () => {
    expect(scrubError('a string', planFor(), RAW_URL)).toBe('a string');
    expect(scrubError(null, planFor(), RAW_URL)).toBeNull();
  });
});
