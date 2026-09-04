import { describe, expect, it } from 'vitest';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { PlanBuilder, SensitiveScrubError } from '@platform-sec/sensitive-string-http';
import type { ScrubPlan } from '@platform-sec/sensitive-string-http';
import { AxiosHeaders } from 'axios';
import type { AxiosError, AxiosResponse } from 'axios';

import { scrubError, scrubResponse } from './scrub.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

function planFor(): ScrubPlan {
  const builder = new PlanBuilder();

  builder.section('header').record('Authorization', new SensitiveString(CANARY, 'credential'));
  builder.section('query').record('token', new SensitiveString(CANARY, 'credential'));
  builder.section('body').record('card.number', new SensitiveString(CANARY, 'credential'));

  return builder.build();
}

function configWithSecret() {
  return {
    headers: new AxiosHeaders({ Authorization: `Bearer ${CANARY}` }),
    data: { card: { number: CANARY } },
    params: { token: CANARY },
    url: `https://api.example.com/x?token=${CANARY}`,
  };
}

describe('scrubResponse', () => {
  it('rewrites an AxiosHeaders bag through its own set(), and every other position', () => {
    const response = { config: configWithSecret(), request: {} } as unknown as AxiosResponse;

    scrubResponse(response, planFor());

    expect(JSON.stringify(response.config)).not.toContain(CANARY);
    expect(response.config.headers['Authorization']).toBe('[REDACTED:credential]');
    expect(response.request).toBeUndefined();
  });

  it('returns an empty-plan response untouched, request included', () => {
    const request = {};
    const response = { config: configWithSecret(), request } as unknown as AxiosResponse;

    expect(scrubResponse(response, new PlanBuilder().build())).toBe(response);
    expect(response.request).toBe(request);
  });
});

describe('scrubError', () => {
  it('rewrites config, the nested response config, and drops both request objects', () => {
    const error = {
      config: configWithSecret(),
      request: {},
      response: { config: configWithSecret(), request: {} },
    } as unknown as AxiosError;

    scrubError(error, planFor());

    expect(JSON.stringify(error.config)).not.toContain(CANARY);
    expect(JSON.stringify(error.response?.config)).not.toContain(CANARY);
    expect((error as { request?: unknown }).request).toBeUndefined();
    expect((error.response as { request?: unknown } | undefined)?.request).toBeUndefined();
  });

  it('refuses to hand back an object where the header survived', () => {
    const error = {
      config: { headers: Object.freeze({ Authorization: `Bearer ${CANARY}` }) },
    } as unknown as AxiosError;

    expect(() => scrubError(error, planFor())).toThrow(SensitiveScrubError);
  });

  it('names the client and the path, and no value, when it refuses', () => {
    const error = {
      config: { headers: Object.freeze({ Authorization: `Bearer ${CANARY}` }) },
    } as unknown as AxiosError;

    try {
      scrubError(error, planFor());
      expect.unreachable();
    } catch (caught) {
      const scrub = caught as SensitiveScrubError;

      expect(scrub.client).toBe('axios');
      expect(scrub.path).toBe("error.config.headers['authorization']");
      expect(scrub.message).not.toContain(CANARY);
    }
  });

  it('handles an error with no config, and one that is not an object', () => {
    const bare = { message: 'boom' } as unknown as AxiosError;

    expect(scrubError(bare, planFor())).toBe(bare);
    expect(scrubError('a string', planFor())).toBe('a string');
    expect(scrubError(null, planFor())).toBeNull();
  });

  it('returns an empty-plan error untouched, request included', () => {
    const request = {};
    const error = { config: configWithSecret(), request } as unknown as AxiosError;

    expect(scrubError(error, new PlanBuilder().build())).toBe(error);
    expect((error as { request?: unknown }).request).toBe(request);
  });
});
