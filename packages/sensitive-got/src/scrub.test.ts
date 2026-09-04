import { describe, expect, it } from 'vitest';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { PlanBuilder } from '@platform-sec/sensitive-string-http';
import type { ScrubPlan } from '@platform-sec/sensitive-string-http';

import { scrubError, scrubResponse } from './scrub.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';
const RAW_URL = `https://api.example.com/x?token=${CANARY}`;

function planFor(): ScrubPlan {
  const builder = new PlanBuilder();

  builder.section('header').record('authorization', new SensitiveString(CANARY, 'credential'));
  builder.section('query').record('token', new SensitiveString(CANARY, 'credential'));
  builder.section('body').record('card.number', new SensitiveString(CANARY, 'credential'));

  return builder.build();
}

describe('scrubError', () => {
  it("rewrites got 14's _init array, which keeps every raw options object", () => {
    const error = {
      options: {
        headers: { authorization: `Bearer ${CANARY}` },
        _init: [{ retry: { limit: 0 } }, { headers: { authorization: `Bearer ${CANARY}` } }],
      },
    };

    scrubError(error, planFor(), RAW_URL);

    const init = error.options._init[1] as { headers: Record<string, string> };

    expect(error.options.headers['authorization']).toBe('[REDACTED:credential]');
    expect(init.headers['authorization']).toBe('[REDACTED:credential]');
  });

  it('does not recurse into a nested _init, so a hostile shape cannot loop', () => {
    const inner: Record<string, unknown> = { headers: {} };
    inner['_init'] = [inner];

    const error = { options: { headers: {}, _init: [inner] } };

    expect(() => scrubError(error, planFor(), RAW_URL)).not.toThrow();
  });

  it('rewrites a URL option in both the URL and the string shape', () => {
    const asUrl = { options: { headers: {}, url: new URL(RAW_URL) } };
    const asString = { options: { headers: {}, url: RAW_URL } };

    scrubError(asUrl, planFor(), RAW_URL);
    scrubError(asString, planFor(), RAW_URL);

    expect(String(asUrl.options.url)).not.toContain(CANARY);
    expect(asUrl.options.url).toBeInstanceOf(URL);
    expect(String(asString.options.url)).not.toContain(CANARY);
    expect(typeof asString.options.url).toBe('string');
  });

  it('leaves a url option that is neither a URL nor a string alone', () => {
    const error = { options: { headers: {}, url: 42 } };

    expect(() => scrubError(error, planFor(), RAW_URL)).not.toThrow();
    expect(error.options.url).toBe(42);
  });

  it('rewrites the response url and the redirect chain beside it', () => {
    const error = {
      options: { headers: {} },
      response: { url: RAW_URL, redirectUrls: [new URL(RAW_URL), RAW_URL] },
    };

    scrubError(error, planFor(), RAW_URL);

    expect(JSON.stringify(error.response)).not.toContain(CANARY);
  });

  it('drops the request references on the error and on its response', () => {
    const error = {
      options: { headers: {} },
      request: { options: { headers: {} } },
      response: { request: { options: { headers: {} } }, req: {} },
    };

    scrubError(error, planFor(), RAW_URL);

    expect((error as { request?: unknown }).request).toBeUndefined();
    expect((error.response as { request?: unknown }).request).toBeUndefined();
    expect((error.response as { req?: unknown }).req).toBeUndefined();
  });

  it('replaces a serialized body wholesale and leaves a structured one addressable', () => {
    const error = {
      options: { headers: {}, body: `{"card":{"number":"${CANARY}"}}` },
    };

    scrubError(error, planFor(), RAW_URL);

    expect(error.options.body).toBe('[REDACTED:body]');
  });

  it('returns an empty-plan error untouched, and ignores a non-object', () => {
    const error = { options: { headers: { authorization: `Bearer ${CANARY}` } } };

    expect(scrubError(error, new PlanBuilder().build(), RAW_URL)).toBe(error);
    expect(error.options.headers.authorization).toContain(CANARY);
    expect(scrubError('a string', planFor(), RAW_URL)).toBe('a string');
  });

  it('survives options that are frozen, and options that are absent', () => {
    const frozen = { options: Object.freeze({ headers: {}, body: 'x' }) };

    expect(() => scrubError(frozen, planFor(), RAW_URL)).not.toThrow();
    expect(() => scrubError({ options: null }, planFor(), RAW_URL)).not.toThrow();
    expect(() => scrubError({}, planFor(), RAW_URL)).not.toThrow();
  });
});

describe('scrubResponse', () => {
  it('rewrites response.request.options and drops the request references', () => {
    const response = {
      url: RAW_URL,
      request: { options: { headers: { authorization: `Bearer ${CANARY}` } } },
      req: {},
    };

    scrubResponse(response, planFor());

    expect(JSON.stringify(response)).not.toContain(CANARY);
    expect(response.request).toBeUndefined();
    expect(response.req).toBeUndefined();
  });

  it('returns an empty-plan response untouched, and ignores a non-object', () => {
    const response = { request: { options: { headers: {} } } };

    expect(scrubResponse(response, new PlanBuilder().build())).toBe(response);
    expect(response.request).toBeDefined();
    expect(scrubResponse(null, planFor())).toBeNull();
  });
});
