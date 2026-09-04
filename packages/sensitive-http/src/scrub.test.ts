import { describe, expect, it } from 'vitest';
import { SensitiveString } from '@platform-sec/sensitive-string-core';

import { SensitiveScrubError } from './errors.js';
import {
  EMPTY_PLAN,
  PlanBuilder,
  assertHeadersScrubbed,
  markerFor,
  planIsEmpty,
  readHeader,
  scrubBody,
  scrubHeaderBag,
  scrubMessage,
  scrubQuery,
  scrubUrlString,
  splitPath,
} from './scrub.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

function planFor(): ReturnType<PlanBuilder['build']> {
  const builder = new PlanBuilder();

  builder.section('header').record('Authorization', new SensitiveString(CANARY, 'credential'));
  builder.section('body').record('card.number', new SensitiveString(CANARY, 'credential'));
  builder.section('query').record('token', new SensitiveString(CANARY, 'credential'));

  return builder.build();
}

describe('PlanBuilder', () => {
  it('lowercases header positions and keeps body and query positions verbatim', () => {
    const plan = planFor();

    expect(plan.headers).toEqual(['authorization']);
    expect(plan.bodyPaths).toEqual(['card.number']);
    expect(plan.queryKeys).toEqual(['token']);
  });

  it('records the redacted form and never the raw value', () => {
    const plan = planFor();

    expect(JSON.stringify(plan)).not.toContain(CANARY);
    expect(plan.entries.every((entry) => entry.marker === '[REDACTED:credential]')).toBe(true);
  });

  it('reports an empty plan for a request that carried nothing sensitive', () => {
    expect(planIsEmpty(new PlanBuilder().build())).toBe(true);
    expect(planIsEmpty(EMPTY_PLAN)).toBe(true);
    expect(planIsEmpty(planFor())).toBe(false);
  });
});

describe('scrubHeaderBag', () => {
  it('overwrites a plain record case-insensitively', () => {
    const bag = { Authorization: `Bearer ${CANARY}`, 'x-trace': 'abc' };

    scrubHeaderBag(bag, planFor());

    expect(bag.Authorization).toBe('[REDACTED:credential]');
    expect(bag['x-trace']).toBe('abc');
  });

  it('overwrites a Headers through set()', () => {
    const bag = new Headers({ authorization: `Bearer ${CANARY}` });

    scrubHeaderBag(bag, planFor());

    expect(bag.get('authorization')).toBe('[REDACTED:credential]');
  });

  it('leaves a header the client never kept alone', () => {
    const bag: Record<string, string> = {};

    scrubHeaderBag(bag, planFor());

    expect(bag).toEqual({});
  });
});

describe('scrubBody and scrubQuery', () => {
  it('overwrites a nested body path in place', () => {
    const body = { amount: 100, card: { number: CANARY } };

    scrubBody(body, planFor());

    expect(body).toEqual({ amount: 100, card: { number: '[REDACTED:credential]' } });
  });

  it('replaces an already-serialized body wholesale rather than by string surgery', () => {
    expect(scrubBody(`{"card":{"number":"${CANARY}"}}`, planFor())).toBe('[REDACTED:body]');
  });

  it('leaves a serialized body alone when the plan named no body path', () => {
    expect(scrubBody('{"a":1}', new PlanBuilder().build())).toBe('{"a":1}');
  });

  it('overwrites a URLSearchParams and a plain query record', () => {
    const params = new URLSearchParams({ token: CANARY, page: '2' });
    const record = { token: CANARY, page: '2' };

    scrubQuery(params, planFor());
    scrubQuery(record, planFor());

    expect(params.get('token')).toBe('[REDACTED:credential]');
    expect(params.get('page')).toBe('2');
    expect(record.token).toBe('[REDACTED:credential]');
  });
});

describe('assertHeadersScrubbed', () => {
  it('accepts a bag whose planned headers hold their markers', () => {
    const bag = { authorization: '[REDACTED:credential]' };

    expect(() => assertHeadersScrubbed(bag, planFor(), 'axios', 'error.config')).not.toThrow();
  });

  it('accepts a bag the client never kept the header in', () => {
    expect(() => assertHeadersScrubbed({}, planFor(), 'axios', 'error.config')).not.toThrow();
  });

  it('refuses to hand back a bag where the value survived', () => {
    const bag = { authorization: `Bearer ${CANARY}` };

    expect(() => assertHeadersScrubbed(bag, planFor(), 'axios', 'error.config')).toThrow(
      SensitiveScrubError
    );
  });
});

describe('helpers', () => {
  it('reads a header out of a record, a Headers and neither', () => {
    expect(readHeader({ Authorization: 'x' }, 'authorization')).toBe('x');
    expect(readHeader(new Headers({ authorization: 'x' }), 'authorization')).toBe('x');
    expect(readHeader(null, 'authorization')).toBeUndefined();
  });

  it('splits the path syntax the walker records', () => {
    expect(splitPath('card.number')).toEqual(['card', 'number']);
    expect(splitPath('tokens[0]')).toEqual(['tokens', '0']);
    expect(splitPath('a.b[2].c')).toEqual(['a', 'b', '2', 'c']);
  });

  it('finds a marker per section, and not across sections', () => {
    const plan = planFor();

    expect(markerFor(plan, 'header', 'Authorization')).toBe('[REDACTED:credential]');
    expect(markerFor(plan, 'query', 'card.number')).toBeUndefined();
  });

  it('tells two sections apart when they name the same position', () => {
    // `headers: { token }` and `searchParams: { token }` both record the
    // position `token`. Inferring the section from which list holds the
    // position answered `header` for both, so the query lookup found nothing
    // and the scrub fell back to a generic marker instead of the class.
    const builder = new PlanBuilder();

    builder.section('header').record('token', new SensitiveString(CANARY, 'credential'));
    builder.section('query').record('token', new SensitiveString(CANARY, 'sensitive'));

    const plan = builder.build();

    expect(markerFor(plan, 'header', 'token')).toBe('[REDACTED:credential]');
    expect(markerFor(plan, 'query', 'token')).toBe('[REDACTED:sensitive]');
  });
});

describe('scrubUrlString', () => {
  it('rewrites only the planned query keys and leaves the rest of the URL alone', () => {
    const scrubbed = scrubUrlString(
      `https://api.example.com/x?keep=1&token=${CANARY}#frag`,
      planFor()
    );

    expect(scrubbed).toContain('keep=1');
    expect(scrubbed).not.toContain(CANARY);
    expect(String(scrubbed)).toContain(encodeURIComponent('[REDACTED:credential]'));
  });

  it('leaves a URL alone when the plan named no query key', () => {
    const url = `https://api.example.com/x?token=${CANARY}`;

    expect(scrubUrlString(url, new PlanBuilder().build())).toBe(url);
  });

  it('leaves a URL alone when the planned key is not in it', () => {
    const url = 'https://api.example.com/x?other=1';

    expect(scrubUrlString(url, planFor())).toBe(url);
  });

  it('drops the query whole when the URL will not parse, rather than guessing', () => {
    expect(scrubUrlString(`/relative?token=${CANARY}`, planFor())).toBe('/relative?[REDACTED]');
    expect(scrubUrlString('/relative', planFor())).toBe('/relative');
  });

  it('passes anything that is not a string straight through', () => {
    expect(scrubUrlString(undefined, planFor())).toBeUndefined();
    expect(scrubUrlString(42, planFor())).toBe(42);
  });
});

describe('scrubMessage', () => {
  it('rewrites the message and the stack, because V8 bakes one into the other', () => {
    const raw = `https://api.example.com/x?token=${CANARY}`;
    const error = new Error(`Request failed: ${raw}`);

    expect(error.stack).toContain(CANARY);

    scrubMessage(error, raw, 'https://api.example.com/x?token=[REDACTED]');

    expect(error.message).not.toContain(CANARY);
    expect(error.stack).not.toContain(CANARY);
  });

  it('does nothing when the two URLs are the same, or the value is not an error', () => {
    const error = new Error(`untouched ${CANARY}`);

    scrubMessage(error, 'https://a/x', 'https://a/x');
    expect(error.message).toContain(CANARY);

    expect(() => scrubMessage(null, 'a', 'b')).not.toThrow();
    expect(() => scrubMessage('a string', 'a', 'b')).not.toThrow();
  });

  it('survives an error whose message cannot be reassigned', () => {
    const error = new Error('https://api.example.com/x');
    Object.defineProperty(error, 'message', { value: error.message, writable: false });

    expect(() =>
      scrubMessage(error, 'https://api.example.com/x', 'https://api.example.com/y')
    ).not.toThrow();
  });
});

describe('scrub edge cases', () => {
  it('ignores a header bag, a body and a query that are not objects', () => {
    const plan = planFor();

    expect(() => scrubHeaderBag(null, plan)).not.toThrow();
    expect(() => scrubHeaderBag('nope', plan)).not.toThrow();
    expect(() => scrubQuery(null, plan)).not.toThrow();
    expect(scrubBody(null, plan)).toBeNull();
    expect(scrubBody(42, plan)).toBe(42);
  });

  it('leaves a body path the client no longer holds alone', () => {
    const body = { amount: 100 };

    expect(scrubBody(body, planFor())).toEqual({ amount: 100 });
  });

  it('leaves a query key the client no longer holds alone', () => {
    const params = new URLSearchParams({ page: '2' });

    scrubQuery(params, planFor());

    expect(params.toString()).toBe('page=2');
  });

  it('survives a frozen header bag rather than taking the call down', () => {
    const bag = Object.freeze({ authorization: `Bearer ${CANARY}` });

    expect(() => scrubHeaderBag(bag, planFor())).not.toThrow();

    // The value did survive, so the assertion is what refuses to hand it back.
    expect(() => assertHeadersScrubbed(bag, planFor(), 'test', 'error.config')).toThrow(
      SensitiveScrubError
    );
  });

  it('reads no header out of a bag whose accessor throws', () => {
    const hostile = {
      get(): never {
        throw new Error('nope');
      },
      set(): void {
        throw new Error('nope');
      },
    };

    expect(readHeader(hostile, 'authorization')).toBeUndefined();
    expect(() => scrubHeaderBag(hostile, planFor())).not.toThrow();
  });
});
