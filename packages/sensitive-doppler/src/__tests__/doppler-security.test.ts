import { describe, it, expect } from 'vitest';
import { describeLabelDisclosure } from '@platform-sec/sensitive-string-secrets';
import type { SecretLoadEvent } from '@platform-sec/sensitive-string-secrets';
import {
  assertEverySourceSwept,
  assertNoCanary,
  sweep,
} from '@platform-sec/sensitive-string-secrets/testing';
import type { SweepCase } from '@platform-sec/sensitive-string-secrets/testing';

import * as dopplerPackage from '../index.js';
import { FakeTransport, TEST_TOKEN, source } from './fake-transport.js';

/** Exactly 20 characters, the length V8 echoes whole into a SyntaxError. */
const SHORT_CANARY = 'LEAKED_SECRET_abc123';
const CANARY = 'LEAKED_SECRET_abc123xyz';

function transport(): FakeTransport {
  return FakeTransport.of({
    'payments/prod': {
      body: { LOG_LEVEL: 'info', STRIPE_SECRET_KEY: CANARY, DATABASE_URL: CANARY },
    },
    'payments/short': { body: { API_KEY: SHORT_CANARY } },
    'payments/dotted': { body: { 'tls.key': CANARY } },
    'payments/array': { body: [CANARY] },
    'payments/denied': { status: 403, messages: ['You do not have access to this config'] },
    'payments/broken': { status: 500, messages: ['Internal error'] },
  });
}

const CASES: readonly SweepCase[] = [
  {
    name: 'getAll on a mixed config',
    run: () =>
      source(transport()).getAll('prod', {
        rules: [{ pattern: /KEY|URL/i, klass: 'credential' }],
        fallback: 'plain',
      }),
  },
  {
    name: 'getAll with everything closed',
    run: () => source(transport()).getAll('prod', { fallback: 'credential' }),
  },
  {
    name: 'getAll on a config with a dotted key',
    run: () => source(transport()).getAll('dotted', { fallback: 'credential' }),
  },
  {
    name: 'getAll on a response that is not a map',
    run: () => source(transport()).getAll('array', { fallback: 'credential' }),
  },
  {
    name: 'getJson with a declared field the config lacks',
    run: () => source(transport()).getJson('prod', { fields: { MISSING: 'credential' } }),
  },
  {
    name: 'getJson on a 20-character secret',
    run: () => source(transport()).getJson('short', { fields: { API_KEY: 'credential' } }),
  },
  { name: 'get on a config that holds named fields', run: () => source(transport()).get('prod') },
  { name: 'an absent config', run: () => source(transport()).get('missing') },
  {
    name: 'a token whose scope does not cover the config',
    run: () => source(transport()).getAll('denied', { fallback: 'credential' }),
  },
  {
    name: 'a service failure',
    run: () => source(transport()).getAll('broken', { fallback: 'credential' }),
  },
];

describe('the doppler sweep', () => {
  it('leaks the canary in no result and no error', async () => {
    const results = await sweep(CANARY, CASES);

    expect(results).toHaveLength(CASES.length);
  });

  it('leaks the 20-character canary either', async () => {
    await sweep(SHORT_CANARY, CASES);
  });

  it('leaks the token in no result and no error', async () => {
    await sweep(TEST_TOKEN, CASES);
  });

  it('forces failures rather than sweeping only happy paths', async () => {
    const results = await sweep(CANARY, CASES);

    expect(results.filter((result) => result.threw).length).toBeGreaterThan(3);
  });
});

describe('load events', () => {
  it('carry no secret material and no token', async () => {
    const events: SecretLoadEvent[] = [];
    const doppler = source(transport(), { onLoad: (event) => events.push(event) });

    await doppler.getAll('prod', { fallback: 'credential' });

    assertNoCanary(CANARY, events, 'the doppler load events');
    assertNoCanary(TEST_TOKEN, events, 'the doppler load events');
  });
});

describe('labels', () => {
  it('disclose nothing under the rule', async () => {
    const config = await source(transport()).getAll('prod', { fallback: 'credential' });

    for (const value of config.fields.values()) {
      expect(describeLabelDisclosure(value.label ?? '')).toEqual([]);
    }
  });
});

describe('the registration test', () => {
  it('fails if a source implementation has no sweep entry', () => {
    expect(() => assertEverySourceSwept(dopplerPackage, [])).toThrow(
      /no sweep entry: DopplerSecretSource/
    );
  });

  it('passes now that DopplerSecretSource is swept', () => {
    expect(() => assertEverySourceSwept(dopplerPackage, ['DopplerSecretSource'])).not.toThrow();
  });
});
