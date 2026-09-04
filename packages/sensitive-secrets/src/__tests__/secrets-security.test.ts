import { describe, it, expect } from 'vitest';
import { SensitiveString } from '@platform-sec/sensitive-string-core';

import { parsePayload } from '../decode.js';
import { assertEverySourceSwept, assertNoCanary, errorText, sweep } from '../testing.js';
import type { SweepCase } from '../testing.js';
import { put, putJson } from '../write.js';
import type { SecretLoadEvent } from '../types.js';
import * as secrets from '../index.js';
import { FakeSecretSource } from './fake-source.js';

/**
 * The canary sweep and the error sweep.
 *
 * Every entry point is driven with a canary in every position the provider
 * accepts, each failure mode the package can produce is forced, and the canary
 * is asserted absent from every rendering of what came back: the value, the
 * error message, the stack, `JSON.stringify` of the error, and the `cause`
 * chain at any depth.
 */

/** Exactly 20 characters, the length V8 echoes whole into a SyntaxError. */
const SHORT_CANARY = 'LEAKED_SECRET_abc123';
const CANARY = 'LEAKED_SECRET_abc123xyz';
const CONTEXT = { name: 'sweep', reason: 'test' };
const REF = { path: 'prod/db', version: '7', metadata: {} };

function source(): FakeSecretSource {
  return FakeSecretSource.of({
    // A bare string where a JSON read will be attempted: the failure that
    // leaks, and the one nobody writes a test for.
    'prod/bare': { payload: { kind: 'string', value: SHORT_CANARY } },
    'prod/long': { payload: { kind: 'string', value: `${CANARY}-and-then-some-more` } },
    'prod/json': {
      payload: { kind: 'string', value: JSON.stringify({ username: 'app', password: CANARY }) },
    },
    'prod/array': { payload: { kind: 'string', value: JSON.stringify([CANARY]) } },
    'prod/number': { payload: { kind: 'string', value: JSON.stringify({ password: 12345 }) } },
    'prod/nested': {
      payload: { kind: 'string', value: JSON.stringify({ db: { password: CANARY } }) },
    },
    'prod/map': { payload: { kind: 'map', value: { password: CANARY } } },
    'prod/error': { payload: { kind: 'string', value: 'unused' } },
  });
}

const CASES: readonly SweepCase[] = [
  { name: 'get on a single value', run: () => source().get('prod/bare') },
  { name: 'get on a map payload', run: () => source().get('prod/map') },
  { name: 'get on an absent secret', run: () => source().get('prod/missing') },
  { name: 'getOptional on an absent secret', run: () => source().getOptional('prod/missing') },
  {
    name: 'getJson on a bare 20-character string',
    run: () => source().getJson('prod/bare', { fields: { password: 'credential' } }),
  },
  {
    name: 'getJson on a longer bare string',
    run: () => source().getJson('prod/long', { fields: { password: 'credential' } }),
  },
  {
    name: 'getJson on a JSON array',
    run: () => source().getJson('prod/array', { fields: {} }),
  },
  {
    name: 'getJson with a declared field the payload lacks',
    run: () => source().getJson('prod/json', { fields: { missing: 'credential' } }),
  },
  {
    name: 'getJson with a declared field that is not a string',
    run: () => source().getJson('prod/number', { fields: { password: 'credential' } }),
  },
  {
    name: 'getJson on a nested payload',
    run: () => source().getJson('prod/nested', { fields: { 'db.password': 'credential' } }),
  },
  {
    name: 'getAll with no fallback',
    run: () => source().getAll('prod/json', {} as unknown as { fallback: 'plain' }),
  },
  {
    name: 'getAll on a store that is secret by construction',
    run: () => source().getAll('prod/json', { fallback: 'credential' }),
  },
  {
    // A mixed store's `plain` fallback is a caller decision to leave a key
    // unwrapped, so the sweep drives it with rules that cover the secret half.
    // Sweeping `fallback: 'plain'` with no rules would assert that the library
    // protects a value the caller asked it not to protect.
    name: 'getAll on a mixed store with rules for the secrets',
    run: () =>
      source().getAll('prod/json', {
        rules: [{ pattern: /password|token|key/i, klass: 'credential' }],
        fallback: 'plain',
      }),
  },
  {
    name: 'put of a stringified instance',
    run: () =>
      // eslint-disable-next-line @typescript-eslint/restrict-template-expressions -- the implicit coercion is the subject of this case
      put(source(), 'prod/json', `${new SensitiveString(CANARY, 'credential')}`, {
        context: CONTEXT,
      }),
  },
  {
    name: 'put with no context',
    run: () => put(source(), 'prod/json', CANARY, {} as unknown as { context: typeof CONTEXT }),
  },
  {
    name: 'putJson of a mixed body',
    run: () =>
      putJson(
        source(),
        'prod/map',
        { password: new SensitiveString(CANARY, 'credential'), note: CANARY },
        { context: CONTEXT }
      ),
  },
  {
    name: 'parsePayload on a bare string',
    run: () => parsePayload(SHORT_CANARY, REF),
  },
];

describe('the error sweep', () => {
  it('leaks the canary in no result and no error', async () => {
    const results = await sweep(CANARY, CASES);

    expect(results).toHaveLength(CASES.length);
  });

  it('leaks the 20-character canary either, which is the length V8 echoes whole', async () => {
    await sweep(SHORT_CANARY, CASES);
  });

  it('forces at least one failure, so a sweep of only happy paths is impossible', async () => {
    const results = await sweep(CANARY, CASES);

    expect(results.filter((result) => result.threw).length).toBeGreaterThan(5);
  });

  it('checks the cause chain, which is what the decode guard turns on', () => {
    const chained = new Error('outer', {
      cause: new Error('inner', { cause: new Error(`deep ${CANARY}`) }),
    });

    expect(errorText(chained)).toContain(CANARY);
    expect(errorText(new Error('outer'))).not.toContain(CANARY);
  });

  it('survives a cycle in an error it is asked to render', () => {
    const cyclic = new Error('outer') as Error & { cause?: unknown };
    cyclic.cause = cyclic;

    expect(() => errorText(cyclic)).not.toThrow();
  });
});

describe('the load event sweep', () => {
  it('carries no secret material in any field of a single event', async () => {
    const events: SecretLoadEvent[] = [];
    const loaded = FakeSecretSource.of(
      {
        'prod/token': {
          payload: { kind: 'string', value: CANARY },
          metadata: { arn: `arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/token` },
        },
      },
      { onLoad: (event) => events.push(event) }
    );

    await loaded.get('prod/token');

    assertNoCanary(CANARY, events, 'the single load event');
  });

  it('carries no secret material in any field of a bulk event', async () => {
    const events: SecretLoadEvent[] = [];
    const loaded = FakeSecretSource.of(
      { 'prod/db': { payload: { kind: 'map', value: { password: CANARY, host: CANARY } } } },
      { onLoad: (event) => events.push(event) }
    );

    await loaded.getAll('prod/db', { fallback: 'credential' });

    assertNoCanary(CANARY, events, 'the bulk load event');
  });

  it('lists the key names, since an audit record without them is useless', async () => {
    const events: SecretLoadEvent[] = [];
    const loaded = FakeSecretSource.of(
      { 'prod/db': { payload: { kind: 'map', value: { password: CANARY } } } },
      { onLoad: (event) => events.push(event) }
    );

    await loaded.getAll('prod/db', { fallback: 'credential' });

    const [event] = events;

    if (event?.kind !== 'bulk') {
      throw new Error('expected a bulk event');
    }

    expect(event.keys).toEqual(['password']);
  });
});

describe('records handed back', () => {
  it('renders as markers when logged whole', async () => {
    const record = await source().getJson('prod/json', {
      fields: { username: 'sensitive', password: 'credential' },
    });

    assertNoCanary(CANARY, { fields: record.fields, extra: record.extra }, 'a getJson record');
    expect(JSON.stringify(record.fields)).not.toContain(CANARY);
  });

  it('carries no provider response object', async () => {
    const record = await source().get('prod/bare');

    expect(Object.keys(record).sort()).toEqual(['ref', 'value']);
    expect(Object.keys(record.ref).sort()).toEqual(['metadata', 'path', 'version']);
  });
});

describe('the registration test', () => {
  it('fails if a source implementation has no sweep entry', () => {
    expect(() => assertEverySourceSwept({ FakeSecretSource }, [])).toThrow(
      /no sweep entry: FakeSecretSource/
    );
  });

  it('passes when every exported source is swept', () => {
    expect(() => assertEverySourceSwept({ FakeSecretSource }, ['FakeSecretSource'])).not.toThrow();
  });

  it('finds no unswept source in the shared package, which exports only the base', () => {
    expect(() => assertEverySourceSwept(secrets, [])).not.toThrow();
  });
});
