import { describe, it, expect } from 'vitest';
import { describeLabelDisclosure } from '@platform-sec/sensitive-string-secrets';
import type { SecretLoadEvent } from '@platform-sec/sensitive-string-secrets';
import {
  assertEverySourceSwept,
  assertNoCanary,
  sweep,
} from '@platform-sec/sensitive-string-secrets/testing';
import type { SweepCase } from '@platform-sec/sensitive-string-secrets/testing';

import * as awsPackage from '../index.js';
import {
  ACCOUNT,
  FakeSecretsManager,
  arnFor,
  awsError,
  describeResponse,
  getResponse,
  source,
} from './fake-client.js';

/**
 * The provider sweep, against this package's own fixtures.
 *
 * Every secret-bearing field in a fixture carries a canary, so a fixture that
 * leaks through a code path is caught by the same sweep that would catch a real
 * leak.
 */

/** Exactly 20 characters, the length V8 echoes whole into a SyntaxError. */
const SHORT_CANARY = 'LEAKED_SECRET_abc123';
const CANARY = 'LEAKED_SECRET_abc123xyz';

function client(): FakeSecretsManager {
  return FakeSecretsManager.of({
    'prod/db': {
      get: getResponse('prod/db', {
        SecretString: JSON.stringify({ username: 'app', password: CANARY }),
      }),
      describe: describeResponse('prod/db'),
    },
    'prod/short': { get: getResponse('prod/short', { SecretString: SHORT_CANARY }) },
    'prod/stripe': { get: getResponse('prod/stripe', { SecretString: CANARY }) },
    'prod/binary': {
      get: getResponse('prod/binary', { SecretBinary: new TextEncoder().encode(CANARY) }),
    },
    'prod/array': { get: getResponse('prod/array', { SecretString: JSON.stringify([CANARY]) }) },
    'prod/nested': {
      get: getResponse('prod/nested', {
        SecretString: JSON.stringify({ db: { password: CANARY } }),
      }),
    },
    'prod/dotted': {
      get: getResponse('prod/dotted', { SecretString: JSON.stringify({ 'tls.key': CANARY }) }),
    },
    'prod/empty': { get: getResponse('prod/empty') },
    'prod/denied': { get: awsError('AccessDeniedException', 'not authorized') },
    'prod/broken': { get: awsError('InternalServiceError', 'an internal error') },
    [arnFor('prod/db')]: {
      get: getResponse('prod/db', { SecretString: JSON.stringify({ password: CANARY }) }),
    },
  });
}

const CASES: readonly SweepCase[] = [
  { name: 'get on a single-value secret', run: () => source(client()).get('prod/stripe') },
  { name: 'get on a binary secret', run: () => source(client()).get('prod/binary') },
  { name: 'get on a secret with no value', run: () => source(client()).get('prod/empty') },
  {
    name: 'getJson on a JSON secret',
    run: () => source(client()).getJson('prod/db', { fields: { password: 'credential' } }),
  },
  {
    name: 'getJson with a declared field the payload lacks',
    run: () => source(client()).getJson('prod/db', { fields: { missing: 'credential' } }),
  },
  {
    name: 'getJson on a secret that is not JSON',
    run: () => source(client()).getJson('prod/stripe', { fields: { password: 'credential' } }),
  },
  {
    name: 'getJson on a 20-character secret that is not JSON',
    run: () => source(client()).getJson('prod/short', { fields: { password: 'credential' } }),
  },
  {
    name: 'getJson on a payload that decodes to an array',
    run: () => source(client()).getJson('prod/array', { fields: { password: 'credential' } }),
  },
  {
    name: 'getAll on a JSON secret',
    run: () => source(client()).getAll('prod/db', { fallback: 'credential' }),
  },
  {
    name: 'getAll on a nested payload',
    run: () => source(client()).getAll('prod/nested', { fallback: 'credential' }),
  },
  {
    name: 'getAll on a payload with a dotted key',
    run: () => source(client()).getAll('prod/dotted', { fallback: 'credential' }),
  },
  {
    name: 'getAll on a secret that is not JSON',
    run: () => source(client()).getAll('prod/stripe', { fallback: 'credential' }),
  },
  {
    name: 'get on a path that holds named fields',
    run: () => source(client()).get('prod/db'),
  },
  { name: 'an absent secret', run: () => source(client()).get('prod/missing') },
  {
    name: 'an authorization failure',
    run: () => source(client()).getAll('prod/denied', { fallback: 'credential' }),
  },
  {
    name: 'a service failure',
    run: () => source(client()).getAll('prod/broken', { fallback: 'credential' }),
  },
  { name: 'a read by ARN', run: () => source(client()).get(arnFor('prod/db')) },
  {
    name: 'a read that also describes the rotation schedule',
    run: () => source(client(), { readRotation: true }).get('prod/stripe'),
  },
];

describe('the aws sweep', () => {
  it('leaks the canary in no result and no error', async () => {
    const results = await sweep(CANARY, CASES);

    expect(results).toHaveLength(CASES.length);
  });

  it('leaks the 20-character canary either', async () => {
    await sweep(SHORT_CANARY, CASES);
  });

  it('forces failures rather than sweeping only happy paths', async () => {
    const results = await sweep(CANARY, CASES);

    expect(results.filter((result) => result.threw).length).toBeGreaterThan(5);
  });
});

describe('the fixtures', () => {
  it('carry a canary, so a fixture that leaks is caught like a real one', () => {
    expect(JSON.stringify(getResponse('x', { SecretString: CANARY }))).toContain(CANARY);
  });
});

describe('load events', () => {
  it('carry no secret material for any read this package makes', async () => {
    const events: SecretLoadEvent[] = [];
    const aws = source(client(), { onLoad: (event) => events.push(event), readRotation: true });

    await aws.getAll('prod/db', { fallback: 'credential' });
    await aws.getAll('prod/nested', { fallback: 'credential' });
    await aws.get('prod/binary');

    assertNoCanary(CANARY, events, 'the aws load events');
  });
});

describe('labels', () => {
  it('disclose nothing under the rule, for every field of every fixture', async () => {
    const aws = source(client());

    for (const path of ['prod/db', 'prod/nested', 'prod/dotted', arnFor('prod/db')]) {
      const record = await aws.getAll(path, { fallback: 'credential' });

      for (const value of record.fields.values()) {
        expect(describeLabelDisclosure(value.label ?? '')).toEqual([]);
        expect(value.label).not.toContain(ACCOUNT);
      }
    }
  });
});

describe('the account identifier', () => {
  it('reaches metadata, which the load hook sees and redacted output does not', async () => {
    const record = await source(client()).get(arnFor('prod/db'));

    expect(record.ref.metadata['account']).toBe(ACCOUNT);
    expect(String(record.value)).not.toContain(ACCOUNT);
  });

  it('does not reach an error message when the read fails on a payload', async () => {
    const failure = await source(client())
      .getJson(arnFor('prod/db'), { fields: { missing: 'credential' } })
      .catch((error: unknown) => error);

    expect((failure as Error).message).not.toContain(ACCOUNT);
  });
});

describe('the registration test', () => {
  it('fails if a source implementation has no sweep entry', () => {
    expect(() => assertEverySourceSwept(awsPackage, [])).toThrow(/no sweep entry: AwsSecretSource/);
  });

  it('passes now that AwsSecretSource is swept', () => {
    expect(() => assertEverySourceSwept(awsPackage, ['AwsSecretSource'])).not.toThrow();
  });
});
