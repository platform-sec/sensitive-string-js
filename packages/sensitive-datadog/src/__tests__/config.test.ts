import safeRegex from 'safe-regex2';
import { resolveScrubPolicy } from '@platform-sec/sensitive-string-scrub';
import { describe, expect, it } from 'vitest';

import {
  DD_QUERY_OBFUSCATION_DEFAULT,
  composeQueryObfuscation,
  planHeaderCapture,
} from '../config.js';
import { AGENT_VERSION, agentRequire } from './fixtures.js';

/**
 * The two lists a hook cannot reach.
 *
 * Measured against `dd-trace` 6.14.0 on Node 22.15.0.
 */

const policy = resolveScrubPolicy();

/** The agent's own default, read off the data file the reproduction was taken from. */
function shippedDefault(): string {
  const require_ = agentRequire();
  const path = require_.resolve(
    'dd-trace/packages/dd-trace/src/config/supported-configurations.json'
  );
  const json = require_(path) as {
    supportedConfigurations: Record<string, { default?: string }[] | { default?: string }>;
  };

  const entry = json.supportedConfigurations['DD_TRACE_OBFUSCATION_QUERY_STRING_REGEXP'];
  const value = Array.isArray(entry) ? entry[0]?.default : entry?.default;

  if (typeof value !== 'string') {
    throw new Error(
      'DD_TRACE_OBFUSCATION_QUERY_STRING_REGEXP has no default in the shipped configuration data. ' +
        'The agent has moved it, and DD_QUERY_OBFUSCATION_DEFAULT must be re-taken by hand.'
    );
  }

  return value;
}

describe(`the reproduced obfuscator against dd-trace ${AGENT_VERSION}`, () => {
  it('is exactly what the agent ships', () => {
    // A vendor widening its own default fails here rather than being silently
    // narrowed by this package.
    expect(DD_QUERY_OBFUSCATION_DEFAULT).toBe(shippedDefault());
  });

  it('compiles, with the flags the agent compiles it with', () => {
    expect(() => new RegExp(DD_QUERY_OBFUSCATION_DEFAULT, 'gi')).not.toThrow();
  });

  it('matches the key names section 2.1 recorded', () => {
    const pattern = new RegExp(DD_QUERY_OBFUSCATION_DEFAULT, 'gi');

    for (const query of ['password=x', 'api_key=x', 'token=x', 'authorization=x', 'signature=x']) {
      pattern.lastIndex = 0;
      expect(pattern.test(query)).toBe(true);
    }
  });

  it('matches the value shapes section 2.1 recorded', () => {
    const pattern = new RegExp(DD_QUERY_OBFUSCATION_DEFAULT, 'gi');

    for (const value of ['bearer abc123', 'ghp_' + 'a'.repeat(36)]) {
      pattern.lastIndex = 0;
      expect(pattern.test(value)).toBe(true);
    }
  });
});

describe('composeQueryObfuscation', () => {
  it('is a superset of the agent default', () => {
    const composed = composeQueryObfuscation(undefined, policy);

    expect(typeof composed).toBe('string');
    expect(composed as string).toContain(DD_QUERY_OBFUSCATION_DEFAULT);
  });

  it.each(['cookie', 'set-cookie', 'x-api-key', 'x-goog-api-key', 'session_id'])(
    'adds %s, which the agent default does not cover',
    (key) => {
      const base = new RegExp(DD_QUERY_OBFUSCATION_DEFAULT, 'gi');
      base.lastIndex = 0;

      // The half that makes the addition real: without it this asserts that a
      // pattern matches something it already matched.
      expect(base.test(`${key}=x`)).toBe(false);

      const pattern = new RegExp(composeQueryObfuscation(undefined, policy) as string, 'gi');
      pattern.lastIndex = 0;

      expect(pattern.test(`${key}=x`)).toBe(true);
    }
  );

  it('adds nothing for a name the default already covers', () => {
    // `refresh_token` is one: the default's `token` branch matches the
    // `token=x` substring inside it. Adding a branch per default name would
    // double the pattern for no coverage.
    const composed = composeQueryObfuscation(undefined, policy) as string;
    const added = composed.slice(DD_QUERY_OBFUSCATION_DEFAULT.length + 1);

    expect(added).not.toContain('refresh_token');
  });

  it('adds a caller name', () => {
    const composed = composeQueryObfuscation(
      undefined,
      resolveScrubPolicy({ denyKeys: ['x-internal-signature'] })
    ) as string;
    const pattern = new RegExp(composed, 'gi');

    pattern.lastIndex = 0;
    expect(pattern.test('x-internal-signature=abc')).toBe(true);
  });

  it('composes onto a caller pattern rather than replacing it', () => {
    const composed = composeQueryObfuscation('mycustomkey=[^&]+', policy) as string;

    expect(composed).toContain('mycustomkey=[^&]+');
    expect(composed).not.toContain(DD_QUERY_OBFUSCATION_DEFAULT);
  });

  it('leaves a whole-query redaction alone, since nothing is stronger', () => {
    expect(composeQueryObfuscation(true, policy)).toBe(true);
  });

  it('leaves an explicit opt-out alone, because that decision is the callers', () => {
    expect(composeQueryObfuscation(false, policy)).toBe(false);
    expect(composeQueryObfuscation('', policy)).toBe('');
  });

  it('keeps the base at the front, so the vendor branches are tried first', () => {
    const composed = composeQueryObfuscation(undefined, policy) as string;

    expect(composed.startsWith(DD_QUERY_OBFUSCATION_DEFAULT)).toBe(true);
  });

  it('escapes a denied name so it reaches the engine as a literal', () => {
    const composed = composeQueryObfuscation(
      'nothing',
      resolveScrubPolicy({ denyKeys: ['a.(b)+'] })
    ) as string;
    const pattern = new RegExp(composed, 'gi');

    pattern.lastIndex = 0;
    expect(pattern.test('a.(b)+=secret')).toBe(true);

    pattern.lastIndex = 0;
    expect(pattern.test('axbbb=secret')).toBe(false);
  });

  it('adds only fragments safe-regex2 accepts', () => {
    // This runs on every request URL and a denied name is configuration a user
    // edits, which is the pair of conditions that makes a catastrophic pattern
    // a denial of service rather than a bug.
    //
    // Asserted over the added branches alone, because the vendor's own default
    // is not something `safe-regex2` accepts: it carries `{100,}` and nested
    // quantifiers in its `ssh-rsa` and PEM branches. Composing onto it does not
    // make that worse and replacing it is not this package's call, so what is
    // pinned here is what this package actually writes.
    const composed = composeQueryObfuscation(undefined, policy) as string;
    const added = composed.slice(DD_QUERY_OBFUSCATION_DEFAULT.length + 1);

    expect(added.length).toBeGreaterThan(0);
    expect(safeRegex(new RegExp(added, 'gi'))).toBe(true);
  });

  it('records that the vendor default is what it is', () => {
    // Not an assertion about this package, and worth pinning anyway: if a
    // future `dd-trace` tightens its own pattern, the test above can be
    // widened to cover the whole composition.
    expect(safeRegex(new RegExp(DD_QUERY_OBFUSCATION_DEFAULT, 'gi'))).toBe(false);
  });
});

describe('planHeaderCapture', () => {
  it('keeps a denied header in the capture list', () => {
    // The tag exists and its presence stays diagnostic; the hook replaces the
    // value.
    const { capture, censored } = planHeaderCapture(['authorization', 'x-trace'], policy);

    expect(capture).toContain('authorization');
    expect(censored).toEqual(['authorization']);
  });

  it('lowercases and deduplicates, since the agent tags by the name it was given', () => {
    const { capture } = planHeaderCapture(['Authorization', 'authorization'], policy);

    expect(capture).toEqual(['authorization']);
  });

  it('is sorted, so the generated list is reviewable in a diff', () => {
    const { capture } = planHeaderCapture(['x-trace', 'authorization', 'cookie'], policy);

    expect(capture).toEqual(['authorization', 'cookie', 'x-trace']);
  });

  it('censors nothing when nothing captured is denied', () => {
    expect(planHeaderCapture(['x-trace'], policy).censored).toEqual([]);
  });

  it('respects allowKeys', () => {
    const allowed = resolveScrubPolicy({
      allowKeys: [{ key: 'authorization', reason: 'this service forwards a signed assertion' }],
    });

    expect(planHeaderCapture(['authorization'], allowed).censored).toEqual([]);
  });
});
