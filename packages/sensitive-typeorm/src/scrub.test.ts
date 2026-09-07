import {
  mergeScrubPolicy,
  resolveScrubPolicy,
  scrubPayload,
} from '@platform-sec/sensitive-string-scrub';
import { QueryFailedError } from 'typeorm';
import { describe, expect, it } from 'vitest';
import { typeormScrubFragment } from './scrub.js';
import { CANARY } from './__tests__/fixtures.js';

/** What an error tracker would capture: the error, flattened onto an event. */
function event(): Record<string, unknown> {
  const error = new QueryFailedError(
    'INSERT INTO "users"("email") VALUES ($1)',
    [CANARY],
    new Error('duplicate key')
  );
  return {
    message: error.message,
    extra: {
      query: error.query,
      parameters: error.parameters,
      driverError: { parameters: [CANARY], detail: `Key (email)=(${CANARY}) already exists.` },
    },
  };
}

describe('typeormScrubFragment', () => {
  it('removes the canary from a captured query error', () => {
    const policy = resolveScrubPolicy(typeormScrubFragment);
    const { payload } = scrubPayload(event(), policy, 'event');
    expect(JSON.stringify(payload)).not.toContain(CANARY);
  });

  it('is needed, because the default policy leaves the canary in place', () => {
    // The 3.2 measurement kept as a test. The value is a correct plaintext
    // string in a property nobody told the scrubber about, which is why the
    // defaults miss it. The day they grow a rule that catches it, this fails
    // and the fragment retires.
    const policy = resolveScrubPolicy({});
    const { payload } = scrubPayload(event(), policy, 'event');
    expect(JSON.stringify(payload)).toContain(CANARY);
  });

  it('merges into a caller policy without losing the caller entries', () => {
    const merged = mergeScrubPolicy(typeormScrubFragment, {
      denyKeys: ['x-internal-signature'],
    });
    const policy = resolveScrubPolicy(merged);
    expect(policy.denyKeys.has('parameters')).toBe(true);
    expect(policy.denyKeys.has('x-internal-signature')).toBe(true);
  });

  it('lets a caller keep an unrelated query key through allowKeys', () => {
    // `query` is the broad entry of the three, and this is the escape hatch
    // sensitive-scrub already has for it.
    const merged = mergeScrubPolicy(typeormScrubFragment, {
      allowKeys: [{ key: 'query', reason: 'GraphQL document, no database statement here' }],
    });
    const policy = resolveScrubPolicy(merged);
    expect(policy.denyKeys.has('query')).toBe(false);
    expect(policy.denyKeys.has('parameters')).toBe(true);
  });
});
