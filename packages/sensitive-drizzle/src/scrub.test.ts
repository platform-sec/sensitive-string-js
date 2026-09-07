import {
  mergeScrubPolicy,
  resolveScrubPolicy,
  scrubPayload,
} from '@platform-sec/sensitive-string-scrub';
import { DrizzleQueryError } from 'drizzle-orm/errors';
import { describe, expect, it } from 'vitest';
import { drizzleScrubFragment } from './scrub.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

/** What an error tracker would capture: the error, flattened onto an event. */
function event(): Record<string, unknown> {
  const error = new DrizzleQueryError(
    'insert into "users" ("email") values ($1)',
    [CANARY],
    Object.assign(new Error('duplicate key'), {
      detail: `Key (email)=(${CANARY}) already exists.`,
    })
  );
  return {
    extra: {
      query: error.query,
      params: error.params,
      cause: { detail: (error.cause as unknown as { detail: string }).detail },
    },
  };
}

describe('drizzleScrubFragment', () => {
  it('removes the canary from a captured query error', () => {
    const policy = resolveScrubPolicy(drizzleScrubFragment);
    const { payload } = scrubPayload(event(), policy, 'event');
    expect(JSON.stringify(payload)).not.toContain(CANARY);
  });

  it('is needed, because the default policy leaves the canary in place', () => {
    // The value is a correct plaintext string in a property nobody told the
    // scrubber about, which is why the defaults miss it. The day they grow a
    // rule that catches it, this fails and the fragment retires.
    const policy = resolveScrubPolicy({});
    const { payload } = scrubPayload(event(), policy, 'event');
    expect(JSON.stringify(payload)).toContain(CANARY);
  });

  it('does not reach the message, which is why sanitizeQueryError still has to run', () => {
    // Drizzle interpolates the parameters into the message it builds, and V8
    // bakes that message into the stack. A key-based policy that denied both
    // would take away the two fields an error report is read for.
    const error = new DrizzleQueryError('select 1 where t = $1', [CANARY], undefined);
    const policy = resolveScrubPolicy(drizzleScrubFragment);
    const { payload } = scrubPayload({ message: error.message }, policy, 'event');
    expect(JSON.stringify(payload)).toContain(CANARY);
  });

  it('merges into a caller policy without losing the caller entries', () => {
    const merged = mergeScrubPolicy(drizzleScrubFragment, {
      denyKeys: ['x-internal-signature'],
    });
    const policy = resolveScrubPolicy(merged);
    expect(policy.denyKeys.has('params')).toBe(true);
    expect(policy.denyKeys.has('x-internal-signature')).toBe(true);
  });

  it('lets a caller keep an unrelated query key through allowKeys', () => {
    const merged = mergeScrubPolicy(drizzleScrubFragment, {
      allowKeys: [{ key: 'query', reason: 'GraphQL document, no database statement here' }],
    });
    const policy = resolveScrubPolicy(merged);
    expect(policy.denyKeys.has('query')).toBe(false);
    expect(policy.denyKeys.has('params')).toBe(true);
  });
});
