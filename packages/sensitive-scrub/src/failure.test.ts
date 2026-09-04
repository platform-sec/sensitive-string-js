import { describe, expect, it, vi } from 'vitest';
import { composeAfter, guardedScrub } from './failure.js';
import { resolveScrubPolicy } from './policy.js';
import type { ScrubReport } from './types.js';

const CANARY = 'LEAKED_SECRET_fail_1d4c';

interface Event {
  type?: string;
  message?: string;
  extra?: Record<string, unknown>;
  tags?: Record<string, string>;
}

const stub = (event: Event): Event => ({
  type: event.type ?? 'Error',
  tags: { 'sensitive.scrub_failed': 'true' },
});

/** A payload the walk cannot finish: the copy is frozen, so writing to it throws. */
function unwritable(): Event {
  const event = { extra: { token: CANARY } };

  // `redactCopy` builds a fresh object for `extra`, then the denylist writes
  // to it. Making Object.entries throw is the reliable way to fail the walk.
  Object.defineProperty(event.extra, 'token', {
    enumerable: true,
    get() {
      throw new Error('property read exploded');
    },
  });

  return event;
}

describe('guardedScrub', () => {
  it('returns the scrubbed payload on the happy path', () => {
    const policy = resolveScrubPolicy();
    const scrub = guardedScrub<Event>({ kind: 'event', policy, stub });

    expect(scrub({ extra: { authorization: CANARY } }).payload).toEqual({
      extra: { authorization: '[SCRUBBED]' },
    });
  });

  it('reports once per payload on the happy path', () => {
    const onScrub = vi.fn();
    const policy = resolveScrubPolicy({ onScrub });
    const scrub = guardedScrub<Event>({ kind: 'breadcrumb', policy, stub });

    scrub({ extra: { token: CANARY } });

    expect(onScrub).toHaveBeenCalledTimes(1);
    expect((onScrub.mock.calls[0]?.[0] as ScrubReport).kind).toBe('breadcrumb');
    expect((onScrub.mock.calls[0]?.[0] as ScrubReport).failed).toBe(false);
  });

  // TEST-SCRUB-FAIL-NOTHROW
  it('does not throw when the walk throws', () => {
    const policy = resolveScrubPolicy();
    const scrub = guardedScrub<Event>({ kind: 'event', policy, stub });

    expect(() => scrub(unwritable())).not.toThrow();
  });

  it('returns the stub when the walk throws', () => {
    const policy = resolveScrubPolicy();
    const scrub = guardedScrub<Event>({ kind: 'event', policy, stub });

    const result = scrub(unwritable()).payload;

    expect(result).toEqual({ type: 'Error', tags: { 'sensitive.scrub_failed': 'true' } });
    expect(JSON.stringify(result)).not.toContain(CANARY);
  });

  it('is not the same as returning null', () => {
    // Returning null tells the vendor the payload was deliberately discarded
    // and it is counted as a client-side drop. The signal that an error of
    // this shape happened is what the stub keeps.
    const policy = resolveScrubPolicy();
    const scrub = guardedScrub<Event>({ kind: 'event', policy, stub });

    expect(scrub(unwritable()).payload).not.toBeNull();
  });

  // TEST-SCRUB-FAIL-REPORTED
  it('reports failed: true, so a scrubber broken on one shape is visible', () => {
    const onScrub = vi.fn();
    const policy = resolveScrubPolicy({ onScrub });
    const scrub = guardedScrub<Event>({ kind: 'event', policy, stub });

    scrub(unwritable());

    expect(onScrub).toHaveBeenCalledTimes(1);
    expect((onScrub.mock.calls[0]?.[0] as ScrubReport).failed).toBe(true);
  });

  it('drops the payload when the stub chooses to, which is how a kind opts out', () => {
    // A payload kind whose loss carries no information says so by returning
    // null from its stub builder.
    const policy = resolveScrubPolicy();
    const scrub = guardedScrub<Event>({ kind: 'span', policy, stub: () => null });

    expect(scrub(unwritable()).payload).toBeNull();
    expect(scrub(unwritable()).report.failed).toBe(true);
  });

  it('drops the payload only when the stub throws as well', () => {
    const policy = resolveScrubPolicy();
    const scrub = guardedScrub<Event>({
      kind: 'event',
      policy,
      stub: () => {
        throw new Error('stub exploded');
      },
    });

    expect(scrub(unwritable()).payload).toBeNull();
  });

  it('swallows what onScrub throws and still returns the scrubbed payload', () => {
    // A reporting failure is the one failure with nowhere to go: reporting it
    // would call the reporter.
    const policy = resolveScrubPolicy({
      onScrub: () => {
        throw new Error('metrics backend down');
      },
    });
    const scrub = guardedScrub<Event>({ kind: 'event', policy, stub });

    expect(scrub({ extra: { token: CANARY } }).payload).toEqual({ extra: { token: '[SCRUBBED]' } });
  });
});

describe('composeAfter', () => {
  it('runs the user hook after the scrubber, on the scrubbed payload', () => {
    const seen: unknown[] = [];
    const policy = resolveScrubPolicy();
    const composed = composeAfter<Event, undefined>(
      (event) => guardedScrub<Event>({ kind: 'event', policy, stub })(event).payload,
      (event) => {
        seen.push(structuredClone(event));
        return event;
      }
    );

    composed({ extra: { authorization: CANARY } }, undefined);

    expect(seen[0]).toEqual({ extra: { authorization: '[SCRUBBED]' } });
  });

  it('lets a user hook returning null still drop the payload', () => {
    const policy = resolveScrubPolicy();
    const composed = composeAfter<Event, undefined>(
      (event) => guardedScrub<Event>({ kind: 'event', policy, stub })(event).payload,
      () => null
    );

    expect(composed({ extra: {} }, undefined)).toBeNull();
  });

  it('treats a user hook returning undefined as a drop, matching the vendor contract', () => {
    const policy = resolveScrubPolicy();
    const composed = composeAfter<Event, undefined>(
      (event) => guardedScrub<Event>({ kind: 'event', policy, stub })(event).payload,
      () => undefined
    );

    expect(composed({ extra: {} }, undefined)).toBeNull();
  });

  it('sends the scrubbed payload when the user hook throws', () => {
    const policy = resolveScrubPolicy();
    const composed = composeAfter<Event, undefined>(
      (event) => guardedScrub<Event>({ kind: 'event', policy, stub })(event).payload,
      () => {
        throw new Error('user hook exploded');
      }
    );

    expect(composed({ extra: { token: CANARY } }, undefined)).toEqual({
      extra: { token: '[SCRUBBED]' },
    });
  });

  it('skips the user hook when the scrubber dropped the payload', () => {
    const user = vi.fn();
    const composed = composeAfter<Event, undefined>(() => null, user);

    expect(composed({ extra: {} }, undefined)).toBeNull();
    expect(user).not.toHaveBeenCalled();
  });

  // TEST-SCRUB-COMPOSE-ASYNC
  it('sends the scrubbed payload when an async user hook rejects', async () => {
    // `beforeSend` may return a promise, so a hook can fail by rejecting as
    // well as by throwing. A rejection reaches the SDK as a dropped payload,
    // which is the outcome the never-throw contract exists to prevent, and a
    // synchronous catch does not see it.
    const policy = resolveScrubPolicy();
    const composed = composeAfter<Event, undefined>(
      (event) => guardedScrub<Event>({ kind: 'event', policy, stub })(event).payload,
      () => Promise.reject(new Error('async user hook exploded'))
    );

    await expect(composed({ extra: { token: CANARY } }, undefined)).resolves.toEqual({
      extra: { token: '[SCRUBBED]' },
    });
  });

  it('honours an async user hook that resolves to a payload', async () => {
    const policy = resolveScrubPolicy();
    const composed = composeAfter<Event, undefined>(
      (event) => guardedScrub<Event>({ kind: 'event', policy, stub })(event).payload,
      (event) => Promise.resolve({ ...event, message: 'added' })
    );

    await expect(composed({ extra: {} }, undefined)).resolves.toMatchObject({ message: 'added' });
  });

  it('honours an async user hook that resolves to null', async () => {
    const policy = resolveScrubPolicy();
    const composed = composeAfter<Event, undefined>(
      (event) => guardedScrub<Event>({ kind: 'event', policy, stub })(event).payload,
      () => Promise.resolve(null)
    );

    await expect(composed({ extra: {} }, undefined)).resolves.toBeNull();
  });

  it('passes the vendor hint through to the user hook', () => {
    const policy = resolveScrubPolicy();
    const seen: unknown[] = [];
    const composed = composeAfter<Event, { originalException: unknown }>(
      (event) => guardedScrub<Event>({ kind: 'event', policy, stub })(event).payload,
      (event, hint) => {
        seen.push(hint);
        return event;
      }
    );

    const hint = { originalException: new Error('x') };
    composed({ extra: {} }, hint);

    expect(seen[0]).toBe(hint);
  });
});
