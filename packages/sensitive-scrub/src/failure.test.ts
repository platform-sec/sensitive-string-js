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

/**
 * A value the scrub walk cannot finish, because writing the copy fails.
 *
 * A write, deliberately, and not a read. `core`'s walks now degrade rather than
 * throw for every hook an object controls on the way *in*: a `get` trap, a
 * throwing enumerable getter, `ownKeys`, `getOwnPropertyDescriptor`, `toJSON`,
 * `toString`, and the prototype read behind every `instanceof`. A throwing
 * enumerable getter is what this suite used to reach for and is now handled
 * end to end, which is the right outcome and leaves the never-throw wrapper
 * untested.
 *
 * `redactCopy` keeps each object's prototype so a serializer downstream still
 * sees the class, and then assigns the copied properties onto the new object.
 * A prototype whose setter refuses is therefore a failure on the way *out*,
 * which no amount of read-guarding can absorb, and it is an ordinary shape: a
 * class with a validating setter behaves this way for a value it rejects.
 */
function unwritable(value: unknown): Record<string, unknown> {
  const prototype = {};

  Object.defineProperty(prototype, 'token', {
    set(): never {
      throw new Error('write refused');
    },
    get(): undefined {
      return undefined;
    },
    configurable: true,
  });

  const source = Object.create(prototype) as Record<string, unknown>;

  // defineProperty rather than assignment, so building the fixture does not
  // trip the setter that the copy is supposed to trip.
  Object.defineProperty(source, 'token', {
    value,
    enumerable: true,
    writable: true,
    configurable: true,
  });

  return source;
}

/** A payload the walk cannot finish. */
function unwritablePayload(): Event {
  return { extra: unwritable(CANARY) };
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

    expect(() => scrub(unwritablePayload())).not.toThrow();
  });

  /**
   * The shape this suite used to use as its failure case, kept as a success
   * case. An ORM produces exactly this for a relation that was not loaded, and
   * it reaching the stub meant every event carrying one lost its whole payload.
   */
  it('scrubs a payload with a getter that throws, rather than falling back', () => {
    const policy = resolveScrubPolicy();
    const scrub = guardedScrub<Event>({ kind: 'event', policy, stub });

    const extra: Record<string, unknown> = { authorization: CANARY };
    Object.defineProperty(extra, 'lazy', {
      enumerable: true,
      get(): never {
        throw new Error('relation not loaded');
      },
    });

    const result = scrub({ extra });

    expect(result.report.failed).toBe(false);
    expect(result.payload).not.toBeNull();
    expect(JSON.stringify(result.payload)).not.toContain(CANARY);
    expect((result.payload?.extra as Record<string, unknown>)['authorization']).toBe('[SCRUBBED]');
  });

  it('returns the stub when the walk throws', () => {
    const policy = resolveScrubPolicy();
    const scrub = guardedScrub<Event>({ kind: 'event', policy, stub });

    const result = scrub(unwritablePayload()).payload;

    expect(result).toEqual({ type: 'Error', tags: { 'sensitive.scrub_failed': 'true' } });
    expect(JSON.stringify(result)).not.toContain(CANARY);
  });

  it('is not the same as returning null', () => {
    // Returning null tells the vendor the payload was deliberately discarded
    // and it is counted as a client-side drop. The signal that an error of
    // this shape happened is what the stub keeps.
    const policy = resolveScrubPolicy();
    const scrub = guardedScrub<Event>({ kind: 'event', policy, stub });

    expect(scrub(unwritablePayload()).payload).not.toBeNull();
  });

  // TEST-SCRUB-FAIL-REPORTED
  it('reports failed: true, so a scrubber broken on one shape is visible', () => {
    const onScrub = vi.fn();
    const policy = resolveScrubPolicy({ onScrub });
    const scrub = guardedScrub<Event>({ kind: 'event', policy, stub });

    scrub(unwritablePayload());

    expect(onScrub).toHaveBeenCalledTimes(1);
    expect((onScrub.mock.calls[0]?.[0] as ScrubReport).failed).toBe(true);
  });

  it('drops the payload when the stub chooses to, which is how a kind opts out', () => {
    // A payload kind whose loss carries no information says so by returning
    // null from its stub builder.
    const policy = resolveScrubPolicy();
    const scrub = guardedScrub<Event>({ kind: 'span', policy, stub: () => null });

    expect(scrub(unwritablePayload()).payload).toBeNull();
    expect(scrub(unwritablePayload()).report.failed).toBe(true);
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

    expect(scrub(unwritablePayload()).payload).toBeNull();
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

describe('guardedScrub under onMatch: observe', () => {
  it('hands back the payload it was given when the walk throws, and still reports failed', () => {
    const reports: ScrubReport[] = [];
    const policy = resolveScrubPolicy({ onMatch: 'observe', onScrub: (r) => reports.push(r) });
    const scrub = guardedScrub<Event>({ kind: 'event', policy, stub });
    const input = unwritablePayload();

    const { payload, report } = scrub(input);

    // A mode that promises to change nothing cannot answer a broken walk with
    // a stub. The vendor gets what it would have got before the install, and
    // the report is where the operator learns the walk broke on this shape.
    expect(payload).toBe(input);
    expect(report.failed).toBe(true);
    expect(reports).toEqual([report]);
  });

  it('otherwise behaves as censor mode does on the happy path', () => {
    const policy = resolveScrubPolicy({ onMatch: 'observe' });
    const scrub = guardedScrub<Event>({ kind: 'event', policy, stub });

    const { payload, report } = scrub({ extra: { authorization: CANARY } });

    expect(payload).toEqual({ extra: { authorization: CANARY } });
    expect(report.failed).toBe(false);
    expect(report.deniedKeys).toEqual(['authorization']);
  });
});
