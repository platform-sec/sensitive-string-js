/**
 * The worker handoff, in one thread.
 *
 * Everything here is what `toWorkerPayload()` and `fromWorkerPayload()` decide
 * on their own, with `structuredClone` standing in for the boundary where a
 * test needs a copy. The cross-isolate findings, which is every one that
 * matters about `workerData`, are in `worker-boundary.test.ts` against a real
 * `Worker`; a mocked boundary would reproduce none of them.
 */
import * as util from 'node:util';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  ConsumedWorkerPayloadError,
  ExpiredSensitiveValueError,
  MalformedWorkerPayloadError,
  MissingWorkerValueError,
  RenewalNotAllowedError,
  RevealLimitExceededError,
  SensitiveString,
  UnauditedWorkerError,
  UnportableDataError,
  UnregisteredClassError,
  UnshareableConstraintError,
  containsSensitive,
  fromWorkerPayload,
  getCurrentRevealContext,
  redactCopy,
  redactInStructure,
  registerPolicy,
  resetPolicies,
  safeStringify,
  sensitiveFormat,
  toWorkerPayload,
  withRevealContext,
  withWorkerPayload,
} from '../index.js';
import type {
  RevealContext,
  RevealDetails,
  SensitivityClass,
  WorkerHandoffAuditDetails,
  WorkerPayload,
} from '../index.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';
const OTHER_CANARY = 'LEAKED_OTHER_def456uvw';

/** A payload as a received side sees it: a clone, not the sender's object. */
function crossed<T extends Record<string, SensitiveString<SensitivityClass>>>(
  payload: WorkerPayload<T>
): WorkerPayload<T> {
  return structuredClone(payload);
}

function token(value = CANARY): SensitiveString<'credential'> {
  return new SensitiveString(value, 'credential', 'api_key');
}

/** A hook that records what it saw and nothing it should not. */
function recordingHook(): {
  calls: RevealDetails[];
  hook: NonNullable<RevealContext['auditReveal']>;
} {
  const calls: RevealDetails[] = [];
  return {
    calls,
    hook: (_value, details) => {
      calls.push(details);
    },
  };
}

describe('toWorkerPayload', () => {
  afterEach(() => {
    resetPolicies();
  });

  describe('shape', () => {
    it('carries each value in the wire format under its key, with the marker', () => {
      const payload = toWorkerPayload({
        token: token(),
        dsn: new SensitiveString(OTHER_CANARY, 'sensitive'),
      });

      expect(payload.__sensitiveWorkerPayload).toBe(1);
      expect(payload.values.token).toEqual({
        __sensitive: true,
        klass: 'credential',
        value: CANARY,
        label: 'api_key',
      });
      expect(payload.values.dsn).toEqual({
        __sensitive: true,
        klass: 'sensitive',
        value: OTHER_CANARY,
      });
      expect(payload.audited).toBe(false);
      expect(payload).not.toHaveProperty('context');
      expect(payload).not.toHaveProperty('data');
    });

    it('carries the deadline, so the receiver enforces it', () => {
      const expiresAt = new Date(Date.now() + 60_000);
      const payload = toWorkerPayload({
        otp: new SensitiveString(CANARY, 'credential', 'otp', { expiresAt }),
      });

      expect(payload.values.otp.expiresAt).toBe(expiresAt.toISOString());
    });

    it('carries name, reason and tags from the given context, and never the hook', () => {
      const payload = toWorkerPayload(
        { token: token() },
        {
          context: {
            name: 'req-42',
            reason: 'charge',
            tags: { userId: 'u1' },
            auditReveal: () => undefined,
          },
        }
      );

      expect(payload.context).toEqual({ name: 'req-42', reason: 'charge', tags: { userId: 'u1' } });
      expect(payload.audited).toBe(true);
      expect(() => structuredClone(payload)).not.toThrow();
    });

    it('defaults to the ambient context', () => {
      const payload = withRevealContext({ name: 'ambient', reason: 'probe' }, () =>
        toWorkerPayload({ token: token() })
      );

      expect(payload.context).toEqual({ name: 'ambient', reason: 'probe' });
      expect(payload.audited).toBe(false);
    });

    it('prefers an explicit context over the ambient one', () => {
      const payload = withRevealContext({ name: 'ambient', auditReveal: () => undefined }, () =>
        toWorkerPayload({ token: token() }, { context: { name: 'explicit' } })
      );

      expect(payload.context).toEqual({ name: 'explicit' });
      expect(payload.audited).toBe(false);
    });

    it('passes data through untouched', () => {
      const data = { batchSize: 100, when: new Date(0), nested: { list: [1, 2, 3] } };

      expect(toWorkerPayload({ token: token() }, { data }).data).toBe(data);
    });

    it('accepts a payload with no values at all', () => {
      const payload = toWorkerPayload({});

      expect(payload.values).toEqual({});
      expect(fromWorkerPayload(crossed(payload)).values).toEqual({});
    });

    it('is a plain object every marker-aware walk can see through', () => {
      const payload = toWorkerPayload({ token: token() });

      expect(containsSensitive(payload)).toBe(true);
    });
  });

  describe('input validation', () => {
    it.each([
      [
        'a non-instance value',
        { token: CANARY },
        /values\.token is a string, not a SensitiveString/,
      ],
      ['a null value', { token: null }, /values\.token is null, not a SensitiveString/],
      [
        'a wire object',
        { token: token().serialize() },
        /values\.token is an object, not a SensitiveString/,
      ],
    ])('refuses %s by key, without echoing it', (_case, values, message) => {
      expect(() => toWorkerPayload(values as never)).toThrow(TypeError);
      expect(() => toWorkerPayload(values as never)).toThrow(message);
      try {
        toWorkerPayload(values as never);
      } catch (error) {
        expect((error as Error).message).not.toContain(CANARY);
      }
    });

    it.each([null, undefined, 'token', 42, [token()]])('refuses %s as values', (values) => {
      expect(() => toWorkerPayload(values as never)).toThrow(TypeError);
    });

    it('refuses an unknown transport and a non-string worker', () => {
      expect(() => toWorkerPayload({ token: token() }, { transport: 'ipc' as never })).toThrow(
        /transport must be 'clone' or 'json'/
      );
      expect(() => toWorkerPayload({ token: token() }, { worker: 42 as never })).toThrow(
        /worker must be a string or a URL/
      );
    });
  });

  describe('what a mid-payload refusal leaves behind', () => {
    it('reveals and audits the values before the one the gate refuses', () => {
      // The up-front checks reveal nothing. The gate's own refusals cannot be
      // hoisted, because deciding them means reading, so a refusal at the
      // second key leaves the first revealed and audited. Asserted rather than
      // wished away: an audit log will show a handoff for a payload that was
      // never built, and the key on the record is how a reader tells.
      const { calls, hook } = recordingHook();
      const good = token();
      const dead = new SensitiveString(OTHER_CANARY, 'credential', 'otp', { ttl: 0 });

      expect(() =>
        toWorkerPayload({ good, dead }, { context: { name: 'req', auditReveal: hook } })
      ).toThrow(ExpiredSensitiveValueError);

      expect(good.revealCount).toBe(1);
      expect(calls).toHaveLength(1);
      expect((calls[0] as WorkerHandoffAuditDetails).key).toBe('good');
    });

    it('reveals nothing for a refusal that does not need to read', () => {
      const { calls, hook } = recordingHook();
      const good = token();
      const limited = new SensitiveString(OTHER_CANARY, 'credential', 'boot', { maxReveals: 1 });

      expect(() =>
        toWorkerPayload({ good, limited }, { context: { name: 'req', auditReveal: hook } })
      ).toThrow(UnshareableConstraintError);

      expect(good.revealCount).toBe(0);
      expect(calls).toEqual([]);
    });
  });

  describe('the audit record', () => {
    it('fires the hook once per value with a worker-handoff record that carries no raw value', () => {
      const { calls, hook } = recordingHook();
      const worker = new URL('file:///srv/app/sign.js');

      toWorkerPayload(
        { token: token(), dsn: new SensitiveString(OTHER_CANARY, 'sensitive', 'dsn') },
        { worker, context: { name: 'req-42', auditReveal: hook } }
      );

      expect(calls).toHaveLength(2);
      expect(calls[0]).toEqual({
        operation: 'worker-handoff',
        worker: 'file:///srv/app/sign.js',
        key: 'token',
        auditHookDropped: true,
      });
      expect((calls[1] as WorkerHandoffAuditDetails).key).toBe('dsn');
      expect(JSON.stringify(calls)).not.toContain(CANARY);
      expect(JSON.stringify(calls)).not.toContain(OTHER_CANARY);
    });

    it('records a string destination as given and no destination as undefined', () => {
      const { calls, hook } = recordingHook();
      const context = { name: 'req', auditReveal: hook };

      toWorkerPayload({ token: token() }, { worker: './sign.js', context });
      toWorkerPayload({ token: token() }, { context });

      expect((calls[0] as WorkerHandoffAuditDetails).worker).toBe('./sign.js');
      expect((calls[1] as WorkerHandoffAuditDetails).worker).toBeUndefined();
    });

    it('records nothing when an explicit context without a hook replaces an audited ambient one', () => {
      const { calls, hook } = recordingHook();

      // An explicit context replaces the ambient one rather than merging with
      // it, so naming a context with no hook drops the outer hook for this
      // call. That is the library's standing rule and not a worker one; it is
      // pinned here because the handoff is where it is easiest to write by
      // accident, and the payload records `audited: false` to match.
      const payload = withRevealContext({ name: 'outer', auditReveal: hook }, () =>
        toWorkerPayload({ token: token() }, { context: { name: 'inner' } })
      );

      expect(calls).toEqual([]);
      expect(payload.audited).toBe(false);
    });

    it('carries auditHookDropped on every delivered record, and delivers none without a hook', () => {
      // The field can only ever read `true`, because a record reaches a sink
      // through the very hook it reports the loss of. Asserted in both
      // directions so the constant is a documented property rather than an
      // untested branch somebody later "fixes".
      const { calls, hook } = recordingHook();

      toWorkerPayload({ token: token() }, { context: { name: 'audited', auditReveal: hook } });
      toWorkerPayload({ token: token() }, { context: { name: 'plain' } });
      toWorkerPayload({ token: token() });

      expect(calls).toHaveLength(1);
      expect((calls[0] as WorkerHandoffAuditDetails).auditHookDropped).toBe(true);
    });

    it('charges one reveal per value', () => {
      const value = token();

      toWorkerPayload({ token: value });

      expect(value.revealCount).toBe(1);
    });

    it('is authorized as an ordinary expose, so a policy that denies expose denies the handoff', () => {
      registerPolicy(
        {
          name: 'credential',
          redact: () => '[REDACTED:credential]',
          checkRevealAllowed(_ctx, _value, access) {
            if (access === 'expose') {
              throw new Error('no exposure of credentials in this process');
            }
            return undefined;
          },
        },
        { overwrite: true }
      );

      expect(() => toWorkerPayload({ token: token() })).toThrow(
        'no exposure of credentials in this process'
      );
    });

    it("refuses an expired value from the gate, with the gate's own error", () => {
      const dead = new SensitiveString(CANARY, 'credential', 'otp', { ttl: 0 });

      expect(() => toWorkerPayload({ otp: dead })).toThrow(ExpiredSensitiveValueError);
    });

    it('lets an audit hook that throws stop the handoff before anything is built', () => {
      const context: RevealContext = {
        name: 'strict',
        auditReveal: () => {
          throw new Error('denied by sink');
        },
      };

      expect(() => toWorkerPayload({ token: token() }, { context })).toThrow('denied by sink');
    });
  });

  describe('a reveal limit cannot cross', () => {
    it('refuses a value with maxReveals, naming the key and the option', () => {
      const single = new SensitiveString(CANARY, 'credential', 'bootstrap', { maxReveals: 1 });

      expect(() => toWorkerPayload({ boot: single })).toThrow(UnshareableConstraintError);
      try {
        toWorkerPayload({ boot: single });
      } catch (error) {
        const refusal = error as UnshareableConstraintError;
        expect(refusal.code).toBe('unshareable-constraint');
        expect(refusal.key).toBe('boot');
        expect(refusal.constraints).toEqual(['maxReveals']);
        expect(refusal.message).toContain("'boot'");
        expect(refusal.message).not.toContain(CANARY);
      }

      // Refused before the read: the budget is untouched.
      expect(single.revealsRemaining).toBe(1);
    });

    it('refuses a rate-limited value, naming both halves of the limit', () => {
      const limited = new SensitiveString(CANARY, 'credential', 'key', {
        revealWindow: 60_000,
        maxRevealsPerWindow: 10,
      });

      try {
        toWorkerPayload({ key: limited });
        expect.unreachable();
      } catch (error) {
        expect((error as UnshareableConstraintError).constraints).toEqual([
          'revealWindow',
          'maxRevealsPerWindow',
        ]);
      }
    });

    it('refuses the constraint through substring, concat and map', () => {
      const single = new SensitiveString(CANARY, 'credential', 'bootstrap', { maxReveals: 5 });
      const plain = token(OTHER_CANARY);

      expect(() => toWorkerPayload({ part: single.substring(0, 4) })).toThrow(
        UnshareableConstraintError
      );
      expect(() => toWorkerPayload({ joined: plain.concat(single) })).toThrow(
        UnshareableConstraintError
      );
      expect(() => toWorkerPayload({ mapped: single.map((v) => v) })).toThrow(
        UnshareableConstraintError
      );
    });

    it('refuses before revealing any other value in the same payload', () => {
      const single = new SensitiveString(CANARY, 'credential', 'bootstrap', { maxReveals: 1 });
      const plain = token(OTHER_CANARY);

      expect(() => toWorkerPayload({ plain, single })).toThrow(UnshareableConstraintError);
      expect(plain.revealCount).toBe(0);
    });

    it('an exhausted value still refuses as unshareable, not as exhausted', () => {
      const single = new SensitiveString(CANARY, 'credential', 'bootstrap', { maxReveals: 1 });
      single.reveal();

      expect(() => toWorkerPayload({ single })).toThrow(UnshareableConstraintError);
      expect(() => toWorkerPayload({ single })).not.toThrow(RevealLimitExceededError);
    });
  });

  describe('data guard', () => {
    it.each([
      ['at the top', { token: token() }],
      ['at depth', { a: { b: [{ c: token() }] } }],
      ['inside a Map', new Map([['k', token()]])],
      ['as a Map key', new Map([[token(), 'v']])],
      ['inside a Set', new Set([token()])],
      ['as a wire object', { wire: token().serialize() }],
    ])('refuses a sensitive value in data %s', (_where, data) => {
      expect(() => toWorkerPayload({}, { data })).toThrow(UnportableDataError);
      try {
        toWorkerPayload({}, { data });
      } catch (error) {
        const refusal = error as UnportableDataError;
        expect(refusal.code).toBe('unportable-data');
        expect(refusal.path).toBe('data');
        expect(refusal.message).toContain('credential');
        expect(refusal.message).not.toContain(CANARY);
      }
    });

    it('refuses an object it cannot walk, rather than passing it as clean', () => {
      const hostile = new Proxy(
        {},
        {
          getPrototypeOf() {
            throw new Error('no');
          },
        }
      );

      expect(() => toWorkerPayload({}, { data: { hostile } })).toThrow(UnportableDataError);
    });
  });

  describe('a protected value cannot ride in the context either', () => {
    it.each([
      ['a wire object', { tok: token().serialize() }],
      ['an instance', { tok: token() }],
      ['at depth', { trace: { inner: [token().serialize()] } }],
    ])('refuses %s in context.tags, naming the path', (_case, tags) => {
      const context: RevealContext = { name: 'req', tags };

      try {
        toWorkerPayload({}, { context });
        expect.unreachable();
      } catch (error) {
        const refusal = error as UnportableDataError;
        expect(refusal).toBeInstanceOf(UnportableDataError);
        expect(refusal.path).toBe('context.tags');
        expect(refusal.message).toContain('credential');
        expect(refusal.message).not.toContain(CANARY);
      }
    });

    it('is the check that keeps consumption honest, since consuming clears only values', () => {
      // A wire object in `tags` used to be accepted, and consumption never
      // touches the context, so the payload still held the raw value after
      // `fromWorkerPayload` returned. Across a real boundary that is plaintext
      // in `workerData` for the life of the thread, which is precisely what
      // consumption exists to prevent.
      const context: RevealContext = { name: 'req', tags: { tok: token().serialize() } };

      expect(() => toWorkerPayload({}, { context })).toThrow(UnportableDataError);
    });

    it('leaves ordinary tags alone', () => {
      const payload = toWorkerPayload(
        {},
        { context: { name: 'req', tags: { userId: 'u1', attempt: 2 } } }
      );

      expect(payload.context?.tags).toEqual({ userId: 'u1', attempt: 2 });
    });
  });

  describe('transport validation', () => {
    const fixtureClosure = (): string => 'LEAKED_SECRET_abc123xyz';

    it('names the failing key for a function in data, without the source or the canary', () => {
      expect(() =>
        toWorkerPayload({}, { data: { batch: { size: 1, onDone: fixtureClosure } } })
      ).toThrow(UnportableDataError);

      try {
        toWorkerPayload({}, { data: { batch: { size: 1, onDone: fixtureClosure } } });
      } catch (error) {
        const refusal = error as UnportableDataError;
        expect(refusal.path).toBe('data.batch.onDone');
        expect(refusal.transport).toBe('clone');
        expect(refusal.message).toContain('data.batch.onDone');
        expect(refusal.message).not.toContain(CANARY);
        expect(refusal.message).not.toContain('=>');
        expect(refusal.message).not.toContain('could not be cloned');
      }
    });

    it('names the failing key for a function in the context tags', () => {
      const context: RevealContext = { name: 'req', tags: { trace: fixtureClosure } };

      try {
        toWorkerPayload({ token: token() }, { context });
        expect.unreachable();
      } catch (error) {
        expect((error as UnportableDataError).path).toBe('context.tags.trace');
        expect((error as Error).message).not.toContain(CANARY);
      }
    });

    it('locates a function inside an array, a Map and a Set', () => {
      const cases: [unknown, string][] = [
        [{ list: [1, fixtureClosure] }, 'data.list[1]'],
        [{ m: new Map([['k', fixtureClosure]]) }, 'data.m[entry 0].value'],
        [{ s: new Set([1, fixtureClosure]) }, 'data.s[entry 1]'],
      ];

      for (const [data, path] of cases) {
        try {
          toWorkerPayload({}, { data });
          expect.unreachable();
        } catch (error) {
          expect((error as UnportableDataError).path).toBe(path);
        }
      }
    });

    it('refuses a symbol and a WeakMap under clone', () => {
      for (const [data, detail] of [
        [{ s: Symbol('x') }, 'a symbol'],
        [{ w: new WeakMap() }, 'a WeakMap'],
      ] as const) {
        expect(() => toWorkerPayload({}, { data })).toThrow(detail);
      }
    });

    // This is the measurement of the two serializers disagreeing, turned into
    // a regression test: it is the one that fails if the two guards are ever
    // collapsed into one. The last column is what `'clone'` does with the
    // same input.
    it.each([
      ['a Date', { when: new Date(0) }, 'data.when', 'a string', 'accepts'],
      ['a Map', { m: new Map() }, 'data.m', 'an empty object', 'accepts'],
      ['a Set', { s: new Set([1]) }, 'data.s', 'an empty object', 'accepts'],
      ['an undefined value', { u: undefined }, 'data.u', 'dropped', 'accepts'],
      ['a BigInt', { big: 1n }, 'data.big', 'throw', 'accepts'],
      ['NaN', { n: Number.NaN }, 'data.n', 'null', 'accepts'],
      ['a RegExp', { r: /x/ }, 'data.r', 'an empty object', 'accepts'],
      ['a typed array', { t: new Uint8Array(2) }, 'data.t', 'indexed keys', 'accepts'],
      [
        'a class with toJSON',
        {
          d: new (class {
            toJSON(): number {
              return 1;
            }
          })(),
        },
        'data.d',
        'toJSON',
        'accepts',
      ],
      ['a nested Date', { a: [{ b: new Date(0) }] }, 'data.a[0].b', 'a string', 'accepts'],
      ['an own toJSON function', { d: { toJSON: (): number => 1 } }, 'data.d', 'toJSON', 'refuses'],
    ] as const)('json rejects %s, and clone %s it', (_case, data, path, detail, clone) => {
      try {
        toWorkerPayload({}, { data, transport: 'json' });
        expect.unreachable();
      } catch (error) {
        const refusal = error as UnportableDataError;
        expect(refusal).toBeInstanceOf(UnportableDataError);
        expect(refusal.transport).toBe('json');
        expect(refusal.path).toBe(path);
        expect(refusal.message).toContain(detail);
      }

      if (clone === 'refuses') {
        expect(() => toWorkerPayload({}, { data })).toThrow(UnportableDataError);
      } else {
        expect(() => toWorkerPayload({}, { data })).not.toThrow();
      }
    });

    it('json accepts what JSON round-trips, and a circular reference is refused', () => {
      expect(() =>
        toWorkerPayload(
          {},
          { data: { a: 1, b: 'two', c: [true, null], d: { e: {} } }, transport: 'json' }
        )
      ).not.toThrow();

      const loop: Record<string, unknown> = {};
      loop['self'] = loop;

      expect(() => toWorkerPayload({}, { data: loop, transport: 'json' })).toThrow('circular');
      // A cycle clones fine; only JSON refuses it.
      expect(() => toWorkerPayload({}, { data: loop })).not.toThrow();
    });

    it('json is a superset of clone: a function is refused by both', () => {
      for (const transport of ['clone', 'json'] as const) {
        expect(() => toWorkerPayload({}, { data: { f: fixtureClosure }, transport })).toThrow(
          UnportableDataError
        );
      }
    });

    it('reports the container when an entry refuses to be read, rather than throwing its error', () => {
      // Building an error message asks arbitrary objects questions, and an
      // object is free to throw from any of them. A guard that a hostile
      // object can replace with an exception of its own is not a guard.
      const throwingToJson = {};
      Object.defineProperty(throwingToJson, 'toJSON', {
        get() {
          throw new Error('no toJSON for you');
        },
        enumerable: true,
      });

      const throwingIterator = new Proxy([1, 2], {
        get(target, prop, receiver) {
          if (prop === 'map') {
            throw new Error('no map');
          }
          return Reflect.get(target, prop, receiver) as unknown;
        },
      });

      expect(() => toWorkerPayload({}, { data: { x: throwingToJson }, transport: 'json' })).toThrow(
        UnportableDataError
      );
      expect(() => toWorkerPayload({}, { data: { fn: () => 1, list: throwingIterator } })).toThrow(
        UnportableDataError
      );
    });

    it('walks a shared subtree once per node, not once per path', () => {
      // Two sets: one for the current path, which detects a cycle, and one for
      // nodes already cleared, which is never unwound. With only the first, a
      // diamond is re-walked once per path and 24 levels took 16 seconds.
      let node: Record<string, unknown> = { leaf: 1 };
      for (let depth = 0; depth < 24; depth++) {
        node = { a: node, b: node };
      }

      const started = Date.now();
      expect(() => toWorkerPayload({}, { data: node, transport: 'json' })).not.toThrow();
      expect(Date.now() - started).toBeLessThan(1000);

      // And a genuine cycle is still caught rather than followed.
      const loop: Record<string, unknown> = { shared: node };
      loop['self'] = loop;
      expect(() => toWorkerPayload({}, { data: loop, transport: 'json' })).toThrow('circular');
    });

    it('skips the checks when there is no data and no tags', () => {
      const clone = vi.spyOn(globalThis, 'structuredClone');

      toWorkerPayload({ token: token() }, { context: { name: 'req', reason: 'r' } });

      expect(clone).not.toHaveBeenCalled();
      clone.mockRestore();
    });
  });
});

describe('fromWorkerPayload', () => {
  afterEach(() => {
    resetPolicies();
  });

  describe('round trip', () => {
    it('rebuilds each value with its class, label and deadline', () => {
      const expiresAt = new Date(Date.now() + 60_000);
      const payload = toWorkerPayload({
        token: token(),
        otp: new SensitiveString(OTHER_CANARY, 'sensitive', 'otp', { expiresAt }),
      });

      const { values } = fromWorkerPayload<{
        token: SensitiveString<'credential'>;
        otp: SensitiveString<'sensitive'>;
      }>(crossed(payload));

      expect(values.token).toBeInstanceOf(SensitiveString);
      expect(values.token.klass).toBe('credential');
      expect(values.token.label).toBe('api_key');
      expect(values.token.reveal()).toBe(CANARY);
      expect(values.otp.klass).toBe('sensitive');
      expect(values.otp.expiresAt?.toISOString()).toBe(expiresAt.toISOString());
      expect(values.otp.reveal()).toBe(OTHER_CANARY);
    });

    it("returns the carried context with this side's hook attached", () => {
      const payload = toWorkerPayload(
        { token: token() },
        { context: { name: 'req-42', reason: 'charge', tags: { userId: 'u1' } } }
      );
      const { hook, calls } = recordingHook();

      const { context } = fromWorkerPayload(crossed(payload), { auditReveal: hook });

      expect(context.name).toBe('req-42');
      expect(context.reason).toBe('charge');
      expect(context.tags).toEqual({ userId: 'u1' });
      // eslint-disable-next-line @typescript-eslint/unbound-method -- identity, not a call
      expect(context.auditReveal).toBe(hook);
      expect(calls).toEqual([]);
    });

    it('returns a context named worker when the payload carried none', () => {
      const { hook } = recordingHook();

      const { context } = fromWorkerPayload(crossed(toWorkerPayload({ token: token() })), {
        auditReveal: hook,
      });

      expect(context).toEqual({ name: 'worker', auditReveal: hook });
    });

    it('returns data untouched and a fresh counter on every value', () => {
      const value = token();
      value.reveal();
      const payload = toWorkerPayload({ token: value }, { data: { batchSize: 100 } });

      const received = fromWorkerPayload<{ token: SensitiveString<'credential'> }>(
        crossed(payload)
      );

      expect(received.data).toEqual({ batchSize: 100 });
      expect(received.values.token.revealCount).toBe(0);
    });

    it('decides renewal by the receiving policy, and takes no grant from the payload', () => {
      const renewable = new SensitiveString(CANARY, 'sensitive', 'session', {
        ttl: 60_000,
        allowRenewal: true,
      });
      const payload = toWorkerPayload({ session: renewable });

      const { values } = fromWorkerPayload<{ session: SensitiveString<'sensitive'> }>(
        crossed(payload)
      );

      // Nothing about renewal is on the wire, so the receiver decides from its
      // own policy. For `sensitive` that means renewable, and this really does
      // renew rather than merely not saying so.
      expect(payload.values.session).not.toHaveProperty('allowRenewal');
      expect(payload.values.session).not.toHaveProperty('maxRenewals');
      const before = values.session.expiresAt?.getTime() ?? 0;
      values.session.renew(60_000);
      expect(values.session.expiresAt?.getTime() ?? 0).toBeGreaterThan(before);

      // A credential is the direction that matters: its class is not
      // renewable, and a sender that granted renewal cannot lift that.
      const granted = new SensitiveString(CANARY, 'credential', 'otp', {
        ttl: 60_000,
        allowRenewal: true,
      });
      const rebuilt = fromWorkerPayload<{ otp: SensitiveString<'credential'> }>(
        crossed(toWorkerPayload({ otp: granted }))
      ).values.otp;

      expect(() => rebuilt.renew(60_000)).toThrow(RenewalNotAllowedError);
      // And the sender's own instance still renews, so the refusal is the
      // wire format dropping the grant rather than the class forbidding it.
      expect(() => granted.renew(60_000)).not.toThrow();
    });
  });

  describe('require', () => {
    it('accepts a complete payload and refuses an incomplete one by key', () => {
      const payload = crossed(toWorkerPayload({ token: token() }));

      expect(() => fromWorkerPayload(crossed(payload), { require: ['token'] })).not.toThrow();

      try {
        fromWorkerPayload(payload, { require: ['token', 'dsn'] });
        expect.unreachable();
      } catch (error) {
        expect(error).toBeInstanceOf(MissingWorkerValueError);
        expect((error as MissingWorkerValueError).key).toBe('dsn');
        expect((error as MissingWorkerValueError).code).toBe('missing-value');
      }
    });

    it('checks require before consuming, so the payload survives the refusal', () => {
      const payload = crossed(toWorkerPayload({ token: token() }));

      expect(() => fromWorkerPayload(payload, { require: ['dsn'] })).toThrow(
        MissingWorkerValueError
      );
      expect(payload.values.token.value).toBe(CANARY);
      expect(payload.consumed).toBeUndefined();
    });
  });

  describe('an unaudited worker throws', () => {
    it('refuses an audited payload with no hook, and the error carries no value', () => {
      const payload = crossed(
        toWorkerPayload(
          { token: token() },
          { context: { name: 'req', auditReveal: () => undefined } }
        )
      );

      try {
        fromWorkerPayload(payload);
        expect.unreachable();
      } catch (error) {
        expect(error).toBeInstanceOf(UnauditedWorkerError);
        expect((error as UnauditedWorkerError).code).toBe('unaudited-worker');
        expect((error as Error).message).not.toContain(CANARY);
        expect(util.inspect(error)).not.toContain(CANARY);
      }

      // Refused before consuming: a corrected call succeeds.
      expect(payload.consumed).toBeUndefined();
      expect(() => fromWorkerPayload(payload, { auditReveal: () => undefined })).not.toThrow();
    });

    it('is satisfied by an explicit hook', () => {
      const payload = crossed(
        toWorkerPayload(
          { token: token() },
          { context: { name: 'req', auditReveal: () => undefined } }
        )
      );

      expect(() => fromWorkerPayload(payload, { auditReveal: () => undefined })).not.toThrow();
    });

    it('is satisfied by an ambient hook, which the returned context forwards to', () => {
      const payload = crossed(
        toWorkerPayload(
          { token: token() },
          { context: { name: 'req', auditReveal: () => undefined } }
        )
      );
      const { hook, calls } = recordingHook();

      withRevealContext({ name: 'parent-handler', auditReveal: hook }, () => {
        const received = fromWorkerPayload<{ token: SensitiveString<'credential'> }>(payload);

        // Installing the returned context must not replace the ambient hook
        // with nothing, which is what a bare `{ name }` would do.
        withRevealContext(received.context, () => {
          received.values.token.reveal();
        });
      });

      expect(calls).toEqual([{ operation: 'reveal' }]);
    });

    it('is satisfied by allowUnaudited, and then records nothing', () => {
      const payload = crossed(
        toWorkerPayload(
          { token: token() },
          { context: { name: 'req', auditReveal: () => undefined } }
        )
      );

      const received = fromWorkerPayload<{ token: SensitiveString<'credential'> }>(payload, {
        allowUnaudited: true,
      });

      // eslint-disable-next-line @typescript-eslint/unbound-method -- presence, not a call
      expect(received.context.auditReveal).toBeUndefined();
      expect(received.values.token.reveal()).toBe(CANARY);
    });

    it('never triggers for a payload built without a hook', () => {
      const payload = crossed(toWorkerPayload({ token: token() }, { context: { name: 'req' } }));

      expect(() => fromWorkerPayload(payload)).not.toThrow();
    });
  });

  describe('consumption', () => {
    it('deletes the raw values from the payload and marks it consumed', () => {
      const payload = crossed(toWorkerPayload({ token: token(), dsn: token(OTHER_CANARY) }));

      expect(JSON.stringify(payload)).toContain(CANARY);
      expect(util.inspect(payload, { depth: null })).toContain(CANARY);

      fromWorkerPayload(payload);

      expect(payload.consumed).toBe(true);
      expect(payload.values.token).not.toHaveProperty('value');
      expect(payload.values.dsn).not.toHaveProperty('value');
      expect(JSON.stringify(payload)).not.toContain(CANARY);
      expect(JSON.stringify(payload)).not.toContain(OTHER_CANARY);
      expect(util.inspect(payload, { depth: null })).not.toContain(CANARY);
    });

    it('keeps the marker and the class, so a consumed payload still redacts', () => {
      const payload = crossed(toWorkerPayload({ token: token() }));

      fromWorkerPayload(payload);

      expect(payload.values.token.__sensitive).toBe(true);
      expect(payload.values.token.klass).toBe('credential');
      expect(redactInStructure(payload)).toEqual({
        __sensitiveWorkerPayload: 1,
        values: { token: '[REDACTED:credential]' },
        audited: false,
        consumed: true,
      });
    });

    it('throws already-consumed on a second call and returns nothing', () => {
      const payload = crossed(toWorkerPayload({ token: token() }));

      fromWorkerPayload(payload);

      expect(() => fromWorkerPayload(payload)).toThrow(ConsumedWorkerPayloadError);
      try {
        fromWorkerPayload(payload);
      } catch (error) {
        expect((error as ConsumedWorkerPayloadError).code).toBe('consumed-payload');
      }
    });

    it('a payload re-sent after consumption arrives consumed', () => {
      const payload = crossed(toWorkerPayload({ token: token() }));
      fromWorkerPayload(payload);

      const second = crossed(payload);

      expect(JSON.stringify(second)).not.toContain(CANARY);
      expect(() => fromWorkerPayload(second)).toThrow(ConsumedWorkerPayloadError);
    });

    it('a payload carrying consumed: true from the sender is refused', () => {
      const payload = crossed(toWorkerPayload({ token: token() }));
      payload.consumed = true;

      expect(() => fromWorkerPayload(payload)).toThrow(ConsumedWorkerPayloadError);
    });

    it('a frozen payload still hands back its values rather than throwing', () => {
      // Consumption is hardening applied after the rebuild has succeeded. A
      // caller who froze the payload keeps the plaintext, which is their
      // doing; what must not happen is losing the values as well, which is
      // strictly worse than either outcome alone.
      const payload = crossed(toWorkerPayload({ token: token() }));
      Object.freeze(payload);
      Object.freeze(payload.values.token);

      const received = fromWorkerPayload<{ token: SensitiveString<'credential'> }>(payload);

      expect(received.values.token.reveal()).toBe(CANARY);
      expect(payload.consumed).toBeUndefined();
    });

    it('consumes what it can when only one entry is frozen', () => {
      const payload = crossed(toWorkerPayload({ open: token(), shut: token(OTHER_CANARY) }));
      Object.freeze(payload.values.shut);

      fromWorkerPayload(payload);

      expect(payload.values.open).not.toHaveProperty('value');
      expect(payload.values.shut.value).toBe(OTHER_CANARY);
      expect(payload.consumed).toBe(true);
    });

    it('keepPayload leaves the values in place and allows a second consumer', () => {
      const payload = crossed(toWorkerPayload({ token: token() }));

      const first = fromWorkerPayload<{ token: SensitiveString<'credential'> }>(payload, {
        keepPayload: true,
      });
      const second = fromWorkerPayload<{ token: SensitiveString<'credential'> }>(payload, {
        keepPayload: true,
      });

      expect(payload.consumed).toBeUndefined();
      expect(payload.values.token.value).toBe(CANARY);
      expect(first.values.token.reveal()).toBe(CANARY);
      expect(second.values.token.reveal()).toBe(CANARY);
    });

    it("works on the sender's own object, so a worker function can be tested in-process", () => {
      const payload = toWorkerPayload({ token: token() });

      expect(
        fromWorkerPayload<{ token: SensitiveString<'credential'> }>(payload).values.token.reveal()
      ).toBe(CANARY);
      expect(payload.consumed).toBe(true);
    });
  });

  describe('a class the receiving thread does not know', () => {
    it('is refused by key and class, and the message names the bootstrap fix', () => {
      registerPolicy({ name: 'pii' as SensitivityClass, redact: () => '[PII]' });
      const payload = crossed(
        toWorkerPayload({ ssn: new SensitiveString(CANARY, 'pii' as SensitivityClass, 'ssn') })
      );

      // The receiving isolate never registered the class.
      resetPolicies();

      try {
        fromWorkerPayload(payload);
        expect.unreachable();
      } catch (error) {
        const refusal = error as UnregisteredClassError;
        expect(refusal).toBeInstanceOf(UnregisteredClassError);
        expect(refusal.code).toBe('unregistered-class');
        expect(refusal.key).toBe('ssn');
        expect(refusal.klass).toBe('pii');
        expect(refusal.message).toContain("'pii'");
        expect(refusal.message).toContain('registerPolicy()');
        expect(refusal.message).toContain('sensitive, credential');
        expect(refusal.message).not.toContain(CANARY);
      }

      // Refused before consuming, so a bootstrap that registers the class
      // and retries succeeds.
      expect(payload.consumed).toBeUndefined();
    });
  });

  describe('expiry at the boundary', () => {
    it('refuses a value that expired in transit, naming the key, and consumes the payload', async () => {
      const payload = crossed(
        toWorkerPayload({ otp: new SensitiveString(CANARY, 'credential', 'otp', { ttl: 5 }) })
      );

      await new Promise((resolve) => setTimeout(resolve, 15));

      try {
        fromWorkerPayload(payload);
        expect.unreachable();
      } catch (error) {
        const refusal = error as ExpiredSensitiveValueError;
        expect(refusal).toBeInstanceOf(ExpiredSensitiveValueError);
        expect(refusal.code).toBe('expired-value');
        expect(refusal.key).toBe('otp');
        expect(refusal.label).toBe('otp');
        expect(refusal.message).toContain("payload key 'otp'");
        expect(refusal.message).not.toContain(CANARY);
      }

      expect(payload.consumed).toBe(true);
      expect(JSON.stringify(payload)).not.toContain(CANARY);
    });

    it('a live value with a deadline arrives live', () => {
      const payload = crossed(
        toWorkerPayload({ otp: new SensitiveString(CANARY, 'credential', 'otp', { ttl: 60_000 }) })
      );

      expect(
        fromWorkerPayload<{ otp: SensitiveString<'credential'> }>(payload).values.otp.isExpired()
      ).toBe(false);
    });
  });

  describe('adversarial input', () => {
    it.each([
      ['null', null],
      ['undefined', undefined],
      ['a string', '{}'],
      ['an empty object', {}],
      ['a wrong marker', { __sensitiveWorkerPayload: 2 }],
      ['a true marker', { __sensitiveWorkerPayload: true }],
      ['an array', [1]],
      ['values as an array', { __sensitiveWorkerPayload: 1, values: [] }],
      ['values as a string', { __sensitiveWorkerPayload: 1, values: 'x' }],
      ['values as null', { __sensitiveWorkerPayload: 1, values: null }],
      ['a bare wire object', token().serialize()],
    ])('refuses %s as malformed and returns nothing', (_case, payload) => {
      expect(() => fromWorkerPayload(payload)).toThrow(MalformedWorkerPayloadError);
      try {
        fromWorkerPayload(payload);
      } catch (error) {
        expect((error as MalformedWorkerPayloadError).code).toBe('malformed-payload');
        expect((error as Error).message).not.toContain(CANARY);
      }
    });

    it.each([
      ['__sensitive: false', { __sensitive: false, klass: 'credential', value: CANARY }],
      ['a missing value', { __sensitive: true, klass: 'credential' }],
      ['a non-string value', { __sensitive: true, klass: 'credential', value: 42 }],
      ['a non-string klass', { __sensitive: true, klass: 7, value: CANARY }],
      ['a string entry', CANARY],
      ['a null entry', null],
      ['a bad label', { __sensitive: true, klass: 'credential', value: CANARY, label: 1 }],
      [
        'a bad deadline',
        { __sensitive: true, klass: 'credential', value: CANARY, expiresAt: 'soon' },
      ],
    ])('refuses an entry with %s, naming the key and not the value', (_case, entry) => {
      const payload = { __sensitiveWorkerPayload: 1, values: { token: entry }, audited: false };

      try {
        fromWorkerPayload(payload);
        expect.unreachable();
      } catch (error) {
        expect(error).toBeInstanceOf(MalformedWorkerPayloadError);
        expect((error as Error).message).toContain('values.token');
        expect((error as Error).message).not.toContain(CANARY);
      }
    });

    it('refuses a malformed context rather than installing it', () => {
      const base = crossed(toWorkerPayload({ token: token() }));

      for (const context of [
        42,
        { reason: 'no name' },
        { name: 'x', reason: 1 },
        { name: 'x', tags: 'y' },
      ]) {
        expect(() => fromWorkerPayload({ ...base, context })).toThrow(MalformedWorkerPayloadError);
      }
    });

    it('treats __proto__ and constructor keys as ordinary own keys on both sides', () => {
      const values: Record<string, SensitiveString<'credential'>> = {};
      Object.defineProperty(values, '__proto__', {
        value: token(),
        enumerable: true,
        writable: true,
        configurable: true,
      });
      values['constructor'] = token(OTHER_CANARY);

      const payload = crossed(toWorkerPayload(values));
      const received = fromWorkerPayload<Record<string, SensitiveString<'credential'>>>(payload);

      expect(Object.getPrototypeOf(received.values)).toBe(Object.prototype);
      expect(Object.hasOwn(received.values, '__proto__')).toBe(true);
      expect(Object.hasOwn(received.values, 'constructor')).toBe(true);
      expect(received.values['constructor']?.reveal()).toBe(OTHER_CANARY);
      expect(
        (
          Object.getOwnPropertyDescriptor(received.values, '__proto__')?.value as SensitiveString
        ).reveal()
      ).toBe(CANARY);
      expect(({} as Record<string, unknown>)['reveal']).toBeUndefined();
    });
  });
});

describe('withWorkerPayload', () => {
  it('installs the context and returns a sync value', () => {
    const { hook, calls } = recordingHook();
    const payload = crossed(
      toWorkerPayload(
        { token: token() },
        { context: { name: 'req-42', auditReveal: () => undefined } }
      )
    );

    const result = withWorkerPayload<{ token: SensitiveString<'credential'> }, string>(
      payload,
      { auditReveal: hook },
      ({ token }, data) => {
        expect(getCurrentRevealContext()?.name).toBe('req-42');
        expect(data).toBeUndefined();
        return token.reveal();
      }
    );

    expect(result).toBe(CANARY);
    expect(calls).toEqual([{ operation: 'reveal' }]);
  });

  it('returns a promise from an async fn, with the context held across the await', async () => {
    const payload = crossed(toWorkerPayload({ token: token() }, { context: { name: 'req-42' } }));

    const result = withWorkerPayload<{ token: SensitiveString<'credential'> }, Promise<string>>(
      payload,
      {},
      async ({ token }) => {
        await new Promise((resolve) => setTimeout(resolve, 1));
        expect(getCurrentRevealContext()?.name).toBe('req-42');
        return token.reveal();
      }
    );

    expect(result).toBeInstanceOf(Promise);
    await expect(result).resolves.toBe(CANARY);
  });

  it('propagates a throw from fn, and a refusal from the boundary', () => {
    const payload = crossed(toWorkerPayload({ token: token() }));

    expect(() =>
      withWorkerPayload(payload, {}, () => {
        throw new Error('from fn');
      })
    ).toThrow('from fn');

    expect(() => withWorkerPayload(payload, {}, () => 1)).toThrow(ConsumedWorkerPayloadError);
  });

  it('passes data through as the second argument', () => {
    const payload = crossed(toWorkerPayload({}, { data: { batchSize: 7 } }));

    expect(withWorkerPayload(payload, {}, (_values, data) => data)).toEqual({ batchSize: 7 });
  });
});

describe('the marker-aware walks over an unconsumed payload', () => {
  it.each([
    ['safeStringify', (p: unknown) => safeStringify(p)],
    ['redactInStructure', (p: unknown) => JSON.stringify(redactInStructure(p))],
    ['redactCopy', (p: unknown) => JSON.stringify(redactCopy(p))],
    [
      'sensitiveFormat',
      (p: unknown) =>
        JSON.stringify(
          sensitiveFormat().transform({ level: 'info', message: 'handoff', payload: p })
        ),
    ],
  ])('%s contains no canary', (_name, render) => {
    const payload = toWorkerPayload(
      { token: token(), dsn: new SensitiveString(OTHER_CANARY, 'sensitive', 'dsn') },
      { data: { batchSize: 1 } }
    );

    const output = render(payload);

    expect(output).not.toContain(CANARY);
    expect(output).not.toContain(OTHER_CANARY);
    expect(output).toContain('[REDACTED:credential]');
  });

  it('but JSON.stringify and util.inspect do, which is the window the consumption closes', () => {
    const payload = toWorkerPayload({ token: token() });

    expect(JSON.stringify(payload)).toContain(CANARY);
    expect(util.inspect(payload, { depth: null })).toContain(CANARY);
  });
});
