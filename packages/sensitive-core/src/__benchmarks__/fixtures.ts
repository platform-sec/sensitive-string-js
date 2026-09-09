/**
 * Shared fixtures for the core benchmarks.
 *
 * Nothing here is a test. The module exists to keep the cost of building an
 * input out of the measurement: a benchmark file builds what it needs once at
 * module scope, and the timed function only reads it.
 *
 * Values are deterministic. A run that measures a freshly randomized string
 * every iteration measures the allocator as much as the library.
 */

import { bench, describe } from 'vitest';

import { SensitiveString } from '../sensitive-string.js';

/**
 * Where results go, so the engine cannot decide a benchmarked call is
 * unobservable and delete the loop being measured.
 *
 * The binding is exported, which is what makes the write count: anything
 * outside the module could read it, so the store has to happen. Every
 * benchmark hands its result to `consume` or `consumeFlag`.
 */
export const sink: { value: unknown; checksum: number } = { value: undefined, checksum: 0 };

/** Keep a result alive. */
export function consume(value: unknown): void {
  sink.value = value;
}

/**
 * Keep a predicate result alive by folding it into a running total.
 *
 * A boolean stored into a field is cheap enough that the store can rival the
 * call being measured; the addition keeps that overhead uniform across every
 * member of a group, which is what the group is comparing.
 */
export function consumeFlag(value: boolean): void {
  sink.checksum += value ? 1 : 0;
}

/**
 * The floor every other benchmark is measured on top of.
 *
 * Tinybench times each call separately, and that bookkeeping costs on the
 * order of a hundred nanoseconds. Any operation in the same range is therefore
 * reported as a fraction of its real cost relative to another one, because
 * both carry the same constant: measured at 90ns, a 160ns operation and a
 * 1175ns one print as 7.4x apart when they are really 15.7x apart. Subtract
 * this group's figure from each side of a pair before taking their ratio.
 *
 * Two members rather than one, because every other benchmark ends in
 * `consume`, so the second is the subtrahend to use and the first says how
 * much of it is the sink rather than the harness.
 *
 * Every file declares this group. The floor belongs to the run rather than to
 * the library, and it can drift between workers.
 */
export function benchFloor(): void {
  describe('harness floor', () => {
    bench('empty function', () => {
      // Deliberately empty: this is the harness measuring itself.
    });

    bench('consume a constant', () => {
      consume(FLOOR_CONSTANT);
    });
  });
}

/** Read by the floor probe, so the sink write it measures is a real one. */
const FLOOR_CONSTANT = 'floor';

/**
 * A conspicuous prefix, so a value that escapes into output during a run is
 * recognizable as having come from here.
 */
const CANARY = 'BENCH_CANARY';

const FILLER = 'abcdefghijklmnopqrstuvwxyz0123456789';

/** A deterministic value of an exact length. */
export function valueOfLength(length: number): string {
  let out = CANARY;

  while (out.length < length) {
    out += FILLER;
  }

  return out.slice(0, length);
}

/**
 * An equal value with a different identity.
 *
 * `===` on two references to one string is a pointer comparison, so an
 * instance compared against the very string it was built from measures
 * nothing about length: the `sensitive` sweep reported 16KB as six times
 * faster than 16 chars, which is the pointer compare, not the library.
 * Splitting and rejoining yields a string the engine has not internalized,
 * which forces the content comparison the sweep exists to measure.
 */
export function distinctCopy(value: string): string {
  const half = value.length >> 1;

  return `${value.slice(0, half)}${value.slice(half)}`;
}

/**
 * The lengths every size sweep uses.
 *
 * The span is deliberate: 16 is a short identifier, 64 a token, 1024 a signed
 * blob, and 16384 large enough that per-character work separates from
 * per-call overhead.
 */
export const LENGTHS = [16, 64, 1024, 16384] as const;

/** A 64 character credential, the length most of the single-value groups use. */
export const TOKEN = valueOfLength(64);

/**
 * A request-shaped record: plain scalars, two levels of nesting, and four
 * sensitive values among a dozen fields. It stands in for the object a service
 * hands to a logger, which is where the structure walkers actually run.
 */
export function requestPayload(): Record<string, unknown> {
  return {
    requestId: 'req-0f8c2a1b',
    method: 'POST',
    path: '/v1/charges',
    status: 201,
    durationMs: 42,
    user: {
      id: 'usr_8812',
      locale: 'en-GB',
      email: new SensitiveString('ada@example.com', 'sensitive', 'email'),
      ssn: new SensitiveString('123-45-6789', 'sensitive', 'ssn'),
    },
    auth: {
      scheme: 'Bearer',
      scopes: ['charges:write', 'charges:read'],
      token: new SensitiveString(TOKEN, 'credential', 'access_token'),
      refresh: new SensitiveString(valueOfLength(96), 'credential', 'refresh_token'),
    },
    metadata: { retries: 0, idempotencyKey: 'idem_5f2' },
  };
}

/**
 * The same shape with plain strings in place of the sensitive values.
 *
 * The gap between this and {@link requestPayload} is what redaction costs on
 * top of the walk, as opposed to what walking a payload costs at all.
 */
export function plainPayload(): Record<string, unknown> {
  return {
    requestId: 'req-0f8c2a1b',
    method: 'POST',
    path: '/v1/charges',
    status: 201,
    durationMs: 42,
    user: {
      id: 'usr_8812',
      locale: 'en-GB',
      email: 'ada@example.com',
      ssn: '123-45-6789',
    },
    auth: {
      scheme: 'Bearer',
      scopes: ['charges:write', 'charges:read'],
      token: TOKEN,
      refresh: valueOfLength(96),
    },
    metadata: { retries: 0, idempotencyKey: 'idem_5f2' },
  };
}

/** The paths of {@link plainPayload} that {@link requestPayload} wraps. */
export const PAYLOAD_FIELDS = {
  'user.email': 'sensitive',
  'user.ssn': { klass: 'sensitive', label: 'ssn' },
  'auth.token': { klass: 'credential', label: 'access_token' },
  'auth.refresh': { klass: 'credential', label: 'refresh_token' },
} as const;

/** `count` account-shaped records, each carrying two sensitive fields. */
export function recordList(count: number): Record<string, unknown>[] {
  return Array.from({ length: count }, (_unused, index) => ({
    id: `acct_${index}`,
    active: index % 3 !== 0,
    email: new SensitiveString(`user${index}@example.com`, 'sensitive', 'email'),
    apiKey: new SensitiveString(valueOfLength(48), 'credential', 'api_key'),
  }));
}

/**
 * The same records with plain strings in place of the sensitive values.
 *
 * The control for a response filter rather than for a log line. Express,
 * Fastify and NestJS run `redactCopy` over every JSON body they send, so a
 * collection with nothing sensitive in it is not an edge case: it is what most
 * endpoints return, and the gap between this and {@link recordList} is the only
 * part of the cost that redaction is responsible for. The rest is the walk,
 * which that response pays to establish that there was nothing to redact.
 */
export function plainRecordList(count: number): Record<string, unknown>[] {
  return Array.from({ length: count }, (_unused, index) => ({
    id: `acct_${index}`,
    active: index % 3 !== 0,
    email: `user${index}@example.com`,
    apiKey: valueOfLength(48),
  }));
}

/**
 * `count` records of which only the last carries anything sensitive.
 *
 * The worst case for any strategy that detects before it redacts, and the one
 * shape neither {@link recordList} nor {@link plainRecordList} can expose.
 * `containsSensitive` returns on its first hit, so a list that is wrapped
 * throughout answers in microseconds and a list wrapped only at the end costs a
 * full walk before the redaction walk even begins. A group that measures only
 * the first two shapes reports the check as free or nearly so, which is true of
 * both of them and not of this.
 */
export function recordListWrappedLast(count: number): Record<string, unknown>[] {
  const records = plainRecordList(count);
  const last = records[count - 1];

  if (last !== undefined) {
    last['email'] = new SensitiveString(`user${count - 1}@example.com`, 'sensitive', 'email');
  }

  return records;
}

/**
 * A chain `depth` levels deep with one sensitive value at the bottom, for the
 * walkers whose cost is driven by nesting rather than by breadth.
 */
export function nestedPayload(depth: number): Record<string, unknown> {
  let node: Record<string, unknown> = {
    token: new SensitiveString(TOKEN, 'credential', 'access_token'),
  };

  for (let level = 0; level < depth; level += 1) {
    node = { level, sibling: `plain-${level}`, child: node };
  }

  return node;
}
