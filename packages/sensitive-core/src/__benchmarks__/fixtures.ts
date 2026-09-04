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
