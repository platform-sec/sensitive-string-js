import type {
  RevealContext,
  SensitivityClass,
  SensitiveString,
} from '@platform-sec/sensitive-string-core';

import { assertNoMarker } from './marker.js';
import { isSensitive } from './reveal.js';
import type { PlanRecorder } from './scrub.js';

/**
 * Auth headers are descriptors, not strings.
 *
 * The guard can only read what this package built. `` `Bearer ${token}` `` is
 * the single most likely way for a marker to reach a header, and it is
 * unreachable through these helpers: they take the instance, and the reveal and
 * the encoding both happen inside the request pipeline, in that order, with the
 * guard run on each component **before** it is encoded.
 *
 * That last ordering is what keeps `Basic` auth honest. Base64 hides a marker
 * completely, so the guard's base64 needles exist for callers who do their own
 * encoding; `basic()` checks the username and the password as plain text and
 * the needles never have to fire on the happy path.
 */

const AUTH_HEADER = Symbol.for('@platform-sec/sensitive-string-http.auth-header');

/** Opaque descriptor for a header value this package will build. */
export interface AuthHeader {
  readonly [AUTH_HEADER]: true;
  readonly scheme: 'bearer' | 'basic' | 'raw';
  /** Instances to reveal, in the order the renderer consumes them. */
  readonly parts: readonly (SensitiveString<SensitivityClass> | string)[];
  /** Builds the final header value from the already-revealed, already-guarded parts. */
  render(revealed: readonly string[]): string;
}

export function isAuthHeader(value: unknown): value is AuthHeader {
  return (
    typeof value === 'object' &&
    value !== null &&
    (value as Record<PropertyKey, unknown>)[AUTH_HEADER] === true
  );
}

/**
 * `Authorization: Bearer <token>`.
 *
 * Takes `credential` only. A bearer token classified `sensitive` is
 * misclassified, and the type is where that is cheapest to say.
 */
export function bearer(token: SensitiveString<'credential'>): AuthHeader {
  return {
    [AUTH_HEADER]: true,
    scheme: 'bearer',
    parts: [token],
    render: (revealed) => `Bearer ${revealed[0] ?? ''}`,
  };
}

/**
 * `Authorization: Basic base64(user:password)`.
 *
 * The username may be a plain string, because it usually is, or an instance
 * when it is an account identifier worth classifying. Both components are
 * guarded as plain text before the base64 runs.
 */
export function basic(
  user: string | SensitiveString<SensitivityClass>,
  password: SensitiveString<'credential'>
): AuthHeader {
  return {
    [AUTH_HEADER]: true,
    scheme: 'basic',
    parts: [user, password],
    render: (revealed) =>
      `Basic ${Buffer.from(`${revealed[0] ?? ''}:${revealed[1] ?? ''}`, 'utf8').toString('base64')}`,
  };
}

/**
 * A bare credential as the whole header value.
 *
 * The header name comes from the key it is assigned to, so this takes only the
 * value: `headers: { 'x-api-key': apiKey(token) }`.
 *
 * A request carrying one of these defaults to refusing redirects. The Fetch
 * specification strips `Authorization`, `Cookie` and `Proxy-Authorization`
 * across origins and nothing else, and every client measured forwards
 * `x-api-key` verbatim to whatever host the first server names.
 */
export function apiKey(value: SensitiveString<'credential'>): AuthHeader {
  return {
    [AUTH_HEADER]: true,
    scheme: 'raw',
    parts: [value],
    render: (revealed) => revealed[0] ?? '',
  };
}

/**
 * Reveal an `AuthHeader`'s parts, guard each one as plain text, then encode.
 *
 * @throws MarkerLeakError when a plain-string part carries a marker, which
 *   means the caller built it by interpolating an instance.
 */
export function renderAuthHeader(
  header: AuthHeader,
  name: string,
  ctx: RevealContext,
  plan: PlanRecorder
): string {
  const revealed: string[] = [];

  for (const part of header.parts) {
    if (isSensitive(part)) {
      plan.record(name, part);
      revealed.push(part.reveal(ctx));
      continue;
    }

    // A plain-string part is the caller's, so it is the one that can already
    // hold a marker. Checked before it is encoded, which is the whole reason
    // the encoding lives here.
    assertNoMarker(part, `header '${name}'`);
    revealed.push(part);
  }

  return header.render(revealed);
}

/**
 * The Fetch specification's cross-origin redirect stripping set, and nothing else.
 *
 * This is what the specification requires, which is not the same claim as what
 * any particular client does. Read `CLIENT_STRIPPED_HEADERS` for that.
 */
export const STRIPPED_HEADERS: ReadonlySet<string> = new Set([
  'authorization',
  'cookie',
  'proxy-authorization',
]);

/** The answer for a client nobody has measured: it strips nothing. */
const NOTHING_STRIPPED: ReadonlySet<string> = new Set();

/**
 * What each wrapped client actually drops on a cross-origin redirect.
 *
 * Per client rather than one global set, because "the platform strips it" is
 * not a property of the header. It is a property of whichever client is
 * holding the request, and clients disagree: a survey of Node HTTP clients
 * found several that forward `Authorization` across origins, so a library that
 * assumes the specification is obeyed is trusting an implementation it has
 * never looked at.
 *
 * Every entry below was measured rather than read off the specification. Two
 * loopback servers on different ports, which is a different origin under the
 * scheme/host/port rule, a 302 from the first to the second, and the second
 * recording what arrived: axios 1.20.0, got 16.0.0, ky 2.1.0, undici 8.10.1
 * and Node 22.15's global `fetch`. All five dropped all three names, and all
 * five forwarded `x-api-key` untouched, which is the whole reason this package
 * exists.
 *
 * `proxy-authorization` is in each entry on that measurement. It used to be in
 * the single global set on the specification's authority alone, which is the
 * kind of claim this table exists to stop.
 */
const CLIENT_STRIPPED_HEADERS: ReadonlyMap<string, ReadonlySet<string>> = new Map([
  ['axios', STRIPPED_HEADERS],
  ['fetch', STRIPPED_HEADERS],
  ['got', STRIPPED_HEADERS],
  ['ky', STRIPPED_HEADERS],
  ['undici', STRIPPED_HEADERS],
]);

/**
 * Whether a credential in this header would be stripped on a cross-origin
 * redirect, by this client.
 *
 * `false` is what makes `allowedHosts: false` the default for the request: the
 * client will not protect that header, so either the caller names the hosts
 * they trust or the redirect is not followed.
 *
 * An unrecognized client answers `false` for every header. `prepareRequest`
 * takes the client name as a string, so anything may arrive here, and the
 * exemption is a promise that a specific implementation was checked. Granting
 * it to a name nobody has measured is how a wrapper around a client that
 * forwards `Authorization` would look correct.
 *
 * @param name - Header name, matched case-insensitively.
 * @param client - The client identifier `prepareRequest` was given.
 */
export function isStrippedAcrossOrigins(name: string, client: string): boolean {
  const stripped = CLIENT_STRIPPED_HEADERS.get(client) ?? NOTHING_STRIPPED;

  return stripped.has(name.toLowerCase());
}

/** The clients whose stripping behaviour has been measured. */
export function measuredClients(): readonly string[] {
  return [...CLIENT_STRIPPED_HEADERS.keys()];
}
