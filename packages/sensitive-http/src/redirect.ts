import {
  InsecureTransportError,
  RedirectHostNotAllowedError,
  TooManyRedirectsError,
} from './errors.js';

/**
 * Where a revealed credential is allowed to go.
 *
 * Section 2.4 of the design measured a 302 from origin A to origin B with four
 * headers carrying a raw value, on axios 1.20.0, got 16.0.0, ky 2.1.0, undici
 * 8.10.1 and Node 22.15's `fetch`. All five stripped `Authorization`, `Cookie`
 * and `Proxy-Authorization`, and all five forwarded `x-api-key` verbatim. They
 * are not wrong: the Fetch specification names those three headers and no
 * other, and most providers authenticate with a name outside that set.
 *
 * So "reveal at the wire" is incomplete, because the wire is not a point. It is
 * a sequence of hosts chosen partly by the server.
 *
 * Which of those names is actually stripped is answered per client, in
 * `auth.ts`, rather than once for all of them. The five above agree today;
 * clients that forward `Authorization` across origins exist, and the point of
 * keeping the answer per client is that adding one of them cannot silently
 * inherit an exemption measured on a different implementation.
 */

/** Loopback destinations, where plaintext is a sidecar rather than a mistake. */
const LOOPBACK = new Set(['localhost', '127.0.0.1', '::1', '[::1]', '0.0.0.0']);

export function isLoopback(hostname: string): boolean {
  const bare = hostname.replace(/^\[|\]$/g, '');

  return LOOPBACK.has(hostname) || LOOPBACK.has(bare) || bare.startsWith('127.');
}

/** Ports the URL parser leaves implicit, so `http://a` and `http://a:80` are one origin. */
const DEFAULT_PORT: Readonly<Record<string, string>> = { 'http:': '80', 'https:': '443' };

function effectivePort(url: URL): string {
  return url.port === '' ? (DEFAULT_PORT[url.protocol] ?? '') : url.port;
}

/**
 * Whether a hop leaves the origin, by the scheme/host/port rule.
 *
 * One exception, and it is the only one: `http:` to `https:` on the same host,
 * where neither side names a non-default port. That is an upgrade to the same
 * server, every client in the measured set follows it without stripping, and
 * treating it as a boundary would drop a credential on a request that is
 * strictly more protected than the one that carried it. The reverse is never
 * allowed: `https:` to `http:` is a downgrade and always crosses.
 *
 * Deliberately not `hostAllowed`'s comparison. That one answers whether a host
 * is on a list the caller wrote, which is a different question with a different
 * failure mode.
 */
export function isCrossOrigin(from: URL, to: URL): boolean {
  if (from.hostname.toLowerCase() !== to.hostname.toLowerCase()) {
    return true;
  }

  if (from.protocol === to.protocol) {
    return effectivePort(from) !== effectivePort(to);
  }

  const upgrading = from.protocol === 'http:' && to.protocol === 'https:';

  return !(upgrading && from.port === '' && to.port === '');
}

/**
 * Refuse a plaintext hop that would carry a credential.
 *
 * Runs **before** the reveal, so a request to a host that fails this check
 * never reveals anything at all, rather than revealing and then declining to
 * send. That ordering is the point of the check, not an optimization.
 *
 * @throws InsecureTransportError
 */
export function assertTransport(
  url: URL,
  carriesCredential: boolean,
  allowInsecure: boolean
): void {
  if (!carriesCredential || allowInsecure || url.protocol === 'https:') {
    return;
  }

  if (url.protocol === 'http:' && isLoopback(url.hostname)) {
    return;
  }

  throw new InsecureTransportError(`${url.protocol}//${url.host}${url.pathname}`);
}

/**
 * Decide the redirect policy for a request.
 *
 * `false` means the wrapper does not follow redirects at all, which is the
 * default the moment a credential sits in a header this client will not strip.
 * An explicit `allowedHosts` always wins, because naming the hosts, or naming
 * `'strip'`, is the caller saying they have thought about it.
 *
 * `'strip'` is never a default and cannot become one. Refusing is the answer
 * that cannot go wrong quietly, and a request that stops is a bug report;
 * a credential dropped on a hop the caller did not expect to be crossed is a
 * request that succeeds while doing less than it looks like it did.
 */
export function resolveRedirectPolicy(
  configured: RedirectPolicy | undefined,
  hasUnstrippedCredential: boolean
): ResolvedRedirectPolicy {
  if (configured !== undefined) {
    return configured;
  }

  // No configuration and every credential is in a header this client strips:
  // leave the client's own redirect handling alone. Re-implementing stripping
  // would be worse than trusting five independent implementations that agree,
  // and a client outside those five never reaches here with `false`.
  return hasUnstrippedCredential ? false : 'client';
}

/**
 * What a caller may configure.
 *
 * `'strip'` follows the redirect with every credential-bearing header removed
 * on a cross-origin hop, which is the third answer between refusing outright
 * and naming hosts. It exists because naming hosts is impossible for a
 * provider that redirects release assets to object storage the caller cannot
 * enumerate in advance, and the two answers this package had before were
 * "break the feature" and "list what you cannot list".
 */
export type RedirectPolicy = readonly string[] | false | 'strip';

/** What `resolveRedirectPolicy` returns, adding the delegating case. */
export type ResolvedRedirectPolicy = RedirectPolicy | 'client';

/** Match a host against the allow list, comparing `host` (with port) and `hostname`. */
export function hostAllowed(url: URL, allowed: readonly string[]): boolean {
  return allowed.some((entry) => {
    const normalized = entry.toLowerCase();

    return url.host.toLowerCase() === normalized || url.hostname.toLowerCase() === normalized;
  });
}

/**
 * Check one redirect hop.
 *
 * @throws RedirectHostNotAllowedError before the next request is built.
 * @throws TooManyRedirectsError when the hop budget is spent.
 */
export function assertHopAllowed(
  next: URL,
  hop: number,
  policy: RedirectPolicy,
  budget: number
): void {
  if (hop > budget) {
    throw new TooManyRedirectsError(budget);
  }

  // `'strip'` allows every host, which is the point of it: the credential is
  // what is not allowed to travel, not the request. The hop budget above still
  // applies, because an unbounded redirect chain is a separate problem.
  if (policy === 'strip') {
    return;
  }

  if (policy === false) {
    throw new RedirectHostNotAllowedError(next.host, false, hop);
  }

  if (!hostAllowed(next, policy)) {
    throw new RedirectHostNotAllowedError(next.host, policy, hop);
  }
}

/**
 * Headers with a set of names removed, matched without regard to case.
 *
 * The names come from `plan.headers`, which holds exactly the header names
 * whose values carried a wrapped class, so what counts as a credential is the
 * caller's own classification. That is the whole difference between this and a
 * fixed denylist, which has to guess the names an application invents and is
 * wrong for `PRIVATE-TOKEN` and every other header a provider makes up.
 *
 * Case folding is not incidental. `plan.headers` is lowercased and the caller
 * wrote whatever they wrote, and comparing those two without folding is
 * precisely the mistake that disclosed a credential in GHSA-p2f4-r6v6-j797.
 *
 * A wrapper is expected to accumulate `dropped` across hops and apply this at
 * the point the next request is built, rather than narrowing a header object
 * once. The two are not equivalent: a client that merges its own instance
 * defaults in afterwards would refill a name that had been removed from the
 * per-request headers, and accumulating names survives that where narrowing an
 * object does not.
 *
 * @param headers - Headers about to be sent, in whatever casing the caller used.
 * @param dropped - Names to remove, in any casing. Empty means no change.
 */
export function headersWithout<T>(
  headers: Readonly<Record<string, T>> | undefined,
  dropped: readonly string[]
): Readonly<Record<string, T>> | undefined {
  if (headers === undefined || dropped.length === 0) {
    return headers;
  }

  const remove = new Set(dropped.map((name) => name.toLowerCase()));
  const kept: Record<string, T> = {};

  for (const [name, value] of Object.entries(headers)) {
    if (!remove.has(name.toLowerCase())) {
      kept[name] = value;
    }
  }

  return kept;
}

/** Status codes that carry a `Location` a client is expected to follow. */
export const REDIRECT_STATUSES: ReadonlySet<number> = new Set([301, 302, 303, 307, 308]);

export function isRedirect(status: number): boolean {
  return REDIRECT_STATUSES.has(status);
}

/**
 * The method and body the next hop uses.
 *
 * 303 always becomes GET, and 301 and 302 become GET for anything that was not
 * GET or HEAD, which is what every client in the measured set does and what the
 * Fetch specification requires. 307 and 308 preserve both.
 */
export function redirectMethod(
  status: number,
  method: string
): { method: string; keepBody: boolean } {
  const upper = method.toUpperCase();

  if (status === 307 || status === 308) {
    return { method: upper, keepBody: true };
  }

  if (status === 303 || (upper !== 'GET' && upper !== 'HEAD')) {
    return { method: 'GET', keepBody: false };
  }

  return { method: upper, keepBody: true };
}
