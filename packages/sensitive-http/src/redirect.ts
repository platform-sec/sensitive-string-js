import {
  InsecureTransportError,
  RedirectHostNotAllowedError,
  TooManyRedirectsError,
} from './errors.js';

/**
 * Where a revealed credential is allowed to go.
 *
 * Section 2.4 of the design measured a 302 from origin A to origin B with three
 * headers carrying a raw value, on axios 1.20.0, got 16.0.0 and Node 22's
 * `fetch`. All three stripped `Authorization` and `Cookie`, and all three
 * forwarded `x-api-key` verbatim. They are not wrong: the Fetch specification
 * names `Authorization`, `Cookie` and `Proxy-Authorization` and no other
 * header, and most providers authenticate with a name outside that set.
 *
 * So "reveal at the wire" is incomplete, because the wire is not a point. It is
 * a sequence of hosts chosen partly by the server.
 */

/** Loopback destinations, where plaintext is a sidecar rather than a mistake. */
const LOOPBACK = new Set(['localhost', '127.0.0.1', '::1', '[::1]', '0.0.0.0']);

export function isLoopback(hostname: string): boolean {
  const bare = hostname.replace(/^\[|\]$/g, '');

  return LOOPBACK.has(hostname) || LOOPBACK.has(bare) || bare.startsWith('127.');
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
 * default the moment a credential sits in a header the platform will not strip.
 * An explicit `allowedHosts` array always wins, because naming the hosts is the
 * caller saying they have thought about it.
 */
export function resolveRedirectPolicy(
  configured: readonly string[] | false | undefined,
  hasUnstrippedCredential: boolean
): readonly string[] | false | 'client' {
  if (configured !== undefined) {
    return configured;
  }

  // No configuration and every credential is in a header the platform strips:
  // leave the client's own redirect handling alone. Re-implementing stripping
  // would be worse than trusting three independent implementations that agree.
  return hasUnstrippedCredential ? false : 'client';
}

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
  policy: readonly string[] | false,
  budget: number
): void {
  if (hop > budget) {
    throw new TooManyRedirectsError(budget);
  }

  if (policy === false) {
    throw new RedirectHostNotAllowedError(next.host, false, hop);
  }

  if (!hostAllowed(next, policy)) {
    throw new RedirectHostNotAllowedError(next.host, policy, hop);
  }
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
