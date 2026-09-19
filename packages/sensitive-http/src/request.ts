import { Readable } from 'node:stream';

import { redactCopy } from '@platform-sec/sensitive-string-core';
import type { RevealContext, SensitivityClass } from '@platform-sec/sensitive-string-core';

import { isAuthHeader, isStrippedAcrossOrigins } from './auth.js';
import { buildAttemptContext } from './context.js';
import { assertNoMarker } from './marker.js';
import { isSensitive, revealForm, revealHeaders, revealOutgoing, revealQuery } from './reveal.js';
import { assertTransport, resolveRedirectPolicy, type ResolvedRedirectPolicy } from './redirect.js';
import { PlanBuilder } from './scrub.js';
import type { ScrubPlan } from './scrub.js';
import type { OutgoingRequest, RequestDescriptor, SensitiveClientOptions } from './types.js';

/**
 * Steps 1 to 5 of the pipeline, shared by all five client packages.
 *
 * The order is fixed and is the design, not an implementation detail:
 *
 * 1. Build the reveal context for this attempt.
 * 2. Check the URL scheme and settle the redirect policy, **before** anything
 *    is revealed, so a request to a host the caller never named never reveals
 *    at all rather than revealing and then declining to send.
 * 3. Log a redacted copy, if the caller asked for one. Also before the reveal.
 * 4. Reveal headers, query and body into a fresh structure, recording the plan.
 * 5. Run the marker guard over each outgoing representation.
 *
 * Steps 6 to 8, handing the structure to the client and scrubbing both
 * settlement paths, are the client package's, because only it knows where its
 * client keeps things.
 */

export interface PreparedRequest {
  readonly method: string;
  /** Absolute URL with the revealed query merged in. */
  readonly url: string;
  readonly headers: Record<string, string>;
  /** The revealed body structure, for a client that serializes it itself. */
  readonly body: unknown;
  /** The revealed body as JSON text, when there was a structured body. */
  readonly bodyText: string | undefined;
  /** The revealed form body as `application/x-www-form-urlencoded` text. */
  readonly formText: string | undefined;
  readonly plan: ScrubPlan;
  /**
   * Whether the structured or form body carried a wrapped value. What a
   * wrapper following a 307 or 308 under `'strip'` has to know before it
   * re-sends the body to another origin; see `assertBodyMayFollow`.
   */
  readonly bodyCarriesCredential: boolean;
  readonly context: RevealContext;
  /**
   * `'client'` means the client's own redirect handling is left alone, which is
   * only chosen when this client already strips every credential the request
   * carries. `'strip'` means the wrapper follows the hops itself and removes
   * the credential headers when one leaves the origin.
   */
  readonly redirects: ResolvedRedirectPolicy;
  readonly descriptor: RequestDescriptor;
}

/** Does anything reachable from these hold a `credential`? Asked before revealing. */
function carriesCredential(request: OutgoingRequest): boolean {
  return (
    classesIn(request.headers).has('credential') ||
    classesIn(request.query).has('credential') ||
    classesIn(request.form).has('credential') ||
    classesIn(request.body).has('credential')
  );
}

function classesIn(
  value: unknown,
  found = new Set<SensitivityClass>(),
  seen = new WeakSet<object>()
): Set<SensitivityClass> {
  if (value === null || typeof value !== 'object') {
    return found;
  }

  if (isSensitive(value)) {
    found.add(value.klass);

    return found;
  }

  if (seen.has(value)) {
    return found;
  }

  seen.add(value);

  if (isAuthHeader(value)) {
    for (const part of value.parts) {
      classesIn(part, found, seen);
    }

    return found;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      classesIn(item, found, seen);
    }

    return found;
  }

  if (value instanceof Date || value instanceof Readable || ArrayBuffer.isView(value)) {
    return found;
  }

  let keys: string[];

  try {
    keys = Object.keys(value);
  } catch {
    return found;
  }

  for (const key of keys) {
    try {
      classesIn((value as Record<string, unknown>)[key], found, seen);
    } catch {
      // An unreadable getter names no class. The walker skips it too.
    }
  }

  return found;
}

/**
 * Header names that carry a wrapped value this client will not strip across origins.
 *
 * This is what flips the redirect default to `false`. `Authorization`,
 * `Cookie` and `Proxy-Authorization` are covered by every client measured;
 * `x-api-key` and its cousins are covered by nobody. Which client is asking
 * decides it, because the exemption is a statement about an implementation
 * that was checked rather than about the header, and a client nobody has
 * measured is exempt from nothing.
 *
 * Any sensitivity class counts, not only `credential`. A caller who wrapped a
 * value and put it in a custom header meant it not to travel, and the question
 * here is where it is allowed to go rather than how bad it would be to lose it.
 */
function hasUnstrippedCredential(request: OutgoingRequest, client: string): boolean {
  for (const [name, value] of Object.entries(request.headers ?? {})) {
    if (isStrippedAcrossOrigins(name, client)) {
      continue;
    }

    if (classesIn(value).size > 0) {
      return true;
    }
  }

  // A credential in the query string travels with the URL, and a redirect
  // carries the URL the server names, so this is not the same risk. It is left
  // to the client, and the guard still covers the marker case.
  return false;
}

export interface PrepareOptions extends SensitiveClientOptions {
  /** Which client package is preparing, for `tags.client` and for scrub errors. */
  readonly client: string;
  /** 1 for the first send, incremented per retry. */
  readonly attempt: number;
  /** 1 for the caller's own request, incremented per redirect hop. Defaults to 1. */
  readonly hop?: number;
}

/**
 * The proxy's `host[:port]`, in the form a destination binding is written in.
 *
 * A bare `host:port` is read by prefixing a scheme, so a client that only
 * knows the proxy's host and port need not invent one; the scheme is not
 * part of what the binding compares.
 *
 * @throws TypeError If the value is not a URL or a host.
 */
function proxyHost(proxy: string | URL | undefined): string | undefined {
  if (proxy === undefined) {
    return undefined;
  }

  const spelled = proxy instanceof URL ? proxy.href : proxy;

  try {
    const parsed = new URL(spelled.includes('://') ? spelled : `http://${spelled}`);

    if (parsed.host === '') {
      throw new Error('no host');
    }

    return parsed.host;
  } catch {
    throw new TypeError(
      `prepareRequest: proxy must be a URL or a host[:port]; the value given could not be parsed as either`
    );
  }
}

/** Steps 1 to 5. Throws before revealing anything when a check fails. */
export function prepareRequest(
  incoming: OutgoingRequest,
  options: PrepareOptions
): PreparedRequest {
  // A redirect target is the URL the server named and nothing else. The
  // caller's query belongs to the request they made, so it is merged on the
  // first hop only. Re-applying it on every hop carried a wrapped query
  // credential to a cross-origin target under `'strip'`, which had just removed
  // the same credential from the headers: the query gap the corpus recorded
  // against GHSA-p2f4-r6v6-j797 and withdrew on reasoning that held only for
  // the delegated mode. Dropped here rather than in each wrapper, so a wrapper
  // cannot forget.
  const request: OutgoingRequest =
    (options.hop ?? 1) > 1 && incoming.query !== undefined
      ? { ...incoming, query: undefined }
      : incoming;

  const url = new URL(request.url);
  const method = request.method.toUpperCase();

  const proxy = proxyHost(request.proxy);

  const descriptor: RequestDescriptor = {
    method,
    url: `${url.protocol}//${url.host}${url.pathname}`,
    host: url.host,
    ...(proxy === undefined ? {} : { proxy }),
    attempt: options.attempt,
    hop: options.hop ?? 1,
  };

  // Step 2, before step 1's reveal and before anything else touches a value.
  assertTransport(url, carriesCredential(request), options.allowInsecureTransport === true);

  const redirects = resolveRedirectPolicy(
    options.allowedHosts,
    hasUnstrippedCredential(request, options.client)
  );

  // Step 3. `redactCopy` holds no revealed value and replaces a `serialize()`
  // result with the marker of the class it names, so a wire-format payload the
  // caller put in the body reaches the socket and no log line.
  if (options.log !== undefined) {
    options.log(
      redactCopy({
        method,
        url: descriptor.url,
        headers: request.headers,
        query: request.query,
        form: request.form,
        body: request.body,
      })
    );
  }

  // Step 1's product, used by step 4.
  const context = buildAttemptContext(descriptor, options.client, options.context, options.reason);

  const builder = new PlanBuilder();
  const scanOptions = { base64: options.scanBase64 === true };

  const headers = revealHeaders(request.headers, context, builder.section('header'), scanOptions);
  const query = revealQuery(request.query, context, builder.section('query'), scanOptions);

  // Form fields share the plan's `query` section with the query string, since
  // both are scrubbed the same way, so whether the *form* carried a wrapped
  // value is noted here on the way past rather than read back from the plan.
  const formRecorder = builder.section('query');
  let formCarriesCredential = false;
  const formText = revealForm(
    request.form,
    context,
    {
      record: (position, value) => {
        formCarriesCredential = true;
        formRecorder.record(position, value);
      },
    },
    scanOptions
  );

  let body: unknown;
  let bodyText: string | undefined;

  if (request.body !== undefined) {
    body = revealOutgoing(request.body, context, builder.section('body'));
    bodyText = JSON.stringify(body) ?? '';
    assertNoMarker(bodyText, 'request body', scanOptions);
    scanPassThrough(body, 'request body', scanOptions);
  }

  if (request.rawBody !== undefined) {
    const text =
      typeof request.rawBody === 'string'
        ? request.rawBody
        : Buffer.from(request.rawBody).toString('utf8');

    assertNoMarker(text, 'request body', scanOptions);
  }

  // Deleted once per key, then appended, rather than `set` per pair. `set`
  // replaces every existing value for the key, so `{ tag: ['a', 'b', 'c'] }`
  // reached the wire as `tag=c` alone: the wrapper silently dropped two thirds
  // of the caller's query.
  for (const key of new Set(query.map(([name]) => name))) {
    url.searchParams.delete(key);
  }

  for (const [key, value] of query) {
    url.searchParams.append(key, value);
  }

  assertNoMarker(url.search, 'query string', scanOptions);

  const plan = builder.build();

  return {
    method,
    url: url.toString(),
    headers,
    body,
    bodyText,
    formText,
    plan,
    bodyCarriesCredential: plan.bodyPaths.length > 0 || formCarriesCredential,
    context,
    redirects,
    descriptor,
  };
}

/**
 * Scan the containers the walker had to pass through.
 *
 * `Headers`, `URLSearchParams`, `FormData` and `Request` stringify on
 * construction, so an instance the caller put into one became a marker before
 * the walker ever saw it. There is no instance left to detect: the marker is
 * the only evidence, and refusing on it is the whole reason these are scanned
 * rather than trusted.
 */
export function scanPassThrough(
  value: unknown,
  where: string,
  scanOptions: { base64: boolean },
  seen: WeakSet<object> = new WeakSet()
): void {
  if (value === null || typeof value !== 'object' || seen.has(value)) {
    return;
  }

  seen.add(value);

  if (value instanceof URLSearchParams) {
    assertNoMarker(value.toString(), where, scanOptions);

    return;
  }

  if (typeof Headers === 'function' && value instanceof Headers) {
    for (const [name, header] of value) {
      assertNoMarker(header, `${where}, header '${name}'`, scanOptions);
    }

    return;
  }

  if (typeof FormData === 'function' && value instanceof FormData) {
    for (const [name, entry] of value) {
      if (typeof entry === 'string') {
        assertNoMarker(entry, `${where}, form field '${name}'`, scanOptions);
      }
    }

    return;
  }

  if (ArrayBuffer.isView(value)) {
    assertNoMarker(
      Buffer.from(value.buffer, value.byteOffset, value.byteLength).toString('utf8'),
      where,
      {
        ...scanOptions,
        decodeForms: false,
      }
    );

    return;
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => {
      scanPassThrough(item, `${where}[${index}]`, scanOptions, seen);
    });

    return;
  }

  for (const [key, item] of Object.entries(value)) {
    scanPassThrough(item, `${where}.${key}`, scanOptions, seen);
  }
}
