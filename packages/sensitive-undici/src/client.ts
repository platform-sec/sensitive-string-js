import { request as undiciRequest } from 'undici';
import type { Dispatcher } from 'undici';

import {
  assertBodyMayFollow,
  assertHopAllowed,
  headersWithout,
  isCrossOrigin,
  decodeJson,
  isRedirect,
  prepareRequest,
  redirectMethod,
  safeUrl,
  wrapResponseFields,
} from '@platform-sec/sensitive-string-http';
import type {
  SensitiveClientOptions,
  SensitiveHeaders,
  SensitiveQuery,
} from '@platform-sec/sensitive-string-http';

import { scrubError } from './scrub.js';

/**
 * The smallest package in the row, because undici already fails closed.
 *
 * Measured, `undici.request` is the only client in the set that rejects a
 * `SensitiveString` rather than stringifying it: `InvalidArgumentError: invalid
 * x-secret header` for a header, and a matching refusal for a body. An
 * application on the dispatcher API therefore finds the problem at the first
 * request in development rather than at the first 401 in production. That
 * behaviour is the rule the other four packages had to be built to reproduce.
 *
 * What this package adds on top of it:
 *
 * - The reveal, the guard and the context, so a caller gets a working request
 *   and an audit trail rather than an `InvalidArgumentError`.
 * - The redirect host policy, which undici does not have because it does not
 *   follow redirects by default.
 * - A dispatcher interceptor for callers who use the dispatcher directly. It
 *   cannot reveal, because by then the caller has already had to produce
 *   strings, but it can refuse to send a marker.
 */

export interface SensitiveUndiciRequestOptions extends Omit<
  Dispatcher.RequestOptions,
  'headers' | 'query' | 'body' | 'path' | 'origin' | 'method'
> {
  method?: Dispatcher.HttpMethod;
  /** May hold `SensitiveString` instances and the auth helpers' descriptors. */
  headers?: SensitiveHeaders;
  /** May hold instances. Merged into the URL after revealing. */
  query?: SensitiveQuery;
  /** A structured body to reveal and serialize as JSON. */
  json?: unknown;
  /** An `application/x-www-form-urlencoded` body the wrapper builds after revealing. */
  form?: SensitiveQuery;
  /** An already-serialized body. Scanned for markers, never rebuilt. */
  body?: string | Uint8Array | undefined;
}

export interface SensitiveUndiciOptions extends SensitiveClientOptions {
  /** The dispatcher to send through. Defaults to undici's global one. */
  dispatcher?: Dispatcher;
}

export interface SensitiveUndiciResponse<T> {
  readonly statusCode: number;
  readonly headers: Record<string, string | string[] | undefined>;
  readonly body: Dispatcher.ResponseData['body'];
  /**
   * The parsed body, through the shared decoder and the response wrapping.
   *
   * A body that is not JSON becomes a `ResponseDecodeError` naming the request
   * rather than a `SyntaxError` quoting what was probably the credential.
   */
  json(): Promise<T>;
}

export async function sensitiveRequest<T = unknown>(
  url: string,
  options: SensitiveUndiciRequestOptions & SensitiveUndiciOptions = {}
): Promise<SensitiveUndiciResponse<T>> {
  let currentUrl = new URL(url).toString();
  let currentMethod = (options.method ?? 'GET').toUpperCase();
  let body = options.json;
  let form = options.form;
  let hop = 0;
  // Names dropped by `'strip'` so far, accumulated rather than recomputed: a
  // credential removed at hop two stays removed at hop three, and a name taken
  // out of the caller's headers cannot be refilled by anything merged in later.
  let dropped: readonly string[] = [];
  const budget = options.maxRedirects ?? 5;

  for (;;) {
    const prepared = prepareRequest(
      {
        method: currentMethod,
        url: currentUrl,
        headers: headersWithout(options.headers, dropped),
        // Merged on the first hop only; `prepareRequest` drops it for the
        // hops that follow.
        query: options.query,
        body,
        form,
        rawBody: options.body,
      },
      { ...options, client: 'undici', attempt: 1, hop: hop + 1 }
    );

    const headers: Record<string, string> = { ...prepared.headers };
    let outBody = options.body;

    if (prepared.formText !== undefined) {
      headers['content-type'] = headers['content-type'] ?? 'application/x-www-form-urlencoded';
      outBody = prepared.formText;
    } else if (prepared.bodyText !== undefined) {
      headers['content-type'] = headers['content-type'] ?? 'application/json';
      outBody = prepared.bodyText;
    }

    let response: Dispatcher.ResponseData;

    try {
      response = await undiciRequest(prepared.url, {
        ...requestRest(options),
        method: currentMethod,
        headers,
        ...(outBody === undefined ? {} : { body: outBody }),
      });
    } catch (error) {
      throw scrubError(error, prepared.plan, prepared.url);
    }

    if (prepared.redirects === 'client' || !isRedirect(response.statusCode)) {
      return decorate<T>(response, prepared.method, prepared.url, options);
    }

    const location = response.headers['location'];
    const target = Array.isArray(location) ? location[0] : location;

    if (target === undefined || target === '') {
      return decorate<T>(response, prepared.method, prepared.url, options);
    }

    hop += 1;

    // Before the next request is built. The response body of the hop is drained
    // first, because undici keeps the connection until it is.
    await response.body.dump();

    const next = new URL(target, currentUrl);

    assertHopAllowed(next, hop, prepared.redirects, budget);

    const rewritten = redirectMethod(response.statusCode, currentMethod);

    if (prepared.redirects === 'strip' && isCrossOrigin(new URL(prepared.url), next)) {
      // A 307 or 308 re-sends the body, and a body carrying a wrapped value
      // cannot be stripped the way a header can. Refused rather than
      // forwarded, before anything is revealed for the next hop.
      if (rewritten.keepBody) {
        assertBodyMayFollow(next, hop, prepared);
      }

      dropped = [...dropped, ...prepared.plan.headers];
    }

    currentUrl = next.toString();
    currentMethod = rewritten.method;

    if (!rewritten.keepBody) {
      body = undefined;
      form = undefined;
    }
  }
}

function requestRest(
  options: SensitiveUndiciRequestOptions & SensitiveUndiciOptions
): Record<string, unknown> {
  const {
    headers: _headers,
    query: _query,
    json: _json,
    form: _form,
    body: _body,
    method: _method,
    context: _context,
    reason: _reason,
    allowedHosts: _allowedHosts,
    allowInsecureTransport: _allowInsecureTransport,
    maxRedirects: _maxRedirects,
    responseFields: _responseFields,
    scanBase64: _scanBase64,
    log: _log,
    retries: _retries,
    ...rest
  } = options;

  return rest;
}

function decorate<T>(
  response: Dispatcher.ResponseData,
  method: string,
  url: string,
  options: SensitiveUndiciOptions
): SensitiveUndiciResponse<T> {
  return {
    statusCode: response.statusCode,
    headers: response.headers,
    body: response.body,
    json: async () => {
      const text = await response.body.text();

      return wrapResponseFields(
        decodeJson(text, {
          method,
          url: safeUrl(url),
          contentType: headerValue(response.headers['content-type']),
        }),
        options.responseFields
      ) as T;
    },
  };
}

function headerValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}
