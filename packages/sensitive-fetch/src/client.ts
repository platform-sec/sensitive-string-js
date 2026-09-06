import {
  SensitiveHttpError,
  assertHopAllowed,
  headersWithout,
  isCrossOrigin,
  decodeJson,
  isRedirect,
  prepareRequest,
  redirectMethod,
  revealHeaders,
  safeUrl,
  wrapResponseFields,
} from '@platform-sec/sensitive-string-http';
import type {
  PreparedRequest,
  SensitiveClientOptions,
  SensitiveHeaders,
  SensitiveQuery,
} from '@platform-sec/sensitive-string-http';
import type { RevealContext } from '@platform-sec/sensitive-string-core';

import { scrubError } from './scrub.js';

/**
 * `fetch`, with the reveal in one place.
 *
 * Covers Node 22's global `fetch` and `undici.fetch`. They share an
 * implementation and measured identically on every row this design ran against
 * both, so they share a package rather than getting one each.
 *
 * `fetch` has no hook of any kind, which makes it the clearest case for the
 * shape all five packages take: the wrapper owns the call because there is
 * nowhere else to stand.
 */

export interface SensitiveFetchInit extends Omit<RequestInit, 'headers' | 'body' | 'redirect'> {
  /** May hold `SensitiveString` instances and the auth helpers' descriptors. */
  headers?: SensitiveHeaders;
  /** May hold instances. Merged into the URL after revealing. */
  searchParams?: SensitiveQuery;
  /**
   * A structured body to reveal and serialize as JSON.
   *
   * Deliberately not `body`. A `RequestInit`'s `body` is already a serialized
   * thing by the time `fetch` receives it, and accepting a structured value
   * there would mean silently ignoring a `Content-Type` the caller set. A
   * separate option makes the reveal-and-serialize path explicit and leaves
   * `body` meaning what it means everywhere else.
   */
  sensitiveJson?: unknown;
  /** An `application/x-www-form-urlencoded` body the wrapper builds after revealing. */
  form?: SensitiveQuery;
  /** An already-serialized body. Scanned for markers, never rebuilt. */
  body?: string | Uint8Array | undefined;
}

export type SensitiveFetchOptions = SensitiveClientOptions;

export interface SensitiveFetchResult<T> extends Promise<Response> {
  json(): Promise<T>;
  text(): Promise<string>;
  arrayBuffer(): Promise<ArrayBuffer>;
}

/**
 * One request, with the reveal, the guard, the host policy and the decoder.
 *
 * Resolves to the platform `Response`, unchanged: a `Response` carries no
 * request headers, measured, so there is nothing on the success path to scrub.
 * `json()` hangs off the returned promise the way ky's does, and routes through
 * the shared decoder so a body that is not JSON becomes a
 * `ResponseDecodeError` naming the request rather than a `SyntaxError` quoting
 * what was probably the credential.
 */
export function sensitiveFetch<T = unknown>(
  url: string,
  init: SensitiveFetchInit & SensitiveFetchOptions = {}
): SensitiveFetchResult<T> {
  const settle = (async () => {
    let currentUrl = new URL(url).toString();
    let currentMethod = (init.method ?? 'GET').toUpperCase();
    let body = init.sensitiveJson;
    let form = init.form;
    let hop = 0;
    // Names dropped by `'strip'` so far, accumulated rather than recomputed: a
    // credential removed at hop two stays removed at hop three, and a name taken
    // out of the caller's headers cannot be refilled by anything merged in later.
    let dropped: readonly string[] = [];
    const budget = init.maxRedirects ?? 5;

    for (;;) {
      const prepared = prepareRequest(
        {
          method: currentMethod,
          url: currentUrl,
          headers: headersWithout(init.headers, dropped),
          query: init.searchParams,
          body,
          form,
          rawBody: init.body,
        },
        { ...init, client: 'fetch', attempt: 1, hop: hop + 1 }
      );

      const manual = prepared.redirects !== 'client';

      let response: Response;

      try {
        response = await fetch(prepared.url, outgoing(prepared, init, manual));
      } catch (error) {
        throw scrubError(error, prepared.plan, prepared.url);
      }

      if (!manual || !isRedirect(response.status)) {
        return { response, prepared };
      }

      const location = response.headers.get('location');

      if (location === null || location === '') {
        return { response, prepared };
      }

      hop += 1;

      await discardBody(response);

      // Before the next request is built, so nothing is revealed for a host the
      // caller never named.
      assertHopAllowed(new URL(location, currentUrl), hop, prepared.redirects, budget);

      if (
        prepared.redirects === 'strip' &&
        isCrossOrigin(new URL(prepared.url), new URL(location, currentUrl))
      ) {
        dropped = [...dropped, ...prepared.plan.headers];
      }

      const rewritten = redirectMethod(response.status, currentMethod);

      currentUrl = new URL(location, currentUrl).toString();
      currentMethod = rewritten.method;

      if (!rewritten.keepBody) {
        body = undefined;
        form = undefined;
      }
    }
  })();

  const promise = settle.then(({ response }) => response) as SensitiveFetchResult<T>;

  promise.json = async () => {
    const { response, prepared } = await settle;
    const text = await response.text();

    return wrapResponseFields(
      decodeJson(text, {
        method: prepared.method,
        url: safeUrl(prepared.url),
        contentType: response.headers.get('content-type') ?? undefined,
      }),
      init.responseFields
    ) as T;
  };

  promise.text = async () => (await settle).response.text();
  promise.arrayBuffer = async () => (await settle).response.arrayBuffer();

  return promise;
}

function outgoing(
  prepared: PreparedRequest,
  init: SensitiveFetchInit & SensitiveFetchOptions,
  manual: boolean
): RequestInit {
  // This package's own options share one object with `RequestInit`, which is
  // what makes the call site read well. They are stripped here rather than
  // handed to `fetch`, which would otherwise be given the caller's `log`
  // callback and `responseFields` object to ignore.
  const {
    headers: _headers,
    searchParams: _searchParams,
    sensitiveJson: _json,
    form: _form,
    body: rawBody,
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
  } = init;

  const headers: Record<string, string> = { ...prepared.headers };
  // `BodyInit` is a DOM lib type this repository does not include; the three
  // shapes this package produces are named directly instead.
  let outBody: string | Uint8Array | undefined = rawBody;

  if (prepared.formText !== undefined) {
    headers['content-type'] = headers['content-type'] ?? 'application/x-www-form-urlencoded';
    outBody = prepared.formText;
  } else if (prepared.bodyText !== undefined) {
    headers['content-type'] = headers['content-type'] ?? 'application/json';
    outBody = prepared.bodyText;
  }

  const out: Record<string, unknown> = {
    ...(rest as Record<string, unknown>),
    method: prepared.method,
    headers,
  };

  // Assigned rather than spread, because `exactOptionalPropertyTypes` treats a
  // present key holding `undefined` as a different thing from an absent one,
  // and `fetch` agrees: `{ body: undefined }` on a GET is an error.
  if (outBody !== undefined) {
    out['body'] = outBody;
  }

  if (manual) {
    out['redirect'] = 'manual';
  }

  return out;
}

/**
 * Build a `Headers` from a record that may hold instances and auth helpers.
 *
 * ⚠️ The result holds plaintext. Do not store it, do not log it, and do not
 * reuse it across requests: everything else in this package exists so that a
 * revealed value has one owner for the length of one call, and this hands the
 * ownership to the caller.
 *
 * It exists because a caller who is not going to stop using `fetch` directly is
 * better served by a helper that reveals and guards than by interpolation that
 * does neither. Whether it should exist at all is an open question in the
 * design; it is in, with this warning.
 */
export function sensitiveHeaders(record: SensitiveHeaders, context?: RevealContext): Headers {
  const ctx: RevealContext = context ?? { name: 'sensitiveHeaders', tags: { sink: 'http' } };

  // The plan is discarded, because there is no settlement path to scrub: the
  // caller is about to make the request themselves. That is the trade this
  // helper makes, and the reason its first line is a warning.
  const rendered = revealHeaders(record, ctx, { record: () => undefined }, { base64: false });

  return new Headers(rendered);
}

export { SensitiveHttpError };

/**
 * Release the connection a hop's unread body is holding.
 *
 * An unread `fetch` body keeps its socket open until the response is collected,
 * so a redirect chain would leak one per hop. The guards are not defensive
 * padding: ky surfaces a 3xx as an `HTTPError` whose body it has already read,
 * and cancelling a locked stream throws `Invalid state: ReadableStream is
 * locked`, which would turn a redirect refusal into a `TypeError`.
 */
async function discardBody(response: Response): Promise<void> {
  if (response.bodyUsed || response.body === null || response.body.locked) {
    return;
  }

  try {
    await response.body.cancel();
  } catch {
    // Another consumer got there first. The socket is theirs to release.
  }
}
