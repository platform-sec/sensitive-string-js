import {
  RedirectHostNotAllowedError,
  SensitiveHttpError,
  assertBodyMayFollow,
  decodeJson,
  headersWithout,
  hostAllowed,
  isCrossOrigin,
  prepareRequest,
  safeUrl,
  wrapResponseFields,
} from '@platform-sec/sensitive-string-http';
import type {
  PreparedRequest,
  SensitiveClientOptions,
  SensitiveHeaderValue,
  SensitiveHeaders,
  SensitiveQuery,
} from '@platform-sec/sensitive-string-http';
import type { Got, Response, StrictOptions } from 'got';

import { scrubError, scrubResponse } from './scrub.js';

/**
 * got is the one client where a hook could have revealed the header correctly.
 *
 * Its `beforeRequest` runs before headers are stringified and after the body is
 * serialized, which is the exact mirror image of axios. The package still
 * reveals before the call, so the guarantee is the same sentence for all five,
 * and because the measured damage is after the send anyway, where no hook runs.
 * The caller's own `beforeRequest` is left untouched.
 *
 * Two got features the wrapper does take over, and says so in the README:
 *
 * - `retry.limit` goes to 0 and retries are driven here, so a retried request
 *   reveals and audits once per attempt. The audit count then matches the
 *   number of times the value crossed a socket, which is the number an operator
 *   needs. The cost is got's retry-after handling, which is a real loss.
 * - `hooks.beforeRedirect` carries the host check. got exposes it and its
 *   redirect handling has semantics worth keeping (method rewriting on 303,
 *   body dropping), so the wrapper does not run its own hop loop here the way
 *   the axios package must.
 */

export interface SensitiveGotRequestConfig extends Omit<
  StrictOptions,
  'headers' | 'searchParams' | 'json' | 'form' | 'url' | 'body'
> {
  /** May hold `SensitiveString` instances and the auth helpers' descriptors. */
  headers?: SensitiveHeaders;
  /** May hold instances. Revealed into primitives, which is what got's own validator demands. */
  searchParams?: SensitiveQuery;
  /** A structured JSON body to reveal and serialize. */
  json?: unknown;
  /** An `application/x-www-form-urlencoded` body the wrapper builds after revealing. */
  form?: SensitiveQuery;
}

export type SensitiveGotOptions = SensitiveClientOptions;

export type SensitiveGotResponse<T> = Omit<Response, 'body'> & { body: T };

export interface SensitiveGot {
  request<T = unknown>(
    url: string,
    config?: SensitiveGotRequestConfig
  ): Promise<SensitiveGotResponse<T>>;
  get<T = unknown>(
    url: string,
    config?: SensitiveGotRequestConfig
  ): Promise<SensitiveGotResponse<T>>;
  delete<T = unknown>(
    url: string,
    config?: SensitiveGotRequestConfig
  ): Promise<SensitiveGotResponse<T>>;
  head<T = unknown>(
    url: string,
    config?: SensitiveGotRequestConfig
  ): Promise<SensitiveGotResponse<T>>;
  post<T = unknown>(
    url: string,
    body?: unknown,
    config?: SensitiveGotRequestConfig
  ): Promise<SensitiveGotResponse<T>>;
  put<T = unknown>(
    url: string,
    body?: unknown,
    config?: SensitiveGotRequestConfig
  ): Promise<SensitiveGotResponse<T>>;
  patch<T = unknown>(
    url: string,
    body?: unknown,
    config?: SensitiveGotRequestConfig
  ): Promise<SensitiveGotResponse<T>>;
  /** The instance the caller handed over, for the features this surface does not expose. */
  readonly client: Got;
}

function resolveUrl(client: Got, url: string): string {
  try {
    return new URL(url).toString();
  } catch {
    const prefix = String(client.defaults.options.prefixUrl ?? '');

    if (prefix === '') {
      throw new TypeError(
        `Cannot resolve '${url}' to an absolute URL: the got instance has no prefixUrl. ` +
          `The wrapper needs the destination host before it reveals anything, because the ` +
          `transport and redirect checks run first.`
      );
    }

    return new URL(url.replace(/^\//, ''), prefix.endsWith('/') ? prefix : `${prefix}/`).toString();
  }
}

/**
 * Default headers merged in, so an instance-level credential is revealed too.
 *
 * `got.extend({ headers })` is the ordinary way to give an instance a
 * credential, and got merges those under the call's headers at send time.
 * Measured: a wrapped value placed there reached the wire as
 * `[REDACTED:credential]` and an `apiKey()` descriptor as `[object Object]`,
 * because the wrapper only ever saw the call's own headers. Merged here so an
 * instance default is revealed, recorded in the plan, scrubbed on the way back
 * and, under `'strip'`, dropped at the origin boundary like any other.
 *
 * got stores its defaults with lowercased names; a value got itself put there,
 * such as its `user-agent`, is a plain string and passes through unchanged.
 */
function withDefaultHeaders(client: Got, headers: SensitiveHeaders | undefined): SensitiveHeaders {
  const defaults = (client.defaults.options.headers ?? {}) as Readonly<Record<string, unknown>>;
  const merged: SensitiveHeaders = {};

  for (const [name, value] of Object.entries(defaults)) {
    if (value === undefined) {
      continue;
    }

    merged[name] = (Array.isArray(value) ? value.join(', ') : value) as SensitiveHeaderValue;
  }

  return { ...merged, ...(headers ?? {}) };
}

/** Whether got will send a body again on this hop: true after a 307 or 308, never after a 303. */
function resendsBody(redirectOptions: { json?: unknown; body?: unknown; form?: unknown }): boolean {
  return (
    redirectOptions.json !== undefined ||
    redirectOptions.body !== undefined ||
    redirectOptions.form !== undefined
  );
}

/**
 * got wraps anything a hook throws in a `RequestError` and hangs the original
 * off `cause`. A refusal from this package has to arrive as itself.
 */
function unwrap(error: unknown): unknown {
  const cause = (error as { cause?: unknown } | null)?.cause;

  return cause instanceof SensitiveHttpError ? cause : error;
}

export function createSensitiveGot(client: Got, options: SensitiveGotOptions = {}): SensitiveGot {
  async function attempt<T>(
    url: string,
    config: SensitiveGotRequestConfig,
    attemptNumber: number
  ): Promise<SensitiveGotResponse<T>> {
    const prepared = prepareRequest(
      {
        method: String(config['method'] ?? 'GET'),
        url,
        headers: withDefaultHeaders(client, config.headers),
        query: config.searchParams,
        body: config.json,
        form: config.form,
      },
      // Always 1: got follows redirects itself, so the wrapper only ever
      // prepares the caller's own request. The host check rides on
      // `beforeRedirect` instead, which is why this package has no hop loop.
      { ...options, client: 'got', attempt: attemptNumber, hop: 1 }
    );

    try {
      const call = client as unknown as (url: string, opts: unknown) => Promise<Response>;
      const response = await call(prepared.url, outgoing(prepared, config, options));

      return finish<T>(scrubResponse(response, prepared.plan), options);
    } catch (error) {
      throw scrubError(unwrap(error), prepared.plan, prepared.url);
    }
  }

  async function send<T>(
    url: string,
    config: SensitiveGotRequestConfig = {}
  ): Promise<SensitiveGotResponse<T>> {
    const resolved = resolveUrl(client, url);
    const budget = options.retries ?? 0;

    for (let attemptNumber = 1; ; attemptNumber += 1) {
      try {
        return await attempt<T>(resolved, config, attemptNumber);
      } catch (error) {
        // A refusal from this package is not something a retry can fix, and
        // retrying it would reveal again for no reason.
        if (error instanceof SensitiveHttpError || attemptNumber > budget) {
          throw error;
        }
      }
    }
  }

  function finish<T>(response: Response, opts: SensitiveGotOptions): SensitiveGotResponse<T> {
    if (opts.responseFields !== undefined) {
      response.body = wrapResponseFields(response.body, opts.responseFields);
    }

    return response as SensitiveGotResponse<T>;
  }

  function outgoing(
    prepared: PreparedRequest,
    config: SensitiveGotRequestConfig,
    opts: SensitiveGotOptions
  ): StrictOptions & Record<string, unknown> {
    const {
      headers: _headers,
      searchParams: _searchParams,
      json: _json,
      form: _form,
      ...rest
    } = config;

    const out = {
      ...rest,
      prefixUrl: '',
      method: prepared.method,
      headers: prepared.headers,
      // The wrapper drives retries, so each attempt reveals and audits once.
      retry: { limit: 0 },
      parseJson: (text: string) =>
        wrapResponseFields(
          decodeJson(text, {
            method: prepared.method,
            url: safeUrl(prepared.url),
            contentType: undefined,
          }),
          opts.responseFields
        ),
    } as unknown as StrictOptions & Record<string, unknown>;

    if (opts.responseFields !== undefined) {
      out['responseType'] = 'json';
    }

    if (prepared.formText !== undefined) {
      out['body'] = prepared.formText;
      out['headers'] = {
        'content-type': 'application/x-www-form-urlencoded',
        ...prepared.headers,
      };
    } else if (prepared.body !== undefined) {
      out['json'] = prepared.body;
    }

    if (prepared.redirects !== 'client') {
      const policy = prepared.redirects;
      const revealed = prepared.plan.headers;
      // The previous hop, advanced on every call, not the request's original
      // URL. Same-origin is not transitive once `isCrossOrigin` allows the
      // http-to-https upgrade: A `http://x` to B `https://x` is an upgrade, B
      // to C `http://x` is a downgrade, and C is same-origin with A. Comparing
      // every hop against A would call that last one same-origin and forward
      // the credential into plaintext. got is the only wrapper that needs this
      // tracked by hand, because the other four rebuild the request each hop
      // and already hold the previous URL.
      let from = new URL(prepared.url);
      // Counted here because got's hook is not told which hop it is on. The
      // first redirect is hop 1, as in the wrappers that drive the loop.
      let hop = 0;

      out['hooks'] = {
        ...((rest as { hooks?: Record<string, unknown> }).hooks ?? {}),
        beforeRedirect: [
          (redirectOptions: {
            url: URL | undefined;
            headers?: Record<string, unknown>;
            json?: unknown;
            body?: unknown;
            form?: unknown;
          }) => {
            const next = redirectOptions.url;

            if (next === undefined) {
              return;
            }

            hop += 1;

            // got is the one client that follows hops itself while still
            // handing the next request's options over for editing, so `'strip'`
            // is a deletion here rather than a rebuilt request. The other
            // wrappers drive the loop and rebuild.
            if (policy === 'strip') {
              if (isCrossOrigin(from, next)) {
                // got keeps the body across a 307 or 308 and hands it over
                // here as `json`, `body` or `form`; after a 303 it has already
                // dropped it. A body carrying a wrapped value cannot be
                // stripped the way a header can, so the hop is refused. got
                // wraps the throw in a RequestError and the wrapper unwraps it.
                if (resendsBody(redirectOptions)) {
                  assertBodyMayFollow(next, hop, prepared);
                }

                const current = redirectOptions.headers;
                if (current !== undefined) {
                  redirectOptions.headers = { ...headersWithout(current, revealed) };
                }
              }
              from = next;
              return;
            }

            if (policy === false || !hostAllowed(next, policy)) {
              throw new RedirectHostNotAllowedError(next.host, policy, 1);
            }
          },
        ],
      };
    }

    return out;
  }

  const withBody =
    (verb: 'POST' | 'PUT' | 'PATCH') =>
    <T>(url: string, body?: unknown, config?: SensitiveGotRequestConfig) =>
      send<T>(url, { ...config, method: verb, json: body });

  const withoutBody =
    (verb: 'GET' | 'DELETE' | 'HEAD') =>
    <T>(url: string, config?: SensitiveGotRequestConfig) =>
      send<T>(url, { ...config, method: verb });

  return {
    request: send,
    get: withoutBody('GET'),
    delete: withoutBody('DELETE'),
    head: withoutBody('HEAD'),
    post: withBody('POST'),
    put: withBody('PUT'),
    patch: withBody('PATCH'),
    client,
  };
}
