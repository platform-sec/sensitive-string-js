import {
  SensitiveHttpError,
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
  PreparedRequest,
  SensitiveHeaders,
  SensitiveInstanceOptions,
  SensitiveQuery,
} from '@platform-sec/sensitive-string-http';
import type { KyInstance, Options } from 'ky';

import { scrubError, scrubResponse } from './scrub.js';

/**
 * ky's hooks cannot carry this, and not for the usual reason.
 *
 * `init` does not expose `options.json` at all, so there is no ky-side point at
 * which the body is still structured. `beforeRequest` receives a built
 * `Request` whose headers are strings; they are still mutable, so a header
 * could be fixed there, but the body could only be changed by returning a
 * replacement `Request`, which means re-serializing what ky just serialized.
 * Revealing before the call is the only option here, not merely the uniform
 * one.
 *
 * ky 2 also changed `beforeRequest` from `(request, options)` to a single state
 * object, so a hook written against ky 1 receives `undefined` and throws at the
 * first call. That is why the peer range is `^2.0.0` and not wider.
 */

export interface SensitiveKyRequestConfig extends Omit<
  Options,
  'headers' | 'searchParams' | 'json' | 'body'
> {
  /** May hold `SensitiveString` instances and the auth helpers' descriptors. */
  headers?: SensitiveHeaders;
  /** May hold instances. Revealed into primitives before the URL is built. */
  searchParams?: SensitiveQuery;
  /** A structured JSON body to reveal and serialize. */
  json?: unknown;
  /** An `application/x-www-form-urlencoded` body the wrapper builds after revealing. */
  form?: SensitiveQuery;
}

export type SensitiveKyOptions = SensitiveInstanceOptions;

/**
 * ky's own ergonomics: a promise for the `Response`, with the body accessors
 * hanging off it.
 *
 * `json()` is the one that matters. It routes through the shared decoder, so a
 * body that is not JSON becomes a `ResponseDecodeError` naming the request
 * rather than a `SyntaxError` quoting the first characters of what was probably
 * the credential, and the configured response fields are wrapped before the
 * caller's `await` resolves.
 */
export interface SensitiveResponsePromise<T> extends Promise<Response> {
  json(): Promise<T>;
  text(): Promise<string>;
  arrayBuffer(): Promise<ArrayBuffer>;
}

export interface SensitiveKy {
  request<T = unknown>(url: string, config?: SensitiveKyRequestConfig): SensitiveResponsePromise<T>;
  get<T = unknown>(url: string, config?: SensitiveKyRequestConfig): SensitiveResponsePromise<T>;
  delete<T = unknown>(url: string, config?: SensitiveKyRequestConfig): SensitiveResponsePromise<T>;
  head<T = unknown>(url: string, config?: SensitiveKyRequestConfig): SensitiveResponsePromise<T>;
  post<T = unknown>(
    url: string,
    body?: unknown,
    config?: SensitiveKyRequestConfig
  ): SensitiveResponsePromise<T>;
  put<T = unknown>(
    url: string,
    body?: unknown,
    config?: SensitiveKyRequestConfig
  ): SensitiveResponsePromise<T>;
  patch<T = unknown>(
    url: string,
    body?: unknown,
    config?: SensitiveKyRequestConfig
  ): SensitiveResponsePromise<T>;
  /** The instance the caller handed over, for the features this surface does not expose. */
  readonly client: KyInstance;
}

function resolveUrl(client: KyInstance, url: string): string {
  try {
    return new URL(url).toString();
  } catch {
    const prefix = prefixUrlOf(client);

    if (prefix === '') {
      throw new TypeError(
        `Cannot resolve '${url}' to an absolute URL: no prefix was configured. Pass ` +
          `{ prefix: 'https://api.example.com' } to createSensitiveKy. The wrapper needs the ` +
          `destination host before it reveals anything, because the transport and redirect ` +
          `checks run first.`
      );
    }

    return new URL(url.replace(/^\//, ''), prefix.endsWith('/') ? prefix : `${prefix}/`).toString();
  }
}

/**
 * ky does not expose the defaults of an extended instance, so the prefix comes
 * from this package's own option bag instead.
 *
 * Named `prefix` after ky 2's own option, which renamed `prefixUrl` and now
 * sits beside `baseUrl`. The wrapper needs the destination host before it
 * reveals anything, so it cannot let ky resolve a relative URL for it.
 */
const prefixes = new WeakMap<object, string>();

function prefixUrlOf(client: KyInstance): string {
  return prefixes.get(client) ?? '';
}

/**
 * The wrapper's own `headers` option, under the call's headers.
 *
 * The only instance-level layer here. ky does not expose an extended
 * instance's defaults, so a wrapped value in `ky.extend({ headers })` is never
 * seen by the wrapper (and does not compile, since ky types it as a string);
 * this option is where an instance credential goes. Merged before the
 * `'strip'` accounting in the hop loop, so a name dropped at a boundary is
 * not refilled from here on the next hop.
 */
function withInstanceHeaders(
  instance: SensitiveHeaders | undefined,
  headers: SensitiveHeaders | undefined
): SensitiveHeaders | undefined {
  return instance === undefined ? headers : { ...instance, ...(headers ?? {}) };
}

export function createSensitiveKy(
  client: KyInstance,
  options: SensitiveKyOptions & { prefix?: string } = {}
): SensitiveKy {
  if (options.prefix !== undefined) {
    prefixes.set(client, options.prefix);
  }

  async function attempt(
    url: string,
    config: SensitiveKyRequestConfig,
    attemptNumber: number
  ): Promise<{ response: Response; prepared: PreparedRequest }> {
    let currentUrl = url;
    let currentMethod = (config.method ?? 'get').toUpperCase();
    let body = config.json;
    let form = config.form;
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
          headers: headersWithout(withInstanceHeaders(options.headers, config.headers), dropped),
          // Merged on the first hop only; `prepareRequest` drops it for the
          // hops that follow.
          query: config.searchParams,
          body,
          form,
        },
        { ...options, client: 'ky', attempt: attemptNumber, hop: hop + 1 }
      );

      const manual = prepared.redirects !== 'client';

      let response: Response;

      try {
        response = await client(prepared.url, outgoing(prepared, config, manual));
      } catch (error) {
        // ky throws on every non-2xx, so a 3xx under `redirect: 'manual'`
        // arrives as an `HTTPError` rather than as a response. The hop loop
        // needs the response; every other status keeps ky's own semantics.
        const carried = (error as { response?: Response } | null)?.response;

        if (manual && carried instanceof Response && isRedirect(carried.status)) {
          response = carried;
        } else {
          throw scrubError(error, prepared.plan, prepared.url);
        }
      }

      if (!manual || !isRedirect(response.status)) {
        return { response: scrubResponse(response, prepared.plan), prepared };
      }

      const location = response.headers.get('location');

      if (location === null || location === '') {
        return { response: scrubResponse(response, prepared.plan), prepared };
      }

      hop += 1;

      await discardBody(response);

      const next = new URL(location, currentUrl);

      // The refusal happens before the next request is built, so nothing is
      // revealed for a host the caller never named.
      assertHopAllowed(next, hop, prepared.redirects, budget);

      const rewritten = redirectMethod(response.status, currentMethod);

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

  function outgoing(
    prepared: PreparedRequest,
    config: SensitiveKyRequestConfig,
    manual: boolean
  ): Options {
    const {
      headers: _headers,
      searchParams: _searchParams,
      json: _json,
      form: _form,
      ...rest
    } = config;

    const out = {
      ...rest,
      method: prepared.method,
      headers: prepared.headers,
      // The wrapper drives retries so each attempt reveals and audits once, and
      // follows redirects itself when a policy applies, because ky's platform
      // forwards a non-standard auth header across origins.
      retry: 0,
      // Neutralized, because `prepared.url` is already absolute. ky 2 renamed
      // `prefixUrl` to `prefix` and added `baseUrl`; both are cleared so an
      // extended instance's own prefix is not applied twice.
      prefix: '',
      baseUrl: undefined,
      ...(manual ? { redirect: 'manual' as const } : {}),
    } as unknown as Options & Record<string, unknown>;

    if (prepared.formText !== undefined) {
      out['body'] = prepared.formText;
      out['headers'] = {
        'content-type': 'application/x-www-form-urlencoded',
        ...prepared.headers,
      };
    } else if (prepared.body !== undefined) {
      out['json'] = prepared.body;
    }

    return out;
  }

  function send<T>(
    url: string,
    config: SensitiveKyRequestConfig = {}
  ): SensitiveResponsePromise<T> {
    const budget = options.retries ?? 0;

    const settle = (async () => {
      // Inside the async body, not beside it: `send` returns a promise, and a
      // wrapper that throws synchronously for a bad URL would be the one place
      // in this package where a caller has to write both `try` and `.catch`.
      const resolved = resolveUrl(client, url);

      for (let attemptNumber = 1; ; attemptNumber += 1) {
        try {
          return await attempt(resolved, config, attemptNumber);
        } catch (error) {
          // A refusal from this package is not something a retry can fix, and
          // retrying it would reveal again for no reason.
          if (error instanceof SensitiveHttpError || attemptNumber > budget) {
            throw error;
          }
        }
      }
    })();

    const promise = settle.then(({ response }) => response) as SensitiveResponsePromise<T>;

    promise.json = async () => {
      const { response, prepared } = await settle;
      const text = await response.text();

      return wrapResponseFields(
        decodeJson(text, {
          method: prepared.method,
          url: safeUrl(prepared.url),
          contentType: response.headers.get('content-type') ?? undefined,
        }),
        options.responseFields
      ) as T;
    };

    promise.text = async () => (await settle).response.text();
    promise.arrayBuffer = async () => (await settle).response.arrayBuffer();

    return promise;
  }

  const withBody =
    (verb: 'post' | 'put' | 'patch') =>
    <T>(url: string, body?: unknown, config?: SensitiveKyRequestConfig) =>
      send<T>(url, { ...config, method: verb, json: body });

  const withoutBody =
    (verb: 'get' | 'delete' | 'head') =>
    <T>(url: string, config?: SensitiveKyRequestConfig) =>
      send<T>(url, { ...config, method: verb });

  return {
    request: send,
    get: withoutBody('get'),
    delete: withoutBody('delete'),
    head: withoutBody('head'),
    post: withBody('post'),
    put: withBody('put'),
    patch: withBody('patch'),
    client,
  };
}

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
