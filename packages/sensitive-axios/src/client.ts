import {
  assertBodyMayFollow,
  assertDecoded,
  assertHopAllowed,
  headersWithout,
  isCrossOrigin,
  isRedirect,
  prepareRequest,
  redirectMethod,
  safeUrl,
  wrapResponseFields,
} from '@platform-sec/sensitive-string-http';
import type {
  PreparedRequest,
  SensitiveClientOptions,
  SensitiveHeaders,
  SensitiveQuery,
} from '@platform-sec/sensitive-string-http';
import type { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';

import { scrubError, scrubResponse } from './scrub.js';

/**
 * The wrapper owns the call.
 *
 * Not an interceptor. axios's request interceptor runs **after** headers are
 * normalized to strings and **before** the body is serialized, so it can fix
 * the body and cannot fix the header. That alone would settle it, but the
 * larger reason is that the measured damage is after the send: an interceptor
 * cannot scrub an error axios has not built yet, cannot scrub a response axios
 * has already resolved with, and cannot see the individual hops of a redirect
 * axios follows internally.
 *
 * The cost is that this surface is the six verbs plus `request`, rather than
 * axios's full API. A caller who needs `CancelToken` or an adapter reaches for
 * `client` and loses the guard, and the README says so.
 */

/** Everything the wrapper does not own is the caller's axios config, unchanged. */
export interface SensitiveAxiosRequestConfig extends Omit<
  AxiosRequestConfig,
  'headers' | 'params' | 'data'
> {
  /** May hold `SensitiveString` instances and the auth helpers' descriptors. */
  headers?: SensitiveHeaders;
  /** May hold `SensitiveString` instances. Revealed into primitives before assignment. */
  params?: SensitiveQuery;
  data?: unknown;
  /** An `application/x-www-form-urlencoded` body the wrapper builds after revealing. */
  form?: SensitiveQuery;
}

/**
 * The response, minus `request`.
 *
 * Typed `undefined` rather than left as axios's `unknown`, so a caller who
 * reads it is told at compile time rather than at run time. See `scrub.ts` for
 * why a `ClientRequest` cannot be handed back.
 */
export type SensitiveAxiosResponse<T> = Omit<AxiosResponse<T>, 'request'> & {
  readonly request: undefined;
};

export type SensitiveAxiosOptions = SensitiveClientOptions;

export interface SensitiveAxios {
  request<T = unknown>(config: SensitiveAxiosRequestConfig): Promise<SensitiveAxiosResponse<T>>;
  get<T = unknown>(
    url: string,
    config?: SensitiveAxiosRequestConfig
  ): Promise<SensitiveAxiosResponse<T>>;
  delete<T = unknown>(
    url: string,
    config?: SensitiveAxiosRequestConfig
  ): Promise<SensitiveAxiosResponse<T>>;
  head<T = unknown>(
    url: string,
    config?: SensitiveAxiosRequestConfig
  ): Promise<SensitiveAxiosResponse<T>>;
  post<T = unknown>(
    url: string,
    data?: unknown,
    config?: SensitiveAxiosRequestConfig
  ): Promise<SensitiveAxiosResponse<T>>;
  put<T = unknown>(
    url: string,
    data?: unknown,
    config?: SensitiveAxiosRequestConfig
  ): Promise<SensitiveAxiosResponse<T>>;
  patch<T = unknown>(
    url: string,
    data?: unknown,
    config?: SensitiveAxiosRequestConfig
  ): Promise<SensitiveAxiosResponse<T>>;
  /** The instance the caller handed over, for the features this surface does not expose. */
  readonly client: AxiosInstance;
}

/** Resolve a possibly relative URL against the instance's `baseURL`. */
function resolveUrl(client: AxiosInstance, url: string | undefined): string {
  const target = url ?? '';

  try {
    return new URL(target).toString();
  } catch {
    const base = client.defaults.baseURL;

    if (base === undefined || base === '') {
      throw new TypeError(
        `Cannot resolve '${target}' to an absolute URL: the axios instance has no baseURL. ` +
          `The wrapper needs the destination host before it reveals anything, because the ` +
          `transport and redirect checks run first.`
      );
    }

    return new URL(target.replace(/^\//, ''), base.endsWith('/') ? base : `${base}/`).toString();
  }
}

/**
 * Default headers merged in, so an instance-level credential is revealed too.
 *
 * Measured: a `SensitiveString` on `defaults.headers.common` reaches the wire
 * as `[REDACTED:credential]` exactly like a per-request one, and the wrapper
 * would never see it if it only read the call's own headers.
 */
function withDefaultHeaders(
  client: AxiosInstance,
  method: string,
  headers: SensitiveHeaders | undefined
): SensitiveHeaders {
  const defaults = client.defaults.headers as unknown as Record<string, SensitiveHeaders>;
  const common = defaults['common'] ?? {};
  const perMethod = defaults[method.toLowerCase()] ?? {};

  return { ...common, ...perMethod, ...(headers ?? {}) };
}

/** The predicate axios would have used, with `null` meaning "accept everything". */
function resolveValidateStatus(
  config: SensitiveAxiosRequestConfig,
  client: AxiosInstance
): (status: number) => boolean {
  const chosen =
    'validateStatus' in config ? config.validateStatus : client.defaults.validateStatus;

  if (chosen === null) {
    return () => true;
  }

  return chosen ?? ((status: number) => status >= 200 && status < 300);
}

function outgoingConfig(
  prepared: PreparedRequest,
  config: SensitiveAxiosRequestConfig,
  manualRedirects: boolean,
  client: AxiosInstance,
  dropped: readonly string[] = []
): AxiosRequestConfig {
  const {
    headers: _headers,
    params: _params,
    data: _data,
    form: _form,
    // `prepared.url` is absolute, so axios ignores `baseURL` anyway. Dropping
    // the key rather than setting it to `undefined` is what
    // `exactOptionalPropertyTypes` asks for.
    baseURL: _baseURL,
    ...rest
  } = config;

  const body = prepared.formText !== undefined ? prepared.formText : prepared.body;

  const outgoing: AxiosRequestConfig = {
    ...rest,
    url: prepared.url,
    method: prepared.method,
    headers: {
      ...prepared.headers,
      ...(prepared.formText !== undefined
        ? { 'content-type': 'application/x-www-form-urlencoded' }
        : {}),
      // Removing a name from what we send is not enough on its own: axios
      // merges `defaults.headers` underneath the request's own, so a header
      // `'strip'` dropped is refilled from the instance defaults on the next
      // hop. The value there was never revealed, so what would arrive is the
      // descriptor's `[object Object]` rather than the secret, but a junk
      // header on the wire is still a bug. `null` is axios's way of saying the
      // default does not apply.
      ...Object.fromEntries(dropped.map((name) => [name, null])),
    },
    data: body,
  };

  if (manualRedirects) {
    // The wrapper follows hops itself, because that is the only way to see each
    // one. The caller's own `maxRedirects` is read as the hop budget.
    outgoing.maxRedirects = 0;

    // `null` is axios's way of saying "accept every status", and it is not the
    // same as absent, so `??` cannot be used to fall through to the defaults:
    // a caller who passed `validateStatus: null` had every status turned back
    // into an error the moment the wrapper started following hops.
    const callerValidates = resolveValidateStatus(config, client);

    // The one axios option the wrapper touches beyond redirects, and only while
    // it is following them: a 3xx has to come back as a response for the hop
    // loop to read `location`. Every other status still goes through the
    // caller's own predicate.
    outgoing.validateStatus = (status: number) =>
      isRedirect(status) ? true : callerValidates(status);
  }

  return outgoing;
}

export function createSensitiveAxios(
  client: AxiosInstance,
  options: SensitiveAxiosOptions = {}
): SensitiveAxios {
  async function send<T>(config: SensitiveAxiosRequestConfig): Promise<SensitiveAxiosResponse<T>> {
    const method = (config.method ?? 'get').toUpperCase();
    const budget = config.maxRedirects ?? options.maxRedirects ?? 5;

    let url = resolveUrl(client, config.url);
    let currentMethod = method;
    let body = config.data;
    let form = config.form;
    let hop = 0;
    // Names dropped by `'strip'` so far, lowercased, accumulated rather than
    // recomputed: a credential removed at hop two stays removed at hop three.
    //
    // Accumulating names rather than narrowing a header object is what makes
    // this correct for `withDefaultHeaders`. The instance's own
    // `defaults.headers` are merged in below and may themselves hold a wrapped
    // value, so they are revealed and land in the plan; filtering only the
    // per-request headers would strip the call site's credential and forward
    // the instance's, which is the leak this mode exists to stop.
    let dropped: readonly string[] = [];

    for (;;) {
      const prepared = prepareRequest(
        {
          method: currentMethod,
          url,
          headers: headersWithout(
            withDefaultHeaders(client, currentMethod, config.headers),
            dropped
          ),
          // Merged on the first hop only; `prepareRequest` drops it for the
          // hops that follow, because a redirect target is the URL the server
          // named and nothing else.
          query: config.params,
          body,
          form,
        },
        { ...options, client: 'axios', attempt: 1, hop: hop + 1 }
      );

      const manual = prepared.redirects !== 'client';

      let response: AxiosResponse<T>;

      try {
        response = await client.request<T>(
          outgoingConfig(prepared, { ...config, method: currentMethod }, manual, client, dropped)
        );
      } catch (error) {
        throw scrubError(error, prepared.plan);
      }

      if (!manual || !isRedirect(response.status)) {
        return finish(scrubResponse(response, prepared.plan), prepared, options);
      }

      const location = response.headers['location'] as string | undefined;

      if (location === undefined || location === '') {
        return finish(scrubResponse(response, prepared.plan), prepared, options);
      }

      hop += 1;

      const next = new URL(location, url);

      // The refusal happens before the next request is built, so nothing is
      // revealed for a host the caller never named. The response for the hop
      // that got us here is scrubbed first, because the refusal does not stop
      // it from being reachable through the thrown error's stack.
      scrubResponse(response, prepared.plan);
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

      url = next.toString();
      currentMethod = rewritten.method;

      if (!rewritten.keepBody) {
        body = undefined;
        form = undefined;
      }
    }
  }

  function finish<T>(
    response: AxiosResponse<T>,
    prepared: PreparedRequest,
    opts: SensitiveAxiosOptions
  ): SensitiveAxiosResponse<T> {
    // axios does not throw on a body that is not JSON; it hands back the raw
    // string. When the caller declared response fields they told us the body is
    // an object, so a string is a decode failure axios chose not to report.
    assertDecoded(response.data, opts.responseFields, {
      method: prepared.method,
      url: safeUrl(prepared.url),
      contentType: response.headers['content-type'] as string | undefined,
    });

    response.data = wrapResponseFields(response.data, opts.responseFields);

    return response as SensitiveAxiosResponse<T>;
  }

  const withData =
    (verb: 'post' | 'put' | 'patch') =>
    <T>(url: string, data?: unknown, config?: SensitiveAxiosRequestConfig) =>
      send<T>({ ...config, url, method: verb, data });

  const withoutData =
    (verb: 'get' | 'delete' | 'head') =>
    <T>(url: string, config?: SensitiveAxiosRequestConfig) =>
      send<T>({ ...config, url, method: verb });

  return {
    request: send,
    get: withoutData('get'),
    delete: withoutData('delete'),
    head: withoutData('head'),
    post: withData('post'),
    put: withData('put'),
    patch: withData('patch'),
    client,
  };
}
