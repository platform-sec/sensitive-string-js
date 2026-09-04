/**
 * The transport.
 *
 * The API surface this package needs is small enough that a `fetch` adapter is
 * the whole vendor client, so the SDK is optional rather than required. The
 * interface is exported so a caller can supply their own with retries, mTLS, or
 * a proxy already configured, and it is also what bounds the OpenBao divergence
 * surface: a handful of endpoints is a small enough contract that a divergence
 * has to show up in one of a handful of places.
 *
 * Retry and backoff live nowhere in this package. An application that has
 * configured its own HTTP stack should not have a second policy wrapped around
 * it, and the single-flight in the shared cache is concurrency control rather
 * than retry.
 */

export interface VaultRequest {
  readonly method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  /** Path below `/v1`, such as `kv/data/prod/db`. Already URL-safe. */
  readonly path: string;
  readonly query?: Readonly<Record<string, string>>;
  readonly body?: unknown;
  readonly headers: Readonly<Record<string, string>>;
}

export interface VaultResponse {
  readonly status: number;
  /** The decoded JSON body, or undefined for an empty response. */
  readonly body: unknown;
}

export interface VaultTransport {
  request(request: VaultRequest): Promise<VaultResponse>;
}

/**
 * A Vault API failure.
 *
 * It carries the status and Vault's own `errors` array, which describes policy
 * and paths rather than values. That is a deliberate exception to the rule that
 * nothing here carries provider output: without it an operator debugging a
 * denied read has a status code and nothing else. `includeServerErrors: false`
 * turns it off for a deployment that would rather have less.
 */
export class VaultRequestError extends Error {
  override readonly name = 'VaultRequestError';

  constructor(
    readonly status: number,
    readonly path: string,
    readonly errors: readonly string[]
  ) {
    super(
      `Vault request to '${path}' failed with status ${String(status)}` +
        (errors.length === 0 ? '.' : `: ${errors.join('; ')}`)
    );
  }
}

export interface FetchTransportOptions {
  /** The API base, such as `https://vault.internal:8200`. */
  readonly endpoint: string;
  /** Injected for tests and for a caller with their own agent. Defaults to global `fetch`. */
  readonly fetch?: typeof globalThis.fetch;
  /** Request timeout in milliseconds. */
  readonly timeoutMs?: number;
  /** Whether a failure carries Vault's own `errors` array. Defaults to true. */
  readonly includeServerErrors?: boolean;
}

const DEFAULT_TIMEOUT_MS = 10_000;

/** Vault's error shape, which is an array of strings under `errors`. */
function serverErrors(body: unknown): string[] {
  if (body === null || typeof body !== 'object') {
    return [];
  }

  const errors = (body as { errors?: unknown }).errors;

  if (!Array.isArray(errors)) {
    return [];
  }

  return errors.filter((entry): entry is string => typeof entry === 'string');
}

/**
 * The default transport.
 *
 * The `Response` object is consumed here and never returned, so no caller can
 * reach a body a second time and no error object retains one. A body that is
 * not JSON produces a failure that names the status and not the content, since
 * a decoder that fails on content puts content in its error.
 */
export function fetchTransport(options: FetchTransportOptions): VaultTransport {
  const base = options.endpoint.replace(/\/+$/, '');
  const doFetch = options.fetch ?? globalThis.fetch;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const includeServerErrors = options.includeServerErrors ?? true;

  return {
    async request(request: VaultRequest): Promise<VaultResponse> {
      const url = new URL(`${base}/v1/${request.path.replace(/^\/+/, '')}`);

      for (const [key, value] of Object.entries(request.query ?? {})) {
        url.searchParams.set(key, value);
      }

      const controller = new AbortController();
      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        controller.abort();
      }, timeoutMs);

      try {
        const response = await doFetch(url, {
          method: request.method,
          headers: {
            ...request.headers,
            ...(request.body === undefined ? {} : { 'content-type': 'application/json' }),
          },
          ...(request.body === undefined ? {} : { body: JSON.stringify(request.body) }),
          signal: controller.signal,
        });

        const text = await response.text();
        let body: unknown;

        if (text !== '') {
          try {
            body = JSON.parse(text);
          } catch {
            // The response was not JSON. Its content does not go into the
            // error, because a response body from a secrets API is the last
            // thing to put into a message that reaches a tracker.
            throw new VaultRequestError(response.status, request.path, [
              'the response body was not JSON',
            ]);
          }
        }

        if (!response.ok) {
          throw new VaultRequestError(
            response.status,
            request.path,
            includeServerErrors ? serverErrors(body) : []
          );
        }

        return { status: response.status, body };
      } catch (error) {
        // A timeout surfaces from `fetch` as an `AbortError`, which names
        // neither the request nor the reason. Reporting it as this package's
        // own error means a caller has one type to catch and a message that
        // says which path gave up. Status 0 because there was no response.
        if (timedOut) {
          throw new VaultRequestError(0, request.path, [
            `the request timed out after ${String(timeoutMs)}ms`,
          ]);
        }

        throw error;
      } finally {
        clearTimeout(timer);
      }
    },
  };
}
