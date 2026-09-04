/**
 * The transport.
 *
 * One endpoint over `fetch`, so the `@infisical/sdk` is not a dependency and
 * this package has no third-party runtime dependency at all. The interface is exported so a caller can
 * supply their own with retries, mTLS or a proxy already configured, which is
 * also what bounds the surface: one endpoint is a small enough contract that a
 * change to it has one place to show up.
 */

export interface InfisicalRequest {
  /** Path below the endpoint, such as `api/v3/secrets/raw`. */
  readonly path: string;
  readonly query: Readonly<Record<string, string>>;
  readonly headers: Readonly<Record<string, string>>;
}

export interface InfisicalResponse {
  readonly status: number;
  /** The decoded JSON body, or undefined for an empty response. */
  readonly body: unknown;
}

export interface InfisicalTransport {
  request(request: InfisicalRequest): Promise<InfisicalResponse>;
}

/**
 * A Infisical API failure.
 *
 * It carries Infisical's own message, which describes the token's scope and the
 * path that was asked for rather than any value. That is the same deliberate
 * exception the Vault package makes: without it an operator debugging a denied
 * read has a status code and nothing else. `includeServerErrors: false` turns
 * it off for a deployment that would rather have less.
 */
export class InfisicalRequestError extends Error {
  override readonly name = 'InfisicalRequestError';

  constructor(
    readonly status: number,
    readonly path: string,
    readonly errors: readonly string[]
  ) {
    super(
      `Infisical request to '${path}' failed with status ${String(status)}` +
        (errors.length === 0 ? '.' : `: ${errors.join('; ')}`)
    );
  }
}

export interface FetchTransportOptions {
  /** The API base. Defaults to Infisical's. */
  readonly endpoint?: string;
  readonly fetch?: typeof globalThis.fetch;
  readonly timeoutMs?: number;
  /** Whether a failure carries Infisical's own message. Defaults to true. */
  readonly includeServerErrors?: boolean;
}

export const DEFAULT_ENDPOINT = 'https://app.infisical.com';

const DEFAULT_TIMEOUT_MS = 10_000;

/**
 * Infisical's error shape, which is `{ message, error, statusCode }`.
 *
 * Only `message` and `error` are taken. They describe the token's scope and the
 * path that was asked for rather than any value, which is the same deliberate
 * exception the Vault package makes for its `errors` array.
 */
function serverErrors(body: unknown): string[] {
  if (body === null || typeof body !== 'object') {
    return [];
  }

  const shaped = body as { message?: unknown; error?: unknown };

  return [shaped.message, shaped.error].filter(
    (entry): entry is string => typeof entry === 'string'
  );
}

/**
 * The default transport.
 *
 * The `Response` is consumed here and never returned, so no caller can reach a
 * body twice and no error object retains one. A body that is not JSON produces
 * a failure naming the status and not the content, because a decoder that fails
 * on content puts content in its error, and the body of a secrets API response
 * is the last thing to put in a message that reaches a tracker.
 */
export function fetchTransport(options: FetchTransportOptions = {}): InfisicalTransport {
  const base = (options.endpoint ?? DEFAULT_ENDPOINT).replace(/\/+$/, '');
  const doFetch = options.fetch ?? globalThis.fetch;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const includeServerErrors = options.includeServerErrors ?? true;

  return {
    async request(request: InfisicalRequest): Promise<InfisicalResponse> {
      const url = new URL(`${base}/${request.path.replace(/^\/+/, '')}`);

      for (const [key, value] of Object.entries(request.query)) {
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
          method: 'GET',
          headers: { ...request.headers, accept: 'application/json' },
          signal: controller.signal,
        });

        const text = await response.text();
        let body: unknown;

        if (text !== '') {
          try {
            body = JSON.parse(text);
          } catch {
            throw new InfisicalRequestError(response.status, request.path, [
              'the response body was not JSON',
            ]);
          }
        }

        if (!response.ok) {
          throw new InfisicalRequestError(
            response.status,
            request.path,
            includeServerErrors ? serverErrors(body) : []
          );
        }

        return { status: response.status, body };
      } catch (error) {
        // A timeout surfaces from `fetch` as an `AbortError`, which names
        // neither the request nor the reason. Status 0 because there was no
        // response.
        if (timedOut) {
          throw new InfisicalRequestError(0, request.path, [
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
