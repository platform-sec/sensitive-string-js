import type {
  RevealContext,
  SensitiveFieldConfig,
  SensitivityClass,
  SensitiveString,
} from '@platform-sec/sensitive-string-core';

import type { AuthHeader } from './auth.js';

/**
 * The options every client package accepts, so a caller who moves from axios to
 * ky rewrites the call and not the policy.
 */

/** A header value the wrapper knows how to handle. */
export type SensitiveHeaderValue =
  string | number | boolean | SensitiveString<SensitivityClass> | AuthHeader;

export type SensitiveHeaders = Record<string, SensitiveHeaderValue | null | undefined>;

/** A query value the wrapper knows how to handle. */
export type SensitiveQueryValue =
  string | number | boolean | SensitiveString<SensitivityClass> | null | undefined;

export type SensitiveQuery = Record<string, SensitiveQueryValue | readonly SensitiveQueryValue[]>;

/** What a `context` factory is told about the request it is naming. */
export interface RequestDescriptor {
  /** Uppercased HTTP method. */
  readonly method: string;
  /** The full URL, with its query string removed. */
  readonly url: string;
  readonly host: string;
  /** 1 for the first send, 2 for the first retry, and so on. */
  readonly attempt: number;
  /**
   * 1 for the request the caller made, 2 for the first redirect hop it was
   * followed to, and so on.
   *
   * Separate from `attempt` because they answer different questions. A retry
   * re-sends the same request to the same host; a hop sends it to a host the
   * server chose. Both write the value to a socket, so both are audited, and
   * without this an audit log cannot tell one from the other.
   */
  readonly hop: number;
}

/** Overrides merged onto the ambient context. Absent keys are omitted, never undefined. */
export interface ContextOverrides {
  readonly name?: string;
  readonly reason?: string;
  readonly tags?: Readonly<Record<string, unknown>>;
}

export type ContextOption =
  RevealContext | ContextOverrides | ((request: RequestDescriptor) => ContextOverrides);

/** Options shared by every client package. */
export interface SensitiveClientOptions {
  /**
   * Name and justify the reveals this client performs.
   *
   * The ambient context is the parent in every case: a call inside an Express
   * or Fastify handler inherits the request's context and its audit sink, and
   * this only adds the destination.
   */
  readonly context?: ContextOption;

  /** Shorthand for `context: { reason }`. */
  readonly reason?: string;

  /**
   * Hosts a redirect may lead to, or `false` to refuse redirects outright.
   *
   * `false` is the default whenever the request carries a credential in a
   * header outside the Fetch specification's stripping set, which in practice
   * means any `apiKey()` header: measured, axios, got and Node's `fetch` all
   * forward `x-api-key` verbatim across origins.
   *
   * When every credential is in `Authorization` or `Cookie` and this is unset,
   * the client's own redirect handling is left alone, because three
   * independent implementations already agree on stripping those.
   */
  readonly allowedHosts?: readonly string[] | false;

  /**
   * Reveal a credential into a plaintext `http://` request to a non-loopback host.
   *
   * Off, and named to be unpleasant to type. The legitimate cases are a sidecar
   * or a local proxy that terminates TLS itself.
   */
  readonly allowInsecureTransport?: boolean;

  /** Hop budget when the wrapper follows redirects itself. Defaults to 5. */
  readonly maxRedirects?: number;

  /** Response body paths to wrap on the way in. Opt-in per path; nothing is wrapped by surprise. */
  readonly responseFields?: SensitiveFieldConfig;

  /**
   * Also scan outgoing representations for the base64 encoding of the marker.
   *
   * Off by default. The auth helpers own the encoding for the case that
   * matters, so this is for a caller who base64-encodes something themselves.
   */
  readonly scanBase64?: boolean;

  /**
   * A redacted copy of the outgoing request, for a log line.
   *
   * The copy is produced by core's `redactCopy`, so it holds no revealed value
   * and no `serialize()` result. It is built before anything is revealed.
   */
  readonly log?: (redacted: unknown) => void;

  /**
   * Retries per call, driven by the wrapper so the audit trail counts attempts.
   *
   * Honoured by the `got` and `ky` packages, which take the client's own retry
   * limit to zero so a retried request reveals and audits once per attempt
   * rather than once per call. axios, `fetch` and undici have no built-in
   * retry, so their packages add none and ignore this. Defaults to 0.
   */
  readonly retries?: number;
}

/** What a client package hands the shared pipeline. */
export interface OutgoingRequest {
  readonly method: string;
  /** Absolute URL, query string included or not; `query` is merged onto it. */
  readonly url: string;
  readonly headers?: SensitiveHeaders | undefined;
  readonly query?: SensitiveQuery | undefined;
  /** A structured body to reveal and serialize. Mutually exclusive with `rawBody`. */
  readonly body?: unknown;
  /** An already-serialized body the wrapper only scans. */
  readonly rawBody?: string | Uint8Array | undefined;
  /** Form-encoded body built by the wrapper after revealing. */
  readonly form?: SensitiveQuery | undefined;
}
