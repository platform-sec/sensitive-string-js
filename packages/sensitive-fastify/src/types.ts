import type {
  RevealContext,
  SensitiveFieldConfig,
  SensitiveString,
  SensitivityClass,
} from '@platform-sec/sensitive-string-core';
import type { FastifyRequest } from 'fastify';

/**
 * Builds the reveal context for one request.
 *
 * Called once per request by the context hook. Returning `undefined`
 * establishes no context for that request rather than an empty one, which
 * keeps a policy that rejects a missing context meaningful.
 *
 * The factory is synchronous on purpose. The hook has to call Fastify's `done`
 * from inside the scope it opened, and an awaited factory would have to
 * reproduce that arrangement by hand.
 */
export type RevealContextFactory = (request: FastifyRequest) => RevealContext | undefined;

/**
 * Lifecycle positions the context hook can occupy.
 *
 * Each is a callback-style hook that runs before the handler, which is what
 * lets the hook keep the `AsyncLocalStorage` scope open across everything
 * Fastify runs after it.
 */
export type ContextHookName = 'onRequest' | 'preValidation' | 'preHandler';

/**
 * Options for `sensitivePlugin`.
 */
export interface SensitivePluginOptions {
  /**
   * Body paths wrapped on every route in this plugin scope.
   *
   * Dot notation to a sensitivity class or to `{ klass, label }`: core's
   * `SensitiveFieldConfig`, the same type `wrapSensitiveByPath` takes, so one
   * field map can be shared between the plugin and any direct call to core's
   * path helpers. A label defaults to the path's last segment.
   *
   * Routes that carry a JSON Schema do not need this; the `sensitive` keyword
   * wraps during validation instead.
   */
  body?: SensitiveFieldConfig;

  /**
   * Media types the `body` option and route configs apply to.
   *
   * Defaults to `['application/json', 'application/x-www-form-urlencoded']`,
   * matched against the request's `Content-Type` with its parameters dropped. A
   * request of any other type is left untouched.
   *
   * The gate is not cosmetic. Wrapping clones the body through core's
   * `wrapSensitiveByPath`, whose clone flattens anything that is not a plain
   * object, array, `Date`, or `SensitiveString`: a `Buffer` from a multipart
   * parser becomes a numeric-keyed object, and a `Map` or `Set` becomes `{}`.
   * The two defaults are the types that cannot carry such a value.
   *
   * Widen it for a custom parser that produces plain data, such as a
   * vendor-specific JSON media type.
   */
  contentTypes?: string[];

  /**
   * Headers extracted to `request.sensitive.headers`.
   *
   * `request.headers` is not modified. Names are matched case-insensitively
   * and read back in lower case, which is how Node stores them.
   */
  headers?: SensitiveFieldConfig;

  /**
   * Builds the request's `RevealContext`. Omit it to establish none.
   */
  context?: RevealContextFactory;

  /**
   * Which hook establishes the context. Defaults to `'onRequest'`.
   *
   * `'onRequest'` covers the most and sees the least: no body, and no
   * `request.user` from an authentication plugin. `'preHandler'` sees both and
   * leaves a validation failure outside the scope.
   */
  contextHook?: ContextHookName;

  /**
   * Redact response bodies in `preSerialization`. Defaults to `false`.
   */
  responseFilter?: boolean;
}

/**
 * Per-route configuration, read from `request.routeOptions.config.sensitive`.
 *
 * Honoured by any registration of the plugin whose scope contains the route,
 * and merged over that registration's `body` option.
 */
export interface SensitiveRouteConfig {
  /** Body paths wrapped on this route only. */
  body?: SensitiveFieldConfig;
}

/**
 * The namespaced container this package adds to the request.
 *
 * Everything here is a wrapped copy. Nothing in it replaces what Fastify or
 * another plugin reads, which is why headers live here rather than in
 * `request.headers`.
 */
export interface SensitiveRequest {
  /**
   * Configured headers, wrapped. A key is present for every configured header
   * and is `null` when that header was absent or empty.
   *
   * The container has a null prototype, so a header named `constructor` or
   * `__proto__` is an ordinary key rather than a collision with `Object`.
   */
  readonly headers: Readonly<Record<string, SensitiveString<SensitivityClass> | null>>;
}

declare module 'fastify' {
  interface FastifyRequest {
    /**
     * Wrapped copies of sensitive request data, populated by this plugin.
     *
     * Present on every request in a scope where the plugin is registered, and
     * an empty frozen container on a route no `headers` option applies to.
     */
    readonly sensitive: SensitiveRequest;
  }

  interface FastifyContextConfig {
    /** Per-route sensitive field configuration. */
    sensitive?: SensitiveRouteConfig;
  }
}
