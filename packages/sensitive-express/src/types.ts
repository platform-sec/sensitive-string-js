import type {
  RevealContext,
  SensitiveFieldConfig,
  SensitiveString,
  SensitivityClass,
} from '@platform-sec/sensitive-string-core';
import type { Request } from 'express';

/**
 * Options for `sensitiveBody()`.
 */
export interface SensitiveBodyOptions {
  /**
   * Dot-notation paths to a sensitivity class, or to `{ klass, label }`.
   *
   * This is core's `SensitiveFieldConfig`, the same type `wrapSensitiveByPath`
   * takes, so one field map can be shared between the middleware and any
   * direct call to core's path helpers.
   */
  fields: SensitiveFieldConfig;

  /**
   * Content types to process, matched with `req.is()`.
   *
   * Defaults to `['application/json', 'application/x-www-form-urlencoded']`.
   * A request whose type matches none of them is left untouched.
   */
  contentTypes?: string[];
}

/**
 * Options for `sensitiveHeaders()`.
 */
export interface SensitiveHeadersOptions {
  /**
   * Header names to a sensitivity class, or to `{ klass, label }`.
   *
   * Names are matched case-insensitively and read back in lower case, which is
   * how Node stores them. The label defaults to the lower-cased header name.
   */
  fields: SensitiveFieldConfig;
}

/**
 * Builds the reveal context for one request.
 *
 * Called once per request by `sensitiveContext()`. Returning `undefined`
 * establishes no context for that request rather than an empty one, which
 * keeps a policy that rejects a missing context meaningful.
 */
export type RevealContextFactory = (req: Request) => RevealContext | undefined;

/**
 * The namespaced container this package adds to the request.
 *
 * Everything here is a wrapped copy. Nothing in it replaces what Express or
 * another middleware reads, which is why headers live here rather than in
 * `req.headers`.
 */
export interface SensitiveRequest {
  /**
   * Configured headers, wrapped. A key is present for every configured header
   * and is `null` when that header was absent or empty.
   *
   * The container has a null prototype, so a header named `constructor` or
   * `__proto__` is an ordinary key rather than a collision with `Object`.
   */
  headers: Record<string, SensitiveString<SensitivityClass> | null>;
}

declare global {
  // Declaration merging onto `Express.Request` is the idiom the framework's own
  // typings expose, and it is only reachable through the namespace form.
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      /**
       * Wrapped copies of sensitive request data, populated by this package's
       * middleware. Present only on requests that passed through one of them.
       */
      sensitive: SensitiveRequest;
    }
  }
}
