import type { ExecutionContext } from '@nestjs/common';
import type { RevealContext } from '@platform-sec/sensitive-string-core';

/**
 * Builds the request-level reveal context.
 *
 * Registered under `SENSITIVE_CONTEXT_FACTORY` and called once per request by
 * `SensitiveContextInterceptor`. Returning `undefined` establishes no
 * request-level context, leaving whatever `@WithRevealContext` declares.
 */
export type RevealContextFactory = (context: ExecutionContext) => RevealContext | undefined;

/**
 * What `@WithRevealContext` accepts: either a fixed context, or a factory that
 * receives the `ExecutionContext` so it can read route params, the
 * authenticated user, or anything else the request carries.
 */
export type HandlerRevealContext =
  RevealContext | ((context: ExecutionContext) => RevealContext | undefined);
