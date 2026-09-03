import { withRevealContext } from '@platform-sec/sensitive-string-core';
import type { RequestHandler } from 'express';
import type { RevealContextFactory } from './types.js';

/**
 * Establish the reveal context for everything that runs after this middleware.
 *
 * The scope is wide because Express calls `next()` synchronously: every later
 * middleware, the route handler, the continuations after each `await` in it,
 * and any error handler all run inside the `AsyncLocalStorage` scope this
 * opens. The error handler holds whether the error arrived by `next(err)`, by a
 * synchronous throw, or from a rejected async handler, because Express catches
 * a throw at the layer that threw and calls `next(err)` from inside this scope.
 *
 * What does not inherit it is middleware registered before this one. An event
 * listener on `req` or `res` is a separate question: a listener is a plain
 * function, so it runs in whatever context is active when the event fires,
 * regardless of where it was registered. `finish` emitted from inside
 * `res.end()` is still inside the scope; an event that arrives after the
 * handler has returned is not. Code that reveals a value off the request path
 * passes an explicit `RevealContext`.
 *
 * A factory returning `undefined` establishes no context for that request
 * rather than an empty one, so a policy whose `checkRevealAllowed` rejects a
 * missing context still rejects.
 *
 * @param factory - Builds the context from the request, once per request
 * @returns Express middleware
 *
 * @example
 * ```ts
 * app.use(sensitiveContext((req) => ({
 *   name: `${req.method} ${req.path}`,
 *   tags: { requestId: req.headers['x-request-id'], ip: req.ip },
 *   auditReveal: (value, details) => {
 *     logger.info('sensitive_access', {
 *       operation: details.operation,
 *       klass: value.klass,
 *       label: value.label,
 *       path: req.path,
 *     });
 *   },
 * })));
 * ```
 */
export function sensitiveContext(factory: RevealContextFactory): RequestHandler {
  return (req, _res, next) => {
    const context = factory(req);

    if (context === undefined) {
      next();
      return;
    }

    // The rest of the chain runs inside the callback, not after it: the scope
    // covers whatever `next()` synchronously enters, which is every handler
    // Express has left to run.
    withRevealContext(context, () => {
      next();
    });
  };
}
