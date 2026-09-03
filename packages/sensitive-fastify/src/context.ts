import { withRevealContext } from '@platform-sec/sensitive-string-core';
import type {
  FastifyInstance,
  FastifyReply,
  FastifyRequest,
  HookHandlerDoneFunction,
} from 'fastify';
import type { ContextHookName, RevealContextFactory } from './types.js';

/** The positions `contextHook` accepts. */
export const CONTEXT_HOOKS: readonly ContextHookName[] = [
  'onRequest',
  'preValidation',
  'preHandler',
];

/**
 * Install the hook that establishes the reveal context for a request.
 *
 * The hook is the callback form, and the callback is what carries the scope:
 * Fastify continues the lifecycle synchronously from `done()`, so every later
 * hook, the handler, each continuation after an `await` in it, `preSerialization`,
 * `onSend`, `onResponse`, and the error handler all run inside the
 * `AsyncLocalStorage` scope this opens. An async hook cannot do it, because
 * `AsyncLocalStorage.run` inside one ends when the hook returns and Fastify
 * continues outside it. This is the idiom `@fastify/request-context` uses.
 *
 * What does not inherit the context: hooks registered before this plugin in the
 * same scope, and hooks in a parent scope, both of which run first.
 *
 * A factory returning `undefined` establishes no context for that request
 * rather than an empty one, so a policy whose `checkRevealAllowed` rejects a
 * missing context still rejects.
 *
 * @param fastify - The instance to hook, already scoped by fastify-plugin
 * @param factory - Builds the context from the request, once per request
 * @param hook - Lifecycle position, defaulting to `onRequest` at the call site
 */
export function installContextHook(
  fastify: FastifyInstance,
  factory: RevealContextFactory,
  hook: ContextHookName
): void {
  const handler = (
    request: FastifyRequest,
    _reply: FastifyReply,
    done: HookHandlerDoneFunction
  ): void => {
    const context = factory(request);

    if (context === undefined) {
      done();
      return;
    }

    withRevealContext(context, () => {
      done();
    });
  };

  // One `addHook` call per position rather than one with a union argument:
  // Fastify types the handler off the hook name, and a union name gives it
  // nothing to infer from.
  switch (hook) {
    case 'onRequest':
      fastify.addHook('onRequest', handler);
      break;
    case 'preValidation':
      fastify.addHook('preValidation', handler);
      break;
    case 'preHandler':
      fastify.addHook('preHandler', handler);
      break;
  }
}
