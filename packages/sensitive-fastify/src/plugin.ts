import type { FastifyInstance, FastifyPluginAsync, FastifySchema } from 'fastify';
import fp from 'fastify-plugin';
import { installBodyWrapping } from './body.js';
import { CONTEXT_HOOKS, installContextHook } from './context.js';
import { compileNameFields, compilePathFields } from './fields.js';
import { installHeaderExtraction, sensitiveGetter } from './headers.js';
import { schemaUsesKeyword } from './keyword.js';
import { installResponseFilter } from './response-filter.js';
import type { SensitivePluginOptions } from './types.js';

/** The name fastify-plugin registers under, and the prefix on its own errors. */
const NAME = '@platform-sec/sensitive-string-fastify';

// The async form, though nothing here awaits: it is what turns an option error
// into a rejected `register()`. Measured, a synchronous throw from the callback
// form escapes avvio as an uncaught exception instead.
const plugin: FastifyPluginAsync<SensitivePluginOptions> = async (fastify, options) => {
  const bodyFields =
    options.body === undefined
      ? undefined
      : compilePathFields(options.body, 'sensitivePlugin.body');
  const headerFields =
    options.headers === undefined
      ? undefined
      : compileNameFields(options.headers, 'sensitivePlugin.headers');
  const contextHook = options.contextHook ?? 'onRequest';

  if (!CONTEXT_HOOKS.includes(contextHook)) {
    throw new TypeError(
      `sensitivePlugin.contextHook must be one of ${CONTEXT_HOOKS.join(', ')}; ` +
        `received '${String(contextHook)}'`
    );
  }

  if (options.context !== undefined && typeof options.context !== 'function') {
    throw new TypeError('sensitivePlugin.context must be a function returning a RevealContext');
  }

  // Checked rather than coerced: a truthy non-boolean would otherwise mean no
  // response filter at all, which is a silent loss of a redaction layer.
  if (options.responseFilter !== undefined && typeof options.responseFilter !== 'boolean') {
    throw new TypeError(
      `sensitivePlugin.responseFilter must be a boolean when given; received ${typeof options.responseFilter}`
    );
  }

  // `decorateRequest` throws FST_ERR_DEC_ALREADY_PRESENT on a second call in the
  // same scope, and a root registration plus a child registration is the
  // expected pattern.
  if (!fastify.hasRequestDecorator('sensitive')) {
    fastify.decorateRequest('sensitive', { getter: sensitiveGetter });
  }

  refuseKeywordInHeaderSchemas(fastify);

  if (options.context !== undefined) {
    installContextHook(fastify, options.context, contextHook);
  }

  if (headerFields !== undefined) {
    installHeaderExtraction(fastify, headerFields);
  }

  // Installed unconditionally: a route's own `config.sensitive.body` has to be
  // honoured by any registration whose scope contains the route, whether or not
  // that registration declared a scope-wide map.
  installBodyWrapping(fastify, bodyFields);

  if (options.responseFilter === true) {
    installResponseFilter(fastify);
  }
};

/**
 * Refuse a route whose headers schema uses the `sensitive` keyword.
 *
 * The keyword replaces the value in its parent object, and for a headers schema
 * that parent is the raw Node headers object, which Fastify itself reads as
 * strings. The route would then serve requests with
 * `typeof request.headers['x-api-key'] === 'object'`.
 *
 * The guard is best effort by construction: `onRoute` fires at route
 * registration, so it sees only routes declared after this plugin loaded. The
 * rule is documented for the rest.
 */
function refuseKeywordInHeaderSchemas(fastify: FastifyInstance): void {
  fastify.addHook('onRoute', (route) => {
    const schema: FastifySchema | undefined = route.schema;

    if (
      schema === undefined ||
      !schemaUsesKeyword(schema.headers, (ref) => resolve(fastify, ref))
    ) {
      return;
    }

    throw new Error(
      `${NAME}: the 'sensitive' keyword is not supported in a headers schema ` +
        `(${String(route.method)} ${route.url}). It would replace the value in the raw Node ` +
        "headers object, which Fastify reads as strings. Use the plugin's headers option instead."
    );
  });
}

/** `fastify.getSchema` throws for an unknown id in some versions; absent is not a use. */
function resolve(fastify: FastifyInstance, ref: string): unknown {
  try {
    return fastify.getSchema(ref);
  } catch {
    return undefined;
  }
}

/**
 * Fastify plugin: reveal context, header extraction, body field maps, and
 * response redaction.
 *
 * Wrapped with `fastify-plugin`, so what it installs applies to the scope it is
 * registered in and to every child of that scope. Registering it at the root
 * covers the application; registering it inside a plugin covers that plugin's
 * routes. Without the wrapper its hooks would live in its own encapsulation
 * context, which contains no user routes, and would reach nothing at all.
 *
 * Registering it twice, once at the root for context and responses and once in a
 * child for a field map, is the expected pattern and is safe: each registration
 * installs only the hooks its options ask for, the request decorator is added
 * once per scope, and a field an outer registration already wrapped is left
 * alone by an inner one.
 *
 * Where each piece runs:
 *
 * | Position | This plugin | Consequence |
 * |---|---|---|
 * | `onRequest` | context (default), header extraction | both see headers, neither sees a body |
 * | validation | the `sensitive` keyword, per property | everything later sees instances for keyword-declared properties |
 * | `preHandler`, instance level | field map and route config | instance hooks registered earlier see strings, later ones see instances |
 * | `preHandler`, route level | | runs after every instance-level hook, so it sees instances |
 * | `preSerialization` | response filter | not run for strings, buffers, streams, or errors |
 *
 * @throws TypeError If an option is malformed, at registration
 *
 * @example
 * ```ts
 * const fastify = Fastify({
 *   ajv: { customOptions: { keywords: [sensitiveKeyword] } },
 * });
 *
 * await fastify.register(sensitivePlugin, {
 *   context: (request) => ({
 *     name: `${request.method} ${request.routeOptions.url}`,
 *     tags: { requestId: request.id },
 *     auditReveal: (value, details) => audit.record(value, details, request),
 *   }),
 *   headers: { authorization: 'credential' },
 *   responseFilter: true,
 * });
 *
 * // Schema-less routes under a prefix, scoped by encapsulation
 * await fastify.register(async function webhooks(instance) {
 *   await instance.register(sensitivePlugin, {
 *     body: { 'additionalData.hmacSignature': 'credential' },
 *   });
 *   instance.post('/notification', handleNotification);
 * }, { prefix: '/webhooks/psp' });
 * ```
 */
export const sensitivePlugin = fp(plugin, {
  name: NAME,
  fastify: '5.x',
});
