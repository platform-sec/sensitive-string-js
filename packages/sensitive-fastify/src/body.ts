import {
  checkSensitiveFieldsWrapped,
  wrapSensitiveByPath,
} from '@platform-sec/sensitive-string-core';
import type { FastifyContextConfig, FastifyInstance } from 'fastify';
import { compilePathFields, mergeFields, type CompiledFields } from './fields.js';

/**
 * Install the instance-level `preHandler` hook that applies field maps.
 *
 * The hook is installed even when the registration carries no `body` option,
 * because a route's own `config.sensitive.body` has to be honoured by any
 * registration whose scope contains that route.
 *
 * `onRoute` would be the tidier place to attach a route-level hook, and it
 * misses routes: it fires synchronously at route registration, so routes
 * declared before the plugin, and routes declared after a `register()` that was
 * not awaited in the same scope, are never seen. An instance-level hook reaches
 * all of them, because Fastify resolves a route's hooks when its scope finishes
 * loading rather than when the route is declared.
 *
 * The cost of that choice is one property read and one cache lookup per request
 * on a route that declares nothing. The cache is keyed on
 * `request.routeOptions.config`, which is one stable object per route, so a
 * merged map is built once per route rather than once per request.
 *
 * The position is the last instance-level one before the handler, so validators
 * and anything else reading the body as plain strings still see strings.
 *
 * @param fastify - The instance to hook, already scoped by fastify-plugin
 * @param scopeFields - The registration's `body` option, compiled
 */
export function installBodyWrapping(
  fastify: FastifyInstance,
  scopeFields: CompiledFields | undefined
): void {
  const perRoute = new WeakMap<object, CompiledFields | null>();

  // The callback form rather than an async one: the work is synchronous, so a
  // promise per request would buy nothing. Fastify calls a hook inside a
  // try/catch, so a malformed route config still reaches the error handler.
  fastify.addHook('preHandler', (request, _reply, done) => {
    const body: unknown = request.body;

    // A GET, a POST with no payload, and a body that parsed to a primitive all
    // land here. None is an error and none has anything to wrap.
    if (body === null || typeof body !== 'object') {
      done();
      return;
    }

    const fields = fieldsFor(request.routeOptions.config, scopeFields, perRoute);

    if (fields === null) {
      done();
      return;
    }

    // An outer registration may already have wrapped these paths, and a body
    // may simply not carry them. Either way there is nothing to clone.
    if (checkSensitiveFieldsWrapped(body, fields).allWrapped) {
      done();
      return;
    }

    request.body = wrapSensitiveByPath(body, fields);
    done();
  });
}

/**
 * The merged map for one route, computed once and cached on its config object.
 *
 * `null` means the route declares nothing, from either side.
 */
function fieldsFor(
  config: FastifyContextConfig | undefined,
  scopeFields: CompiledFields | undefined,
  cache: WeakMap<object, CompiledFields | null>
): CompiledFields | null {
  // `request.routeOptions.config` is always an object on a matched route. A 404
  // has no route config to key a cache on, and no route config to read.
  if (config === undefined || config === null) {
    return scopeFields ?? null;
  }

  const cached = cache.get(config);

  if (cached !== undefined) {
    return cached;
  }

  const declared = config.sensitive?.body;
  const merged = mergeFields(
    scopeFields,
    declared === undefined ? undefined : compilePathFields(declared, 'route config.sensitive.body')
  );

  cache.set(config, merged);

  return merged;
}
