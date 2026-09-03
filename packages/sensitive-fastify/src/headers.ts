import { SensitiveString, type SensitivityClass } from '@platform-sec/sensitive-string-core';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { CompiledFields } from './fields.js';
import type { SensitiveRequest } from './types.js';

/** One compiled header: the lower-cased name, its class, and its label. */
interface CompiledHeader {
  name: string;
  klass: SensitivityClass;
  label: string;
}

/**
 * Extracted headers, per request.
 *
 * A `WeakMap` rather than a property on the request, because Fastify 5 refuses
 * a request decorator holding a reference type (`FST_ERR_DEC_REFERENCE_TYPE`):
 * the value would be shared by every request. The decorator is a getter over
 * this map instead, which also costs nothing on a route that extracts nothing.
 */
const STORE = new WeakMap<FastifyRequest, SensitiveRequest>();

/** What `request.sensitive` reads on a route no `headers` option applies to. */
const EMPTY: SensitiveRequest = Object.freeze({
  headers: Object.freeze(Object.create(null) as SensitiveRequest['headers']),
});

/** The getter behind the `sensitive` request decorator. */
export function sensitiveGetter(this: FastifyRequest): SensitiveRequest {
  return STORE.get(this) ?? EMPTY;
}

/**
 * Install the `onRequest` hook that extracts configured headers.
 *
 * `request.headers` is left byte-identical. Fastify reads it itself, and so does
 * every authentication and CORS plugin: replacing `authorization` with an object
 * breaks anything that calls `startsWith('Bearer ')` on it. A wrapped copy
 * alongside the original is the choice the NestJS package makes for headers and
 * the Express package makes on `req.sensitive.headers`.
 *
 * The limitation that follows is worth stating rather than hiding: code that
 * logs `request.headers` still sees the raw `authorization` value. Fastify's own
 * request log line carries no headers, and closing the rest is a logger
 * concern, such as pino's `redact: ['req.headers.authorization']`.
 *
 * A header that reaches Node as an array contributes its first element. An
 * absent or empty header becomes `null` through `SensitiveString.fromOptional`,
 * so an empty header is not mistaken for a credential of length zero.
 *
 * @param fastify - The instance to hook, already scoped by fastify-plugin
 * @param fields - The registration's `headers` option, compiled
 */
export function installHeaderExtraction(fastify: FastifyInstance, fields: CompiledFields): void {
  const headers: CompiledHeader[] = Object.entries(fields).map(([name, entry]) => ({
    name,
    klass: entry.klass,
    label: entry.label,
  }));

  fastify.addHook('onRequest', (request, _reply, done) => {
    // Null prototype, so a header literally named `constructor` or `__proto__`
    // is an ordinary key rather than a collision with `Object.prototype`.
    const extracted = Object.create(null) as Record<
      string,
      SensitiveString<SensitivityClass> | null
    >;

    // An outer registration's entries are kept: a root registration and a child
    // registration both contribute headers on the child's routes.
    Object.assign(extracted, STORE.get(request)?.headers);

    for (const { name, klass, label } of headers) {
      extracted[name] = SensitiveString.fromOptional(
        firstValue(request.headers[name]),
        klass,
        label
      );
    }

    STORE.set(request, Object.freeze({ headers: Object.freeze(extracted) }));

    done();
  });
}

/** Node gives some repeated headers as an array; the first element is the value. */
function firstValue(raw: string | string[] | undefined): string | undefined {
  return Array.isArray(raw) ? raw[0] : raw;
}
