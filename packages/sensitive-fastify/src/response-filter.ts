import { redactCopy } from '@platform-sec/sensitive-string-core';
import type { FastifyInstance } from 'fastify';

/**
 * Install the `preSerialization` hook that redacts a response body.
 *
 * This is defense in depth. Both of Fastify's serializers already redact a
 * `SensitiveString` on their own: the default `JSON.stringify` path honours
 * `toJSON()`, and the response-schema path (`fast-json-stringify`) calls
 * `toString()` for a string-typed property and `toJSON()` for an untyped one.
 * The hook earns its place for the two cases neither can cover:
 *
 * - A `serialize()` result. It carries the raw value under a `__sensitive: true`
 *   marker for service-to-service transport, and every serializer emits it
 *   faithfully. In a client response that is a leak; the walk replaces it with
 *   the class's redaction.
 * - A class instance, such as an ORM entity or a DTO, whose own `toJSON()` or a
 *   serializer downstream decides the shape.
 *
 * The walk is core's `redactCopy`, the same one the NestJS
 * `SensitiveResponseInterceptor` uses. It never mutates the body, since an
 * entity may be shared with an ORM identity map; it keeps each object's
 * prototype, so an entity `toJSON()` still runs; and it memoizes copies, so a
 * reference appearing twice stays one shared reference while a genuine cycle
 * produces a cyclic copy that fails at serialization exactly as the original
 * would.
 *
 * What it does not cover: Fastify runs no `preSerialization` hook for a string,
 * `Buffer`, or stream payload, or for an error reply. An error reply is
 * serialized from `statusCode`, `code`, `error`, and `message`, and a message
 * that interpolates an instance carries the redaction marker rather than the
 * value.
 *
 * What it cannot do is recover a value already revealed into a plain string.
 * `{ email: user.email.reveal() }` sends the email, by design.
 *
 * A registration at the root and another in a child both walk the child's
 * responses. The second walk sees an already-redacted copy, so it changes
 * nothing and costs one clone; skipping it would instead lose whatever a
 * `preSerialization` hook between the two added.
 *
 * @param fastify - The instance to hook, already scoped by fastify-plugin
 */
export function installResponseFilter(fastify: FastifyInstance): void {
  fastify.addHook('preSerialization', (_request, _reply, payload: unknown, done) => {
    done(null, redactCopy(payload));
  });
}
