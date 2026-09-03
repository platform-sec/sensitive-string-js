import { redactCopy } from '@platform-sec/sensitive-string-core';
import type { RequestHandler, Response } from 'express';

/** Marks a response whose `json` and `jsonp` this package already replaced. */
const PATCHED = Symbol.for('@platform-sec/sensitive-string-express.responseFilter');

type JsonSend = (body?: unknown) => Response;

/**
 * Walk every JSON response body and redact what it carries.
 *
 * This is defense in depth. `toJSON()` already redacts a `SensitiveString`
 * whenever `JSON.stringify` reaches it, and the filter earns its place for the
 * two cases that method cannot cover:
 *
 * - A `serialize()` result. It carries the raw value under a
 *   `__sensitive: true` marker for service-to-service transport, and
 *   `JSON.stringify` emits it faithfully. In a client response that is a leak;
 *   the walk replaces it with `[REDACTED:<klass>]`.
 * - A class instance, such as an ORM entity or a DTO, whose own `toJSON()` or
 *   a serializer downstream decides the shape.
 *
 * `res.send(object)` delegates to `res.json` in Express and is covered too.
 * `res.send(string)` is not touched: a revealed value is a plain string, and
 * nothing distinguishes it from any other text the handler meant to send.
 * `res.json({ email: user.email.reveal() })` sends the email, by design.
 *
 * The walk is core's `redactCopy`, the same one the NestJS
 * `SensitiveResponseInterceptor` uses. It never mutates the body, since an
 * entity may be shared with an ORM identity map; it keeps each object's
 * prototype, so an entity `toJSON()` still runs; and it memoizes copies, so a
 * reference appearing twice stays one shared reference while a genuine cycle
 * produces a cyclic copy that fails at `JSON.stringify` exactly as the original
 * would.
 *
 * @returns Express middleware
 *
 * @example
 * ```ts
 * app.use(sensitiveResponseFilter());
 *
 * app.get('/api/user/profile', async (req, res) => {
 *   const user = await db.getUser(req.params.id);
 *   res.json({
 *     email: user.email,             // -> '[REDACTED:sensitive]'
 *     token: user.token.serialize(), // -> '[REDACTED:credential]'
 *   });
 * });
 * ```
 */
export function sensitiveResponseFilter(): RequestHandler {
  return (_req, res, next) => {
    const marked = res as Response & { [PATCHED]?: true };

    // Mounting the filter globally and again on a router would otherwise walk
    // every body twice, for the same result at twice the cost.
    if (marked[PATCHED] === true) {
      next();
      return;
    }

    marked[PATCHED] = true;

    const json = res.json.bind(res) as JsonSend;
    const jsonp = res.jsonp.bind(res) as JsonSend;

    res.json = ((body?: unknown) => json(redactCopy(body))) as Response['json'];
    res.jsonp = ((body?: unknown) => jsonp(redactCopy(body))) as Response['jsonp'];

    next();
  };
}
