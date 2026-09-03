import { wrapSensitiveByPath } from '@platform-sec/sensitive-string-core';
import type { RequestHandler } from 'express';
import { compilePathFields } from './fields.js';
import type { SensitiveBodyOptions } from './types.js';

/** What a body parser produces without being told otherwise. */
const DEFAULT_CONTENT_TYPES = ['application/json', 'application/x-www-form-urlencoded'];

/**
 * Replace configured `req.body` fields with `SensitiveString` instances.
 *
 * This parses nothing. It reads the body a parser already produced, so it must
 * be registered after `express.json()` or `express.urlencoded()`, and after
 * anything that reads the body as plain strings: schema validators, a
 * passport-local strategy handing `req.body.password` to `bcrypt.compare`, and
 * CSRF middleware reading `req.body._csrf` all break on an object where they
 * expected a string. Anything that *logs* the body wants to run after this.
 *
 * The wrap is core's `wrapSensitiveByPath`, so this middleware inherits its
 * behaviour: it returns a clone rather than mutating, leaves an existing
 * `SensitiveString` alone (applying the middleware twice is a no-op the second
 * time), skips a non-string value instead of coercing it, and refuses to follow
 * a `__proto__`, `constructor`, or `prototype` path segment.
 *
 * Because the wrap is a clone, the property is reassigned and the object that
 * was there before survives holding the raw strings. Code that captured a
 * reference to `req.body` before this middleware ran still reads plain
 * credentials out of it afterwards, which is the sharp edge behind the ordering
 * rule above: a logger registered earlier that keeps the reference and prints it
 * from a `finish` listener prints the secret. Mutating in place would close
 * that, at the cost of a second walk through the most security-sensitive
 * function in core, and measurement put the clone at roughly the cost of the
 * `JSON.parse` body-parser already performed on the same bytes, so the clone
 * stands and the ordering rule carries the weight.
 *
 * @param options - Field map and, optionally, the content types to process
 * @returns Express middleware
 * @throws TypeError If the field map is malformed, at construction
 *
 * @example
 * ```ts
 * app.use(express.json());
 * app.use('/api/auth', sensitiveBody({
 *   fields: {
 *     password: 'credential',
 *     email: { klass: 'sensitive', label: 'email' },
 *     'creditCard.number': 'credential',
 *   },
 * }));
 *
 * app.post('/api/auth/login', (req, res) => {
 *   console.log(req.body);
 *   // { email: SensitiveString<sensitive:email> { [REDACTED:sensitive] }, ... }
 *   const password = req.body.password.reveal();
 * });
 * ```
 */
export function sensitiveBody(options: SensitiveBodyOptions): RequestHandler {
  const fields = compilePathFields(options.fields, 'sensitiveBody');
  const contentTypes = options.contentTypes ?? DEFAULT_CONTENT_TYPES;

  return (req, _res, next) => {
    const body: unknown = req.body;

    // Express 5 leaves `req.body` undefined when nothing was parsed, Express 4
    // leaves it `{}`. Neither is an error, and neither has anything to wrap.
    if (body === null || typeof body !== 'object') {
      next();
      return;
    }

    // `req.is()` answers false for a mismatch and null for a request carrying
    // no body at all; both mean there is nothing this middleware should touch.
    if (!req.is(contentTypes)) {
      next();
      return;
    }

    req.body = wrapSensitiveByPath(body, fields);
    next();
  };
}
