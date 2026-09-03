import { SensitiveString, type SensitivityClass } from '@platform-sec/sensitive-string-core';
import type { Request, RequestHandler } from 'express';
import { compileNameFields } from './fields.js';
import type { SensitiveHeadersOptions, SensitiveRequest } from './types.js';

interface CompiledHeader {
  name: string;
  klass: SensitivityClass;
  label: string;
}

/**
 * Put wrapped copies of configured headers on `req.sensitive.headers`.
 *
 * `req.headers` is left byte-identical. Express itself reads it through
 * `req.get()`, `req.is()`, and `req.fresh`, and so does every authentication
 * and CORS middleware; replacing `authorization` with an object breaks anything
 * that calls `startsWith('Bearer ')` on it. A wrapped copy alongside the
 * original is the same choice the NestJS package makes for headers, query, and
 * params.
 *
 * The limitation that follows is worth stating rather than hiding: a request
 * logger that dumps `req.headers` still sees the raw `authorization` value.
 * That is a logger configuration concern, such as pino's
 * `redact: ['req.headers.authorization']`, and this middleware does not close
 * it.
 *
 * Header names are matched case-insensitively and read back in lower case,
 * which is how Node stores them. A header that reaches Node as an array
 * contributes its first element. An absent or empty header becomes `null`
 * through `SensitiveString.fromOptional`, so an empty header is not mistaken
 * for a credential of length zero.
 *
 * @param options - The header field map
 * @returns Express middleware
 * @throws TypeError If the field map is malformed, at construction
 *
 * @example
 * ```ts
 * app.use(sensitiveHeaders({
 *   fields: {
 *     authorization: 'credential',
 *     'x-api-key': { klass: 'credential', label: 'api_key' },
 *   },
 * }));
 *
 * app.get('/api/data', (req, res) => {
 *   const auth = req.sensitive.headers['authorization']; // SensitiveString | null
 *   // req.headers.authorization is still the plain string
 * });
 * ```
 */
export function sensitiveHeaders(options: SensitiveHeadersOptions): RequestHandler {
  const headers: CompiledHeader[] = Object.entries(
    compileNameFields(options.fields, 'sensitiveHeaders')
  ).map(([name, entry]) => ({ name, klass: entry.klass, label: entry.label }));

  return (req, _res, next) => {
    const container = ensureSensitive(req);

    for (const { name, klass, label } of headers) {
      container.headers[name] = SensitiveString.fromOptional(
        firstValue(req.headers[name]),
        klass,
        label
      );
    }

    next();
  };
}

/**
 * The request's `sensitive` container, created on first use.
 *
 * Reusing an existing container matters when the middleware is mounted more
 * than once, globally and again on a router: the second pass must add to what
 * the first produced rather than discard it.
 */
function ensureSensitive(req: Request): SensitiveRequest {
  const existing: SensitiveRequest | undefined = req.sensitive;

  if (existing !== undefined && existing !== null) {
    return existing;
  }

  // Null prototype, so a header literally named `constructor` or `__proto__`
  // is an ordinary key rather than a collision with `Object.prototype`.
  const created: SensitiveRequest = {
    headers: Object.create(null) as SensitiveRequest['headers'],
  };

  req.sensitive = created;

  return created;
}

/** Node gives some repeated headers as an array; the first element is the value. */
function firstValue(raw: string | string[] | undefined): string | undefined {
  return Array.isArray(raw) ? raw[0] : raw;
}
