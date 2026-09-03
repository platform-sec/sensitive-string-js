/**
 * @platform-sec/sensitive-string-express
 *
 * Express integration for SensitiveString: configured body fields are wrapped
 * at the middleware layer, sensitive headers are extracted without touching
 * `req.headers`, the reveal context is established once per request, response
 * bodies are redacted on the way out, and a parse error stops carrying the raw
 * body it failed on.
 *
 * @example
 * ```ts
 * import express from 'express';
 * import {
 *   sensitiveBody,
 *   sensitiveContext,
 *   sensitiveHeaders,
 *   sensitiveResponseFilter,
 *   stripParseErrorBody,
 * } from '@platform-sec/sensitive-string-express';
 *
 * const app = express();
 *
 * // 1. Parse, and keep parse failures from carrying the raw body
 * app.use(express.json());
 * app.use(stripParseErrorBody());
 *
 * // 2. Reveal context for everything below
 * app.use(sensitiveContext((req) => ({
 *   name: `${req.method} ${req.path}`,
 *   tags: { requestId: req.headers['x-request-id'] },
 *   auditReveal: (value, details) => audit.record(value, details, req),
 * })));
 *
 * // 3. Headers, extracted without touching req.headers
 * app.use(sensitiveHeaders({ fields: { authorization: 'credential' } }));
 *
 * // 4. Response redaction
 * app.use(sensitiveResponseFilter());
 *
 * // 5. Body wrapping, mounted where the sensitive routes live
 * app.use('/api/auth', sensitiveBody({
 *   fields: { password: 'credential', email: 'sensitive' },
 * }));
 *
 * app.post('/api/auth/login', async (req, res) => {
 *   const { email, password } = req.body; // both already SensitiveString
 *   const user = await authenticateUser(email, password);
 *   res.json({ success: true, userId: user.id });
 * });
 * ```
 *
 * `sensitiveBody` runs after body parsing and after anything that reads the
 * body as plain strings: schema validators, passport-local, and CSRF middleware
 * reading `req.body._csrf`. Anything that logs the body wants to run after it.
 * The other four have no ordering constraints, because none of them changes
 * what the framework or another middleware reads.
 *
 * @packageDocumentation
 */

// Types
export type {
  RevealContextFactory,
  SensitiveBodyOptions,
  SensitiveHeadersOptions,
  SensitiveRequest,
} from './types.js';

// Middleware
export { sensitiveBody } from './body.js';
export { sensitiveHeaders } from './headers.js';
export { sensitiveContext } from './context.js';
export { sensitiveResponseFilter } from './response-filter.js';
export { stripParseErrorBody } from './parse-error.js';
