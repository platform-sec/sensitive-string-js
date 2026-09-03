/**
 * @platform-sec/sensitive-string-fastify
 *
 * Fastify integration for SensitiveString: a JSON Schema keyword wraps a
 * property during validation, a field map covers routes without one, sensitive
 * headers are extracted without touching `request.headers`, the reveal context
 * is established once per request, and response bodies are redacted on the way
 * out.
 *
 * @example
 * ```ts
 * import Fastify from 'fastify';
 * import {
 *   sensitiveKeyword,
 *   sensitivePlugin,
 * } from '@platform-sec/sensitive-string-fastify';
 *
 * // 1. The keyword goes into the constructor: Ajv is built with the instance,
 * //    and a plugin cannot add a keyword afterwards.
 * const fastify = Fastify({
 *   logger: true,
 *   ajv: { customOptions: { keywords: [sensitiveKeyword] } },
 * });
 *
 * // 2. Context, headers, and the response filter for the whole application
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
 * // 3. A schema-first route: the keyword wraps during validation
 * fastify.post('/api/auth/login', {
 *   schema: {
 *     body: {
 *       type: 'object',
 *       required: ['email', 'password'],
 *       properties: {
 *         email: { type: 'string', format: 'email', sensitive: { klass: 'sensitive' } },
 *         password: { type: 'string', minLength: 8, sensitive: { klass: 'credential' } },
 *       },
 *     },
 *   },
 * }, async (request) => {
 *   request.log.info({ body: request.body });
 *   // {"body":{"email":"[REDACTED:sensitive]","password":"[REDACTED:credential]"}}
 *   return { ok: true };
 * });
 *
 * // 4. Schema-less routes under a prefix: the field map, scoped by encapsulation
 * await fastify.register(async function webhooks(instance) {
 *   await instance.register(sensitivePlugin, {
 *     body: { 'additionalData.hmacSignature': 'credential' },
 *   });
 *   instance.post('/notification', handleNotification);
 * }, { prefix: '/webhooks/psp' });
 *
 * await fastify.listen({ port: 3000 });
 * ```
 *
 * The keyword needs no plugin registration, and the plugin needs no keyword.
 * Applications on a validator compiler other than the default Ajv one, a
 * TypeBox or Zod type provider among them, use the `body` option or their schema
 * library's own transform; the keyword is simply absent there.
 *
 * @packageDocumentation
 */

// Types
export type {
  ContextHookName,
  RevealContextFactory,
  SensitivePluginOptions,
  SensitiveRequest,
  SensitiveRouteConfig,
} from './types.js';
export type {
  SensitiveKeywordContext,
  SensitiveKeywordDefinition,
  SensitiveKeywordSchema,
} from './keyword.js';

// The plugin, and the Ajv keyword it does not install
export { sensitivePlugin } from './plugin.js';
export { sensitiveKeyword } from './keyword.js';
