/**
 * Which `dd-trace` plugins offer a hook, which of them this package installs
 * into, and the reader that notices when that stops being true.
 *
 * The seam inventory of the Sentry package does not transfer as a type-level
 * exhaustiveness check, because there is no `before${string}` family to
 * `Extract` over. The equivalent here reads the shipped `index.d.ts` and fails
 * when a plugin gains a `hooks` option this package does not know about. That
 * is weaker than a compile-time constraint, since it is a runtime read of a
 * declaration file, and it catches the same failure: a plugin gaining a hook
 * in a minor release and this package silently not covering it.
 *
 * ## The count is 19, not 8
 *
 * Eight interfaces in `dd-trace` 6.14.0 declare `hooks` directly:
 * `HttpServer`, `HttpClient`, `apollo`, `aws_sdk`, `elasticsearch`, `graphql`,
 * `http` and `next`, plus `sharedb`. Counting only those misses the ones that
 * inherit, and the ones that inherit are the ones most deployments actually
 * run: `express`, `fastify`, `koa`, `connect`, `hapi`, `hono`, `restify` and
 * `microgateway_core` all extend `HttpServer`, and `fetch` and `undici` extend
 * `HttpClient`.
 *
 * That is not a naming detail. Measured on `dd-trace` 6.14.0 with
 * `headerTags: ['authorization', 'cookie', 'x-api-key']` and an express
 * application, installing a hook on `http` alone:
 *
 * ```
 * express.request  http.request.headers.authorization  "Bearer LEAKED_SECRET_abc123xyz"
 * http.request     http.request.headers.authorization  "[SCRUBBED]"
 * ```
 *
 * The server span is named `express.request` and carries the raw header. The
 * mechanism is `web.js`'s `setFramework`, which calls `web.setConfig(req,
 * config)` and replaces the request's whole plugin config with the framework
 * plugin's, hooks and header list included, after `web.startSpan` has already
 * run. So a framework-served request runs the **framework** plugin's hook, and
 * covering `http` does not cover it. With `express` covered too, both spans
 * arrive scrubbed.
 *
 * Every one of those framework plugins takes the same hook shape over the same
 * tag names, so covering them is one more entry in a list rather than a new
 * hook body.
 */

/** One plugin this package installs a hook into. */
export interface CoveredPlugin {
  /** The plugin id, as `tracer.use()` takes it. */
  readonly plugin: string;
  /** The hook names on that plugin this package composes into. */
  readonly hooks: readonly string[];
  /** Why it is covered, for the README and for the seam test's failure text. */
  readonly note: string;
}

/**
 * The plugins this package installs into.
 *
 * All of them are request-shaped, which is what makes one hook body cover
 * them: each writes `http.request.headers.*` and `http.response.headers.*`
 * onto a span and each takes a `hooks.request` that runs after that tagging
 * and before formatting.
 */
export const COVERED_PLUGINS: readonly CoveredPlugin[] = [
  { plugin: 'http', hooks: ['request'], note: 'the core server and client spans' },
  { plugin: 'undici', hooks: ['request'], note: 'the undici client path' },
  { plugin: 'fetch', hooks: ['request'], note: 'global fetch, which is undici underneath' },
  { plugin: 'next', hooks: ['request'], note: 'the Next.js request span' },
  { plugin: 'express', hooks: ['request'], note: 'replaces the http config per request' },
  { plugin: 'fastify', hooks: ['request'], note: 'replaces the http config per request' },
  { plugin: 'koa', hooks: ['request'], note: 'replaces the http config per request' },
  { plugin: 'connect', hooks: ['request'], note: 'replaces the http config per request' },
  { plugin: 'hapi', hooks: ['request'], note: 'replaces the http config per request' },
  { plugin: 'hono', hooks: ['request'], note: 'replaces the http config per request' },
  { plugin: 'restify', hooks: ['request'], note: 'replaces the http config per request' },
  {
    plugin: 'microgateway-core',
    hooks: ['request'],
    note: 'replaces the http config per request',
  },
];

/**
 * Plugins that declare a hook and this package deliberately does not install
 * into, with the reason.
 *
 * The seam test reads both lists. A plugin in neither is a new seam, and that
 * is the failure the test exists for. A plugin here is a decision somebody
 * wrote down.
 */
export const DEFERRED_PLUGINS: Readonly<Record<string, string>> = {
  apollo: 'GraphQL variable tags. Covered after the MVP, per the design Q3',
  'aws-sdk': 'response-derived tags. Covered after the MVP, per the design Q3',
  elasticsearch: 'elasticsearch.body and .params. Covered after the MVP, per the design Q3',
  opensearch: 'the same tags as elasticsearch, whose interface it extends',
  graphql: 'variable tags, only written when DD_TRACE_GRAPHQL_VARIABLES is on',
  sharedb: 'request and reply tags. Covered after the MVP, per the design Q3',
  web: 'not a module a user requires; the shared base every HttpServer plugin runs through',
};

/** Every plugin id this package has an opinion about. */
export function knownPlugins(): Set<string> {
  return new Set([
    ...COVERED_PLUGINS.map((entry) => entry.plugin),
    ...Object.keys(DEFERRED_PLUGINS),
  ]);
}
