/**
 * @platform-sec/sensitive-string-datadog
 *
 * Span tag scrubbing for `dd-trace`, at the plugin hooks the agent actually
 * offers, plus the two lists a hook cannot reach.
 *
 * Unlike an error tracker, this agent does not leak at stock defaults.
 * Measured on `dd-trace` 6.14.0, Node 22.15.0, one inbound
 * `POST /pay?token=<canary>&page=2` carrying `authorization`, `cookie`,
 * `x-api-key` and a JSON body with a `password` field, the whole server span
 * was three tags:
 *
 * ```
 * http.url          "http://127.0.0.1:38951/pay?<redacted>&page=2"
 * http.method       "POST"
 * http.status_code  "500"
 * ```
 *
 * No header, no body, and the query obfuscated in place so the route survived.
 *
 * The leak is one configuration line away, and the line is one a competent
 * operator has a reason to write. With `headerTags: ['authorization',
 * 'cookie', 'x-api-key']`:
 *
 * ```
 * web.request   http.request.headers.authorization  "Bearer LEAKED_SECRET_abc123xyz"
 * web.request   http.request.headers.cookie         "session=LEAKED_SECRET_abc123xyz"
 * http.request  http.request.headers.authorization  "Bearer LEAKED_SECRET_abc123xyz"
 * ```
 *
 * On the client span as well as the server one, so turning header capture on
 * to debug inbound traffic also starts transmitting the `authorization` header
 * of every outbound call the service makes.
 *
 * There is a second leak that has nothing to do with headers, and it is the
 * one case in this row where the structural walk is the only defence rather
 * than defence in depth. Measured, `span.setTag('probe', secret.serialize())`:
 *
 * ```
 * probe.klass  "credential"
 * probe.value  "LEAKED_SECRET_abc123xyz"
 * probe.label  "tok"
 * ```
 *
 * Nothing on that path calls `toJSON()`. `addMixedTag` flattens an object one
 * level with `Object.entries`, and one level is exactly enough to find the
 * `value` key of a wire-format object. The same flattening turns a plain
 * `SensitiveString` into `probe.klass` and `probe.label`, so the marker
 * convention the rest of this library depends on does not hold here and a
 * user-chosen label is transmitted with no option involved.
 *
 * @example
 * ```ts
 * import tracer from 'dd-trace';
 * import { installSensitiveScrubbing } from '@platform-sec/sensitive-string-datadog';
 *
 * tracer.init({ service: 'payments' });
 *
 * installSensitiveScrubbing(tracer, {
 *   denyKeys: ['x-internal-signature'],
 *   captureHeaders: ['authorization', 'x-request-id'],
 *   onScrub: (report) => metrics.increment('sensitive.scrubbed', report.deniedKeys.length),
 * });
 * ```
 *
 * @packageDocumentation
 */

export { installSensitiveScrubbing, isApplied } from './install.js';
export type { DatadogTracer, InstallOptions, Installation } from './install.js';

export { CENSOR_PLACEHOLDER, canEnumerateTags, readTags } from './hooks.js';
export type { DatadogSpan, DatadogSpanContext } from './hooks.js';

export {
  DD_QUERY_OBFUSCATION_DEFAULT,
  composeQueryObfuscation,
  planHeaderCapture,
} from './config.js';
export type { QueryStringObfuscation } from './config.js';

export {
  DATADOG_DENY_PATHS,
  DATADOG_POLICY,
  DATADOG_URL_KEYS,
  REQUEST_HEADER_PREFIX,
  RESERVED_TAGS,
  RESPONSE_HEADER_PREFIX,
  classifyTag,
  isReservedTag,
  projectHeaderPaths,
} from './paths.js';
export type { TagDecision } from './paths.js';

export { COVERED_PLUGINS, DEFERRED_PLUGINS, knownPlugins } from './seams.js';
export type { CoveredPlugin } from './seams.js';

// Re-exported so a caller configures the policy without a second install.
export type { ScrubPolicy, ScrubReport, PayloadKind } from '@platform-sec/sensitive-string-scrub';
