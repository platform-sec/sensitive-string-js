/**
 * @platform-sec/sensitive-string-newrelic
 *
 * Attribute exclusions for `newrelic`, generated in the agent's own vocabulary
 * and exact enough that nothing can lift them.
 *
 * Unlike an error tracker, this agent does not leak at stock defaults.
 * Measured on `newrelic` 14.3.10, Node 22.15.0, one inbound request carrying
 * `authorization`, `cookie`, `x-api-key`, a `?token=` parameter and a JSON
 * body with a `password` field, exactly six headers reached the payload:
 * `accept`, `content-length`, `content-type`, `referer`, `user-agent`, `host`.
 * No query parameters, no body, no canary.
 *
 * The leak is one configuration line away, and the line is one a competent
 * operator has a reason to write:
 *
 * ```
 * allow_all_headers: true
 *
 * request.headers.authorization  "Bearer LEAKED_SECRET_abc123xyz"
 * request.headers.cookie         "session=LEAKED_SECRET_abc123xyz"
 * request.headers.xApiKey        "LEAKED_SECRET_abc123xyz"
 * ```
 *
 * Note `xApiKey`. An exclusion written as `request.headers.x-api-key`, in the
 * spelling the HTTP request actually used, silently does nothing. Translating
 * names is this package's main job, and emitting rules that no later
 * `include` line can reopen is the other.
 *
 * @example
 * ```ts
 * // newrelic.js
 * const { sensitiveAgentConfig } = require('@platform-sec/sensitive-string-newrelic');
 *
 * module.exports = {
 *   app_name: ['payments'],
 *   allow_all_headers: true,
 *   ...sensitiveAgentConfig({
 *     denyKeys: ['x-internal-signature'],
 *     allowKeys: [{ key: 'x-request-id', reason: 'opaque correlation id, not a credential' }],
 *   }),
 * };
 * ```
 *
 * @packageDocumentation
 */

export { sensitiveAgentConfig } from './config.js';
export type {
  NewRelicAttributeRules,
  NewRelicConfigFragment,
  SensitiveAgentConfig,
  SensitiveAgentConfigOptions,
} from './config.js';

export { sensitiveAttributes } from './attributes.js';
export type { NewRelicAttributeValue } from './attributes.js';

export {
  COLLECTED_REQUEST_HEADERS,
  HEADER_ATTR_NAMES,
  REQUEST_HEADER_PREFIX,
  REQUEST_PARAMETER_PREFIX,
  RESPONSE_HEADER_PREFIX,
  camelCaseHeader,
  headerAttributeName,
  headerSpellings,
} from './names.js';

// Re-exported so a caller configures the policy without a second install.
export type { ScrubPolicy, ScrubReport, PayloadKind } from '@platform-sec/sensitive-string-scrub';
