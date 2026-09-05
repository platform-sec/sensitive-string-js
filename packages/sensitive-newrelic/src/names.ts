/**
 * The agent's attribute vocabulary, reproduced.
 *
 * New Relic does not name an attribute after the HTTP header it came from. It
 * renames it, and a denylist written in the spelling the request actually used
 * silently does nothing. Measured on `newrelic` 14.3.10, Node 22.15.0, with
 * `allow_all_headers: true` and an inbound `x-api-key` header:
 *
 * | Rule | `request.headers.xApiKey` |
 * |---|---|
 * | `attributes.exclude: ['request.headers.x-api-key']` | Still transmitted |
 * | `attributes.exclude: ['request.headers.xApiKey']` | Dropped |
 *
 * That is the single most likely way for a hand-written New Relic exclusion
 * list to be wrong, and translating names is this package's main job.
 *
 * Reproduced rather than imported. `lib/header-attributes.js` is a private
 * module, and importing it to compute a security-critical list makes the
 * package break on a refactor that would otherwise be invisible.
 * `names.test.ts` asserts the reproduction still agrees with the shipped agent
 * on every name in the map and on a fixture set of shapes outside it, so a
 * vendor change fails a test here rather than going unnoticed in a generated
 * configuration.
 */

/**
 * `HEADER_ATTR_NAMES` from `newrelic` 14.3.10, all 50 entries.
 *
 * The agent consults this map first and falls back to `camelCaseHeader` for
 * anything it does not name. Most entries agree with the fallback; the ones
 * that do not are why the map has to be carried rather than computed. `etag`
 * becomes `eTag` and `newrelic` stays `newrelic`, neither of which the
 * fallback produces.
 */
export const HEADER_ATTR_NAMES: Readonly<Record<string, string>> = Object.freeze({
  accept: 'accept',
  'accept-charset': 'acceptCharset',
  'accept-encoding': 'acceptEncoding',
  'access-control-allow-headers': 'accessControlAllowHeaders',
  'access-control-allow-methods': 'accessControlAllowMethods',
  'access-control-allow-origin': 'accessControlAllowOrigin',
  age: 'age',
  allow: 'allow',
  authorization: 'authorization',
  'cache-control': 'cacheControl',
  connection: 'connection',
  cookie: 'cookie',
  'content-encoding': 'contentEncoding',
  'content-length': 'contentLength',
  'content-type': 'contentType',
  date: 'date',
  etag: 'eTag',
  expect: 'expect',
  expires: 'expires',
  forwarded: 'forwarded',
  host: 'host',
  'if-match': 'ifMatch',
  'if-modified-since': 'ifModifiedSince',
  'last-modified': 'lastModified',
  location: 'location',
  newrelic: 'newrelic',
  origin: 'origin',
  'proxy-authorization': 'proxyAuthorization',
  referer: 'referer',
  refresh: 'refresh',
  server: 'server',
  'set-cookie': 'setCookie',
  'transfer-encoding': 'transferEncoding',
  'user-agent': 'userAgent',
  upgrade: 'upgrade',
  vary: 'vary',
  'x-correlation-id': 'xCorrelationId',
  'x-csrf-token': 'xCsrfToken',
  'x-forwarded-for': 'xForwardedFor',
  'x-http-method-override': 'xHttpMethodOverride',
  'x-newrelic-app-data': 'xNewrelicAppData',
  'x-newrelic-id': 'xNewrelicId',
  'x-newrelic-synthetics': 'xNewrelicSynthetics',
  'x-newrelic-synthetics-info': 'xNewrelicSyntheticsInfo',
  'x-newrelic-transaction': 'xNewrelicTransaction',
  'x-powered-by': 'xPoweredBy',
  'x-queue-start': 'xQueueStart',
  'x-request-id': 'xRequestId',
  'x-request-start': 'xRequestStart',
  'x-requested-with': 'xRequestedWith',
});

/** The six headers `newrelic` 14.3.10 collects when `allow_all_headers` is false. */
export const COLLECTED_REQUEST_HEADERS: readonly string[] = Object.freeze([
  'accept',
  'content-length',
  'content-type',
  'referer',
  'user-agent',
  'host',
]);

/** The prefix the agent writes inbound request headers under. */
export const REQUEST_HEADER_PREFIX = 'request.headers.';

/** The prefix the agent writes response headers under. */
export const RESPONSE_HEADER_PREFIX = 'response.headers.';

/** The prefix the agent writes parsed query parameters under. */
export const REQUEST_PARAMETER_PREFIX = 'request.parameters.';

/**
 * `_headerToCamelCase` from `newrelic` 14.3.10, reproduced.
 *
 * Three behaviours worth naming, because each of them is a way a hand-written
 * exclusion goes wrong:
 *
 * - Only the **first** character is lowercased. Every later segment is
 *   title-cased by upper-casing its first character and keeping the rest as it
 *   arrived, so `X-API-KEY` becomes `xAPIKEY` and `x-api-key` becomes
 *   `xApiKey`. Two spellings of one header produce two different attributes.
 * - A single-character name is lowercased whole and returned.
 * - The split is on `[\W_]`, so underscores separate segments the same way
 *   hyphens do and the separator itself is dropped.
 */
export function camelCaseHeader(header: string): string {
  if (header.length === 0) {
    return '';
  }

  if (header.length === 1) {
    return header.toLowerCase();
  }

  const lowered = header.charAt(0).toLowerCase() + header.slice(1);

  return lowered
    .split(/[\W_]/)
    .map((segment, index) =>
      index === 0 ? segment : segment.slice(0, 1).toUpperCase() + segment.slice(1)
    )
    .join('');
}

/**
 * The attribute name the agent writes for one header, map first and fallback
 * after.
 *
 * This is `_collectHeaders`' `nameMap[headerKey] || prefix + _headerToCamelCase(headerKey)`,
 * with the one detail that decides whether a generated rule matches: the map
 * is keyed by the **lowercased** header name, because with `allow_all_headers`
 * off the agent lowercases every key before the lookup. With it on the agent
 * uses the key as it arrived, and Node lowercases inbound header names itself,
 * so a lowercase lookup is right on both paths for a server span.
 *
 * @param header - The HTTP header name, in any casing
 * @param prefix - `request.headers.` or `response.headers.`
 */
export function headerAttributeName(header: string, prefix: string): string {
  const mapped = HEADER_ATTR_NAMES[header.toLowerCase()];

  return prefix + (mapped ?? camelCaseHeader(header));
}

/**
 * Every spelling of one header name the agent could write, deduplicated.
 *
 * A generated rule has to match the attribute the agent actually produced, and
 * `camelCaseHeader` is not injective over casing: an application that forwards
 * `X-API-KEY` on an outbound call produces `xAPIKEY` where the inbound
 * lowercase form produces `xApiKey`. The generator emits an exact rule for
 * every spelling it can derive rather than guessing which one will arrive,
 * because per section 2.9 an exact rule is the only one no include can lift
 * and two exact excludes cost nothing.
 *
 * The raw name is included as well. It is not a spelling the agent produces
 * for a header, but it is the spelling a reader of the configuration expects
 * to see, and it is the one that matches if the same name is used as a plain
 * attribute somewhere the header path never touched.
 */
export function headerSpellings(header: string, prefix: string): readonly string[] {
  const lowered = header.toLowerCase();

  return [
    ...new Set([
      headerAttributeName(lowered, prefix),
      prefix + camelCaseHeader(header),
      prefix + camelCaseHeader(lowered),
      prefix + lowered,
    ]),
  ];
}
