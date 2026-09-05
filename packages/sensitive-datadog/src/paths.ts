import {
  denied,
  isUrlPosition,
  pathDenied,
  scrubUrl,
  type ResolvedScrubPolicy,
  type ScrubPolicy,
} from '@platform-sec/sensitive-string-scrub';

/**
 * Where Datadog puts things, and how a flat tag key is matched against a
 * denylist written for nested payloads.
 *
 * The shared layer owns the key names and the walk. This file is the part that
 * cannot be shared, because it is knowledge of one vendor's tag vocabulary.
 *
 * Measured on `dd-trace` 6.14.0, Node 22.15.0, one inbound
 * `POST /pay?token=<canary>&page=2` with `headerTags: ['authorization',
 * 'cookie', 'x-api-key']`:
 *
 * ```
 * web.request   http.request.headers.authorization   "Bearer LEAKED_SECRET_abc123xyz"
 * web.request   http.request.headers.cookie          "session=LEAKED_SECRET_abc123xyz"
 * web.request   http.request.headers.x-api-key       "LEAKED_SECRET_abc123xyz"
 * web.request   http.response.headers.x-api-key      "LEAKED_SECRET_abc123xyz"
 * http.request  http.request.headers.authorization   "Bearer LEAKED_SECRET_abc123xyz"
 * http.request  http.request.headers.cookie          "session=LEAKED_SECRET_abc123xyz"
 * http.request  http.request.headers.x-api-key       "LEAKED_SECRET_abc123xyz"
 * http.request  http.response.headers.x-api-key      "LEAKED_SECRET_abc123xyz"
 * ```
 *
 * Four things follow, and each shapes something here.
 *
 * The tag name keeps the raw HTTP header spelling, hyphens and all. New Relic
 * does the opposite, which is why the shared denylist is projected into each
 * vendor's vocabulary rather than copied into it.
 *
 * A tag bag is **flat**. `http.request.headers.authorization` is one key with
 * dots in it, not a path of four segments, so `denyKeys.has('authorization')`
 * does not match it. The projection below is what closes that gap: every
 * denied key becomes an exact denied **path** in Datadog's spelling, resolved
 * once at install time.
 *
 * The obfuscator does not run on header values. It is a query-string
 * transform called from `obfuscateQs` on the URL only, and nothing else in the
 * tag path consults it, so `Bearer <canary>` arrives verbatim even though
 * `bearer` is a default pattern.
 *
 * A client span carries the same tags. Turning header capture on to debug
 * inbound traffic also starts transmitting the `authorization` header of every
 * outbound call, which is why the hooks cover both directions.
 */

/** The prefix `dd-trace` writes captured request headers under. */
export const REQUEST_HEADER_PREFIX = 'http.request.headers.';

/** The prefix `dd-trace` writes captured response headers under. */
export const RESPONSE_HEADER_PREFIX = 'http.response.headers.';

/**
 * Tag keys holding a URL, a path with a query, or a bare query string.
 *
 * Deleting a URL from a span removes most of its value, so these are rewritten
 * rather than censored: the denied query parameters are replaced and the route
 * survives.
 *
 * `http.url` is the one `dd-trace`'s own plugins write, and it is one key
 * containing dots rather than a path of two segments, which is why the shared
 * matcher accepts a terminal key name as well as a whole dotted path. The
 * OpenTelemetry spellings are here because a span that came through
 * `dd-trace`'s OTel bridge carries those instead, and a tag list that only
 * knew Datadog's own name would silently miss them.
 */
export const DATADOG_URL_KEYS: readonly string[] = [
  'http.url',
  'http.uri',
  'url.full',
  'url.path',
  'url.query',
  'http.target',
  'http.query',
  'peer.url',
  // A terminal key name rather than a path, which is how an application tag
  // like `probe.url` is matched. The shared matcher accepts either.
  'url',
];

/**
 * Whole tag positions whose content is a payload rather than a named field.
 *
 * Each is a place a plugin writes application data under a key that says
 * nothing about what is in it, so no key name list describes the contents.
 * They are denied as whole paths, the way the shared defaults deny
 * `request.cookies`.
 */
export const DATADOG_DENY_PATHS: readonly string[] = [
  'elasticsearch.body',
  'elasticsearch.params',
  'opensearch.body',
  'opensearch.params',
  'graphql.variables',
  'sharedb.request.body',
];

/** The policy this package contributes before the caller's own is merged in. */
export const DATADOG_POLICY: ScrubPolicy = {
  denyPaths: DATADOG_DENY_PATHS,
  urlKeys: DATADOG_URL_KEYS,
};

/**
 * Tags the agent owns, which the walk skips.
 *
 * Two reasons, and the second is the one that matters. They are not
 * application data, so walking them is work with no possible finding. And
 * writing one back would hand the agent a value it did not write for a field
 * it uses to route and name the span; `service.name` and `resource.name` are
 * read by the formatter into dedicated span fields rather than into `meta`.
 *
 * `_dd`-prefixed keys are excluded by prefix rather than by name, since the
 * set grows with every agent feature and none of it is ever application data.
 */
export const RESERVED_TAGS: ReadonlySet<string> = new Set([
  'service',
  'service.name',
  'span.type',
  'span.kind',
  'resource.name',
  'version',
  'runtime-id',
  'component',
  'analytics.event',
  'language',
  'error',
  'manual.drop',
  'manual.keep',
]);

/** Whether a tag belongs to the agent rather than to the application. */
export function isReservedTag(key: string): boolean {
  return key.startsWith('_dd') || RESERVED_TAGS.has(key);
}

/**
 * Project a resolved denylist into Datadog's tag vocabulary.
 *
 * Every denied key name becomes two exact denied paths, one per header
 * direction, so `http.request.headers.authorization` is denied as a whole path
 * as well as by its last segment. `tagKeyName` already covers the ordinary
 * case; this covers the one it cannot, a header name that itself contains a
 * dot, whose last segment is not the header name at all.
 *
 * It happens once at install time, so the hook does no list arithmetic per
 * span.
 *
 * @returns The paths to add to the policy's `denyPaths`
 */
export function projectHeaderPaths(denyKeys: Iterable<string>): string[] {
  const paths: string[] = [];

  for (const key of denyKeys) {
    paths.push(`${REQUEST_HEADER_PREFIX}${key}`, `${RESPONSE_HEADER_PREFIX}${key}`);
  }

  return paths;
}

/** What a tag key means to the matcher. */
export type TagDecision = 'deny' | 'url' | 'walk';

/**
 * The part of a dotted tag key that plays the role of a key name.
 *
 * A tag bag is flat, so `probe.password` is one key rather than a path of two
 * segments, and `denyKeys.has('probe.password')` is false. In the nested
 * payload the shared denylist was written for, the same value sits at path
 * `probe.password` under the key `password`, and the key is what matches. This
 * is that translation: the whole tag key is the path and its last dotted
 * segment is the key.
 *
 * Without it a wrapped credential under an application tag called
 * `probe.password` reaches the agent verbatim, which is what the first run of
 * `tags.test.ts` measured.
 */
export function tagKeyName(key: string): string {
  const at = key.lastIndexOf('.');

  return at === -1 ? key : key.slice(at + 1);
}

/**
 * Classify one tag key without allocating.
 *
 * The whole key is offered to the matcher as well as its last segment, so a
 * denylist entry written with a dot in it (`http.url`, or a header name that
 * contains one) still matches, and so does a `denyPaths` entry.
 *
 * `walk` means the tag is neither denied by name nor a URL position, and its
 * value still has to be looked at: it may be a `SensitiveString`, a
 * `serialize()` result, or a structure with a denied key inside it.
 */
export function classifyTag(key: string, policy: ResolvedScrubPolicy): TagDecision {
  const name = tagKeyName(key);

  if (
    policy.denyKeys.has(key.toLowerCase()) ||
    denied(name, key, policy.denyKeys, policy.denyPaths)
  ) {
    return 'deny';
  }

  if (isUrlPosition(name, key, policy.urlKeys)) {
    return 'url';
  }

  return 'walk';
}

/**
 * Whether one tag is worth putting in the bag at all.
 *
 * The fast path. An APM hook runs on every span of every request rather than
 * on the error path, which is the one place this row differs from the error
 * trackers, so a span with nothing to scrub must cost one pass over its keys
 * and no allocation. A tag earns its place when its key is denied, its key is
 * a URL position whose value actually carries a query, or its value is a
 * structure, which is the only shape a wrapped value or a `serialize()` result
 * can arrive in.
 */
export function isCandidate(key: string, value: unknown, policy: ResolvedScrubPolicy): boolean {
  if (isReservedTag(key)) {
    return false;
  }

  if (typeof value === 'object' && value !== null) {
    return true;
  }

  switch (classifyTag(key, policy)) {
    case 'deny':
      return true;
    case 'url':
      return typeof value === 'string' && scrubUrl(value, policy.denyKeys, policy.censor) !== null;
    case 'walk':
      // A string under a key nothing denied, at a position that is not a URL.
      // Only an opt-in value recognizer can have anything to say about it.
      return typeof value === 'string' && policy.denyValues.length > 0;
  }
}

/**
 * Whether a nested path inside a tag value is denied.
 *
 * Exposed for the failure path, which censors without walking and still has to
 * know which keys it is censoring.
 */
export function tagPathDenied(path: string, policy: ResolvedScrubPolicy): boolean {
  return pathDenied(path, policy.denyPaths);
}
