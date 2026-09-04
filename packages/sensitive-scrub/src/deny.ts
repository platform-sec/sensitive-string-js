/**
 * The denylist, its matcher, and the URL query handling.
 *
 * Stage 2 of the three stages. Stage 1 replaces values the application
 * wrapped; this stage is the one that closes the measured leak, which is the
 * raw strings nobody wrapped sitting beside the wrapped ones.
 *
 * Matching is on key names and paths, never on values. A scrubber that
 * decides by looking at a string is a classifier, it is wrong some of the
 * time, and the thing a user does about an error tracker that hides values
 * they needed is turn the scrubbing off.
 */

/**
 * Rollbar 3.1.0's `commonScrubFields`, reproduced.
 *
 * Reproduced rather than imported so the Sentry and Bugsnag packages do not
 * depend on a Rollbar install. `deny.test.ts` asserts the reproduction is
 * still a superset of what the installed `rollbar` ships, so a vendor adding
 * a name fails a test here rather than going unnoticed in four packages.
 */
const ROLLBAR_COMMON_SCRUB_FIELDS = [
  'pw',
  'pass',
  'passwd',
  'password',
  'secret',
  'confirm_password',
  'confirmPassword',
  'password_confirmation',
  'passwordConfirmation',
  'access_token',
  'accessToken',
  'X-Rollbar-Access-Token',
  'secret_key',
  'secretKey',
  'secretToken',
] as const;

/** Rollbar 3.1.0's `apiScrubFields`, reproduced. */
const ROLLBAR_API_SCRUB_FIELDS = [
  'api_key',
  'authenticity_token',
  'oauth_token',
  'token',
  'user_session_secret',
] as const;

/** Rollbar 3.1.0's `commonScrubHeaders`, reproduced. */
const ROLLBAR_COMMON_SCRUB_HEADERS = [
  'authorization',
  'www-authorization',
  'http_authorization',
  'omniauth.auth',
  'cookie',
  'oauth-access-token',
  'x-access-token',
  'x_csrf_token',
  'http_x_csrf_token',
  'x-csrf-token',
] as const;

/**
 * Names Sentry captures at stock defaults that Rollbar's lists do not carry.
 *
 * Each is a name whose value is a credential by construction rather than by
 * convention, which is the bar for adding to a default list. A name that is
 * merely often sensitive belongs in a caller's `denyKeys`, because a false
 * positive here censors a value an engineer needed and costs more than it
 * saves.
 */
const ADDITIONAL_DENY_KEYS = [
  // Credential-bearing headers. `set-cookie` is a response header, and Sentry
  // collects response headers as well as request headers by default.
  'proxy-authorization',
  'set-cookie',
  'x-api-key',
  'api-key',
  'apikey',
  'x-auth-token',
  'x-session-token',
  'x-amz-security-token',
  'x-goog-api-key',
  'x-functions-key',
  // OAuth and OIDC fields that travel in bodies rather than headers. Rollbar
  // lists `access_token` and `oauth_token` but none of these.
  'refresh_token',
  'refreshToken',
  'id_token',
  'idToken',
  'client_secret',
  'clientSecret',
  // Key material and session handles.
  'private_key',
  'privateKey',
  'passphrase',
  'session_id',
  'sessionId',
  'credentials',
] as const;

/**
 * The default denied key names.
 *
 * The union of Rollbar 3.1.0's three key-shaped lists, which are the best
 * defaults of the three vendors measured, plus the names above.
 */
export const DEFAULT_DENY_KEYS: readonly string[] = [
  ...ROLLBAR_COMMON_SCRUB_FIELDS,
  ...ROLLBAR_API_SCRUB_FIELDS,
  ...ROLLBAR_COMMON_SCRUB_HEADERS,
  ...ADDITIONAL_DENY_KEYS,
];

/**
 * The default denied paths, seeded from Rollbar 3.1.0's `requestScrubFields`.
 *
 * Rollbar's fourth list is path-shaped rather than key-shaped, so it cannot
 * join `DEFAULT_DENY_KEYS`: `request.cookies` as a key name would match a key
 * literally called `request.cookies`, and as a path it matches the parsed
 * cookie object an error tracker actually captures.
 *
 * These are written against Rollbar's payload shape. Two of them, by
 * coincidence rather than by agreement, are also Sentry's. A vendor package
 * supplies its own shape through `denyPaths` rather than assuming this list
 * describes it.
 */
export const DEFAULT_DENY_PATHS: readonly string[] = [
  'request.session.csrf',
  'request.session._csrf',
  'request.params._csrf',
  'request.cookie',
  'request.cookies',
];

/** Rollbar's shipped lists, exposed for the superset test and for nothing else. */
export const ROLLBAR_REPRODUCED = {
  commonScrubFields: ROLLBAR_COMMON_SCRUB_FIELDS,
  apiScrubFields: ROLLBAR_API_SCRUB_FIELDS,
  commonScrubHeaders: ROLLBAR_COMMON_SCRUB_HEADERS,
  requestScrubFields: DEFAULT_DENY_PATHS,
} as const;

/**
 * Whether a dotted path matches one of the denied paths.
 *
 * Whole-path matching, not segment matching: `request.cookie` denies the
 * cookie hanging off the request and says nothing about a `cookie` nested
 * three levels into a body. A `*` segment in a denied path matches exactly one
 * segment of the subject, which is how an array element is named, since an
 * element contributes its index to the path.
 */
export function pathDenied(path: string, denyPaths: ReadonlySet<string>): boolean {
  if (denyPaths.size === 0) {
    return false;
  }

  const lowered = path.toLowerCase();

  if (denyPaths.has(lowered)) {
    return true;
  }

  for (const candidate of denyPaths) {
    if (candidate.includes('*') && wildcardMatches(candidate, lowered)) {
      return true;
    }
  }

  return false;
}

function wildcardMatches(pattern: string, subject: string): boolean {
  const patternSegments = pattern.split('.');
  const subjectSegments = subject.split('.');

  if (patternSegments.length !== subjectSegments.length) {
    return false;
  }

  return patternSegments.every(
    (segment, index) => segment === '*' || segment === subjectSegments[index]
  );
}

/**
 * Whether a key name or the path it sits at names a value to replace.
 *
 * A key match is case-insensitive and depth-independent, which is what makes
 * `authorization` cover the header wherever a vendor decided to put it.
 */
export function denied(
  key: string,
  path: string,
  denyKeys: ReadonlySet<string>,
  denyPaths: ReadonlySet<string>
): boolean {
  return denyKeys.has(key.toLowerCase()) || pathDenied(path, denyPaths);
}

/** Whether a key name or its path names a value that should be treated as a URL. */
export function isUrlPosition(key: string, path: string, urlKeys: ReadonlySet<string>): boolean {
  return urlKeys.has(key.toLowerCase()) || urlKeys.has(path.toLowerCase());
}

/**
 * Replace the denied query parameters of a URL, keeping everything else.
 *
 * Deleting the URL from an error event removes most of its value, and the
 * measured leak is a token in a query string on a URL whose route is the useful
 * part of the report. Three shapes arrive here, and a vendor emits all three
 * for one outbound request. Measured on `@sentry/node` 10.73.0, a single
 * `http.get` produced these span attributes, every one of them carrying the
 * token:
 *
 * ```
 * url.full      "http://127.0.0.1:8080/pay?token=SECRET&page=2"   absolute
 * http.target   "/pay?token=SECRET&page=2"                        relative
 * http.query    "token=SECRET&page=2"                             bare query
 * ```
 *
 * A relative URL is the one that used to slip through: `new URL()` refuses it,
 * and handing `/pay?token=SECRET&page=2` to `URLSearchParams` yields the keys
 * `['/pay?token', 'page']`, so nothing matched and the string was kept whole.
 *
 * A password in the userinfo component is replaced unconditionally. There is
 * no key name to match it by, and a URL that carries one carries a credential
 * by construction.
 *
 * @returns The rewritten string and the parameter names replaced, or `null`
 *          when nothing was denied, in which case the caller keeps the
 *          original string. Nothing is rewritten just to normalize it: a
 *          round trip through `URL` changes percent-encoding and default
 *          ports, and an unrelated string must come back byte-identical.
 */
export function scrubUrl(
  value: string,
  denyKeys: ReadonlySet<string>,
  censor: string
): { value: string; replaced: string[] } | null {
  return (
    tryAbsoluteUrl(value, denyKeys, censor) ??
    tryRelativeUrl(value, denyKeys, censor) ??
    tryQueryString(value, denyKeys, censor)
  );
}

/** The base a relative URL is resolved against, and never emitted. */
const RELATIVE_BASE = 'http://relative.invalid';

function tryAbsoluteUrl(
  value: string,
  denyKeys: ReadonlySet<string>,
  censor: string
): { value: string; replaced: string[] } | null {
  let url: URL;

  try {
    url = new URL(value);
  } catch {
    return null;
  }

  const replaced = replaceParams(url.searchParams, denyKeys, censor);

  if (url.password !== '') {
    url.password = censor;
    replaced.push('url.password');
  }

  return replaced.length === 0 ? null : { value: restoreCensor(url.toString(), censor), replaced };
}

/**
 * A path with a query, which is what a span's `http.target` holds.
 *
 * Resolved against a base that is thrown away, and re-emitted from the path
 * onwards so the base never reaches the payload. An arbitrary string also
 * resolves against a base, which is why nothing is rewritten unless a denied
 * parameter actually matched: `new URL('not a url', base)` succeeds and would
 * otherwise come back percent-encoded.
 *
 * A leading slash is required, so this branch claims only what is actually a
 * path. Without it a bare `?token=...` resolves to the path `/` and comes back
 * as `/?token=...`, gaining a segment the caller never wrote, and that shape
 * belongs to the query-string branch below.
 */
function tryRelativeUrl(
  value: string,
  denyKeys: ReadonlySet<string>,
  censor: string
): { value: string; replaced: string[] } | null {
  if (!value.startsWith('/')) {
    return null;
  }

  let url: URL;

  try {
    url = new URL(value, RELATIVE_BASE);
  } catch {
    return null;
  }

  const replaced = replaceParams(url.searchParams, denyKeys, censor);

  if (replaced.length === 0) {
    return null;
  }

  return {
    value: restoreCensor(`${url.pathname}${url.search}${url.hash}`, censor),
    replaced,
  };
}

/**
 * A bare query string, which is what `request.query_string` and a span's
 * `http.query` hold.
 *
 * `URLSearchParams` accepts anything, so an arbitrary string parses as one key
 * with an empty value. Rewriting that would corrupt it, so a subject with
 * nothing to replace is reported as untouched and the original is kept.
 */
function tryQueryString(
  value: string,
  denyKeys: ReadonlySet<string>,
  censor: string
): { value: string; replaced: string[] } | null {
  const params = new URLSearchParams(value.startsWith('?') ? value.slice(1) : value);
  const replaced = replaceParams(params, denyKeys, censor);

  if (replaced.length === 0) {
    return null;
  }

  return {
    value: (value.startsWith('?') ? '?' : '') + restoreCensor(params.toString(), censor),
    replaced,
  };
}

/**
 * Put the censor back in its literal form.
 *
 * `URLSearchParams.toString()` percent-encodes what it writes, so the default
 * `[SCRUBBED]` comes back as `%5BSCRUBBED%5D`. That is still censored and it
 * is unreadable, and the point of rewriting a URL rather than dropping it is
 * that somebody reads the result. Only the censor is restored, so nothing the
 * caller put in the URL is decoded on their behalf.
 */
function restoreCensor(value: string, censor: string): string {
  const encoded = encodeURIComponent(censor);

  return encoded === censor ? value : value.split(encoded).join(censor);
}

function replaceParams(
  params: URLSearchParams,
  denyKeys: ReadonlySet<string>,
  censor: string
): string[] {
  const replaced: string[] = [];

  for (const name of new Set(params.keys())) {
    if (denyKeys.has(name.toLowerCase())) {
      params.set(name, censor);
      replaced.push(name);
    }
  }

  return replaced;
}
