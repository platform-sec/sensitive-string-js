import type { ResolvedScrubPolicy } from '@platform-sec/sensitive-string-scrub';

/**
 * The two lists a hook cannot reach.
 *
 * A hook rewrites tags on a span the agent already built. It cannot decide
 * which headers get captured in the first place, and it cannot reach a URL on
 * a span belonging to a plugin with no hook at all. Both of those are
 * configuration, and both are generated here.
 */

/**
 * `dd-trace` 6.14.0's default query-string obfuscator, reproduced.
 *
 * The default value of `DD_TRACE_OBFUSCATION_QUERY_STRING_REGEXP`, read off
 * `supported-configurations.json`. It matches on key name for the `pwd`,
 * `passwd`, `pword` and `password` spellings, `pass`, `passphrase`, `secret`,
 * `api_key`, `private_key`, `public_key`, `access_key`, `secret_key` (each
 * also with an `_id` suffix), `token`, `consumer_id`, `consumer_key`,
 * `consumer_secret`, `sign`, `signed`, `signature`, `auth`, `authentication`
 * and `authorization`. It matches on value shape for `bearer <token>`, a
 * 13-character value under a `token:` key, JWTs, GitHub tokens, PEM private
 * key blocks and `ssh-rsa` keys.
 *
 * Reproduced rather than imported, the same reason
 * `@platform-sec/sensitive-string-scrub` reproduces Rollbar's lists:
 * `supported-configurations.json` is a private data file of the agent, and
 * reading it at runtime to build a security-critical pattern makes the package
 * break on a file move that would otherwise be invisible. `config.test.ts`
 * asserts the reproduction is still exactly what the installed `dd-trace`
 * ships, so a vendor widening its own default fails a test here rather than
 * being silently narrowed by this package.
 *
 * This is a value-shape matcher, and this package's general position is that
 * value-shape matching is opt-in. The distinction is the position rather than
 * the technique: a query string is a bounded position with a known grammar,
 * and Datadog itself runs these patterns there unconditionally while gating a
 * richer set behind its AppSec product for arbitrary request data. Composing
 * with what the vendor already runs, where the vendor already runs it, is not
 * the same as turning value matching on for every tag.
 */
export const DD_QUERY_OBFUSCATION_DEFAULT =
  '(?:p(?:ass)?w(?:or)?d|pass(?:_?phrase)?|secret|(?:api_?|private_?|public_?|access_?|secret_?)key(?:_?id)?|token|consumer_?(?:id|key|secret)|sign(?:ed|ature)?|auth(?:entication|orization)?)(?:(?:\\s|%20)*(?:=|%3D)[^&]+|(?:"|%22)(?:\\s|%20)*(?::|%3A)(?:\\s|%20)*(?:"|%22)(?:%2[^2]|%[^2]|[^"%])+(?:"|%22))|bearer(?:\\s|%20)+[a-z0-9\\._\\-]+|token(?::|%3A)[a-z0-9]{13}|gh[opsu]_[0-9a-zA-Z]{36}|ey[I-L](?:[\\w=-]|%3D)+\\.ey[I-L](?:[\\w=-]|%3D)+(?:\\.(?:[\\w.+\\/=-]|%3D|%2F|%2B)+)?|[\\-]{5}BEGIN(?:[a-z\\s]|%20)+PRIVATE(?:\\s|%20)KEY[\\-]{5}[^\\-]+[\\-]{5}END(?:[a-z\\s]|%20)+PRIVATE(?:\\s|%20)KEY|ssh-rsa(?:\\s|%20)*(?:[a-z0-9\\/\\.+]|%2F|%5C|%2B){100,}';

/**
 * What the agent's own `queryStringObfuscation` option accepts.
 *
 * `true` redacts the whole query, `false` and the empty string disable
 * obfuscation, and a string is compiled with the `gi` flags.
 */
export type QueryStringObfuscation = boolean | string;

/**
 * Escape a denylist entry so it reaches the regex engine as a literal.
 *
 * A denylist entry is configuration a user edits and this pattern runs on
 * every request URL, which is the pair of conditions that turns a catastrophic
 * pattern into a denial of service rather than a bug. Escaping is what keeps
 * every fragment a literal, and the fragment shape below keeps the composed
 * alternation linear: each branch is `<literal>` followed by a bounded
 * separator and `[^&]+`, with no nested quantifier for a backtracker to
 * explore.
 */
function escapeLiteral(value: string): string {
  return value.replaceAll(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`);
}

/**
 * One alternation branch matching `<key>=<value>` in a query string.
 *
 * Modelled on the vendor's own key-name branch, including the `%20` and `%3D`
 * spellings, because a query string reaching the obfuscator may or may not
 * have been decoded.
 */
function queryFragment(key: string): string {
  return `${escapeLiteral(key)}(?:(?:\\s|%20)*(?:=|%3D)[^&]+)`;
}

/**
 * Compose this package's key names into the agent's query obfuscator.
 *
 * Composed, never replaced. Invariant 7 is that neither package narrows the
 * agent's own protection, and the agent's default is good: it is on in every
 * deployment and covers more key names than the shared denylist does.
 *
 * Three cases, and only the third generates anything:
 *
 * - `true`, meaning the whole query is already dropped. Nothing is stronger,
 *   so it is returned unchanged.
 * - `false` or `''`, meaning the caller turned obfuscation off deliberately.
 *   That decision is theirs and is left alone. The URL is still covered on
 *   every span this package hooks, because the hook rewrites `http.url`
 *   through the shared `scrubUrl`; what is lost is coverage of spans from
 *   plugins with no hook.
 * - absent or a string, where the result is the base pattern followed by one
 *   branch per denied key the base does not already match.
 *
 * @param existing - The caller's own `queryStringObfuscation`, if any
 * @param policy - The resolved policy whose key names are added
 */
export function composeQueryObfuscation(
  existing: QueryStringObfuscation | undefined,
  policy: ResolvedScrubPolicy
): QueryStringObfuscation {
  if (existing === true) {
    return true;
  }

  if (existing === false || existing === '') {
    return existing;
  }

  const base = existing ?? DD_QUERY_OBFUSCATION_DEFAULT;
  const compiled = new RegExp(base, 'gi');
  const added: string[] = [];

  for (const key of policy.denyKeys) {
    compiled.lastIndex = 0;

    // Only what the base does not already cover. Testing against the key
    // followed by a value is what the obfuscator will actually see, and it
    // keeps the composed pattern from growing a branch per default name.
    if (!compiled.test(`${key}=x`)) {
      added.push(queryFragment(key));
    }
  }

  return added.length === 0 ? base : `${base}|${added.join('|')}`;
}

/**
 * Filter a header capture list against the denylist.
 *
 * Nothing is removed. A name that resolves to a denied key is still captured,
 * so the tag exists and its presence and shape stay diagnostic, and the hook
 * then replaces its value. That is a real use rather than a compromise: the
 * presence of an auth header is worth knowing and its content is not.
 *
 * The list is deduplicated and lowercased, because `dd-trace` matches header
 * names case-insensitively when tagging and writes the tag under the name it
 * was given, so two spellings of one header would otherwise produce two tags.
 *
 * @returns The list to hand the agent, and the subset whose values the hook
 *          has to censor
 */
export function planHeaderCapture(
  requested: readonly string[],
  policy: ResolvedScrubPolicy
): { capture: string[]; censored: string[] } {
  const capture = [...new Set(requested.map((name) => name.toLowerCase()))].sort();
  const censored = capture.filter((name) => policy.denyKeys.has(name));

  return { capture, censored };
}
