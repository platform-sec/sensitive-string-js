import {
  DEFAULT_DENY_KEYS,
  resolveScrubPolicy,
  type ResolvedScrubPolicy,
  type ScrubPolicy,
  type ScrubReport,
} from '@platform-sec/sensitive-string-scrub';

import {
  REQUEST_HEADER_PREFIX,
  REQUEST_PARAMETER_PREFIX,
  RESPONSE_HEADER_PREFIX,
  headerSpellings,
} from './names.js';

/**
 * A configuration generator, because there is nothing to wrap.
 *
 * `newrelic` 14.3.10's public API has 39 methods and none of them receives a
 * payload for rewriting. `setErrorGroupCallback` is the closest thing and it
 * returns a grouping string. There is no `beforeSend`, no event processor and
 * no transport seam, so the only lever this package has is the configuration
 * the agent reads at startup.
 *
 * That lever is enough, because the leak is an opt-in. Measured on `newrelic`
 * 14.3.10, Node 22.15.0, one inbound request carrying `authorization`,
 * `cookie`, `x-api-key`, a `?token=` parameter and a JSON body with a
 * `password` field:
 *
 * ```
 * stock defaults      six headers, none of them a credential; no query
 *                     parameters; no body
 * allow_all_headers   request.headers.authorization  "Bearer LEAKED_SECRET_abc123xyz"
 *                     request.headers.cookie         "session=LEAKED_SECRET_abc123xyz"
 *                     request.headers.xApiKey        "LEAKED_SECRET_abc123xyz"
 * ```
 *
 * `allow_all_headers` exists because somebody debugging a production incident
 * wants the headers. This package is what makes turning it on survivable.
 */

/** One destination's, or the global, attribute rules. */
export interface NewRelicAttributeRules {
  readonly enabled?: boolean;
  readonly include_enabled?: boolean;
  readonly include?: readonly string[];
  readonly exclude?: readonly string[];
}

/**
 * As much of an agent configuration as this package reads or writes.
 *
 * Deliberately not the agent's whole `Config` type. The agent does not publish
 * one for the object a `newrelic.js` exports, and a package that reproduced it
 * would have to track every option the agent adds. Everything not named here
 * passes through untouched.
 */
export interface NewRelicConfigFragment {
  readonly attributes?: NewRelicAttributeRules;
  readonly [key: string]: unknown;
}

/**
 * The fragment a caller spreads into their agent configuration.
 *
 * `exclude` is required here where it is optional on `NewRelicAttributeRules`,
 * because a generated fragment always carries one: that list is the whole
 * output.
 *
 * A type alias rather than an interface, so it stays assignable to the
 * index-signature shape a `newrelic.js` export has. An interface is not, and
 * the point of this value is to be spread into one.
 */
export type SensitiveAgentConfig = {
  readonly attributes: NewRelicAttributeRules & { readonly exclude: readonly string[] };
};

/** What `sensitiveAgentConfig` was asked to generate. */
export interface SensitiveAgentConfigOptions extends ScrubPolicy {
  /**
   * Also emit the `request.headers.*` wildcard. Off by default, and documented
   * as beatable.
   *
   * Measured on `newrelic` 14.3.10's own `AttributeFilter`: a wildcard exclude
   * is a default rather than a floor. `attributes.exclude: ['request.headers.*']`
   * drops `request.headers.authorization` from every destination, and adding
   * `attributes.include: ['request.headers.authorization']` restores it to all
   * five, because `_doTest` resolves include against exclude by match strength
   * and an exact include outscores any wildcard.
   *
   * So this is worth having for a user who wants headers excluded wholesale
   * rather than by name, and it is worth knowing that one later `include`
   * line, added months afterwards for an unrelated reason, silently reopens
   * it. The exact rules this generator emits by default cannot be reopened
   * that way.
   */
  readonly excludeAllRequestHeaders?: boolean;
}

/**
 * Every spelling of every denied key, sorted.
 *
 * New Relic's rules are **case-sensitive**: `_importRules` compiles them into
 * a `RegExp` with no `i` flag, so `accesstoken` does not match an attribute
 * called `accessToken`. `resolveScrubPolicy` lowercases, which is right for
 * every other consumer of the shared denylist because every other matcher
 * lowercases the subject too. Here it is not, and generating from the resolved
 * set alone silently dropped ten of the shipped defaults:
 *
 * ```
 * accessToken  refreshToken  sessionId  clientSecret  privateKey
 * confirmPassword  passwordConfirmation  secretKey  secretToken  idToken
 * ```
 *
 * Each of those is in `DEFAULT_DENY_KEYS` in camelCase precisely because that
 * is how it appears in a JavaScript payload, so losing them is losing the
 * names most likely to be there. Measured against the shipped
 * `AttributeFilter`, a custom attribute called `accessToken` was transmitted
 * under the generated configuration and `accesstoken` was excluded.
 *
 * So the source lists are read in the casing they were written, and both
 * spellings are emitted. `allowKeys` still decides membership, through the
 * resolved set, so a key the caller took back is absent in every casing.
 *
 * Sorted so the generated list is stable across runs and reviewable in a
 * configuration diff.
 */
function deniedSpellings(
  options: SensitiveAgentConfigOptions,
  policy: ResolvedScrubPolicy
): string[] {
  const spellings = new Set<string>(policy.denyKeys);

  for (const key of [...DEFAULT_DENY_KEYS, ...(options.denyKeys ?? [])]) {
    if (policy.denyKeys.has(key.toLowerCase())) {
      spellings.add(key);
    }
  }

  return [...spellings].sort();
}

/**
 * Build the `attributes.exclude` list a denied key needs, in every position
 * the agent writes one.
 *
 * Four positions, and each is a place a measurement put a value:
 *
 * - `request.headers.*` and `response.headers.*`, which is the leak of
 *   section 2.7, spelled in the agent's own vocabulary rather than the HTTP
 *   one. `headerSpellings` emits every spelling the agent could produce,
 *   because `camelCaseHeader` is not injective over casing and a rule that
 *   misses is indistinguishable from no rule at all.
 * - `request.parameters.<k>`, the parsed query. Those attributes sit at
 *   destination `NONE` unless a configuration explicitly includes them, and an
 *   explicit include is exactly the thing an exact exclude survives, so this
 *   is belt and braces rather than dead weight.
 * - the bare key, which covers a custom attribute and any agent attribute
 *   written at the top level.
 *
 * Every entry is exact. Per section 2.9, `_doTest` returns false on
 * `globalExclude === EXACT_MATCH` before it evaluates any include at all, so
 * an exact global exclusion is the only rule in New Relic's engine that
 * nothing in the configuration surface can lift. A generator that emitted
 * `request.headers.*` and called it done would produce a configuration a
 * single later `include` line reopens.
 */
function entriesFor(key: string): readonly string[] {
  return [
    ...headerSpellings(key, REQUEST_HEADER_PREFIX),
    ...headerSpellings(key, RESPONSE_HEADER_PREFIX),
    REQUEST_PARAMETER_PREFIX + key,
    key,
  ];
}

/**
 * Generate the attribute exclusions for a policy, merged over a caller's own.
 *
 * Pure, and with no side effect but the `onScrub` callback the caller asked
 * for. There is no agent to install into and none to import: the result is a
 * plain object a `newrelic.js` spreads, and a test can assert against it with
 * nothing running.
 *
 * @param options - What to deny, over the shared denylist. `denyPaths`,
 *                  `urlKeys`, `denyValues` and `censor` are accepted so one
 *                  policy object can be shared with the other packages in this
 *                  row, and are unused here: a configuration generator has no
 *                  payload to walk and no value to replace.
 * @param existing - The caller's own configuration, whose `attributes` section
 *                   is carried forward rather than replaced
 * @returns A fragment to spread into a `newrelic.js` export. The input is not
 *          modified.
 *
 * @throws ScrubPolicyError when the policy cannot be resolved, which for this
 *         package means an `allowKeys` entry with no reason or a key named in
 *         both lists.
 *
 * @example
 * ```ts
 * // newrelic.js
 * module.exports = {
 *   app_name: ['payments'],
 *   allow_all_headers: true,
 *   ...sensitiveAgentConfig({ denyKeys: ['x-internal-signature'] }),
 * };
 * ```
 */
export function sensitiveAgentConfig(
  options: SensitiveAgentConfigOptions = {},
  existing: NewRelicConfigFragment = {}
): SensitiveAgentConfig {
  const policy = resolveScrubPolicy(options);
  const keys = deniedSpellings(options, policy);
  const generated: string[] = [];

  for (const key of keys) {
    generated.push(...entriesFor(key));
  }

  if (options.excludeAllRequestHeaders === true) {
    generated.push(`${REQUEST_HEADER_PREFIX}*`);
  }

  const attributes = mergeAttributes(existing.attributes, generated);

  // The canonical key set, not the spellings. A caller reading `onScrub` wants
  // to know which names were denied; that one of them produced two rules
  // because the agent's matching is case-sensitive is this file's problem, not
  // theirs.
  report(policy.onScrub, [...policy.denyKeys].sort(), attributes.exclude.length);

  return { attributes };
}

/**
 * Append the generated entries to the caller's, keeping everything else.
 *
 * The fragment is spread over a configuration, so returning a bare
 * `{ attributes: { exclude } }` would drop a caller's `include`,
 * `include_enabled` or `enabled` along with it. Every field the caller set is
 * carried forward and only `exclude` grows, which is what makes the result a
 * superset of both inputs.
 */
function mergeAttributes(
  existing: NewRelicAttributeRules | undefined,
  generated: readonly string[]
): NewRelicAttributeRules & { exclude: readonly string[] } {
  const exclude = [...new Set([...(existing?.exclude ?? []), ...generated])];

  // `exactOptionalPropertyTypes` is on, so a field the caller did not set has
  // to be absent rather than present and undefined.
  return {
    ...(existing ?? {}),
    exclude,
  };
}

/**
 * Report what was generated, once per call.
 *
 * Key names and counts, never a value: there is no value here to leak, and the
 * report shape is the one every package in this row publishes so an operator
 * reads one thing.
 *
 * The kind is `transaction` because a global `attributes.exclude` covers every
 * destination at once, and the transaction is what owns the attributes the
 * five payload sections are projected from. There is no configuration kind and
 * adding one would be a breaking change to a shipped package.
 */
function report(
  onScrub: ((report: ScrubReport) => void) | undefined,
  keys: readonly string[],
  entries: number
): void {
  if (onScrub === undefined) {
    return;
  }

  const generated: ScrubReport = {
    kind: 'transaction',
    instances: entries,
    classes: new Set(),
    deniedKeys: keys,
    deniedValues: [],
    markersSeen: 0,
    markerClasses: new Set(),
    failed: false,
  };

  try {
    onScrub(generated);
  } catch {
    // A reporting callback that throws must not take the configuration with
    // it. This runs at startup, where the alternative is an agent that never
    // starts because a metrics counter was misconfigured.
  }
}
