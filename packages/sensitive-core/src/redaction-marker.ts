import { getPolicy, getRegisteredClasses, policyRegistryVersion } from './policy.js';

/**
 * Recognising this library's own redacted output in a string.
 *
 * Every guard that refuses to hand a redaction onward needs the same answer:
 * given a string that is about to be written to a column, sent in a request
 * body or stored in a secret, does it carry the text a `SensitiveString`
 * renders as? Three packages arrived at that question independently and wrote
 * three detectors, and the two written for a database missed the one case core
 * had already provided for, {@link SensitivityPolicy.markerPattern}. This is
 * the one detector, in the package that owns the format.
 *
 * What it cannot do is stated once here rather than in each caller. This is a
 * heuristic. A legitimate value containing a marker as text is refused, which
 * is the correct direction: the string is indistinguishable from the corruption
 * the guards exist to catch. And a policy whose `redact` varies with its input
 * and declares no `markerPattern` is recognised only if it uses the default
 * prefix, because there is nothing constant to look for.
 */

/**
 * Two probes handed to a policy's `redact` to learn what its marker looks like.
 *
 * Two rather than one, and of different lengths, because one probe cannot tell
 * a constant redaction from a value-dependent one. A policy that renders
 * `len:29` gives the same shape for one probe as a constant would, and a needle
 * derived from it would fire on unrelated strings while missing every real
 * marker. Two probes that disagree is the test for both.
 *
 * Both are conspicuous and non-secret, so a needle accidentally derived from
 * one is inert rather than dangerous.
 */
const PROBE_A = 'SENSITIVE_STRING_MARKER_PROBE';
const PROBE_B = 'SENSITIVE_STRING_MARKER_PROBE_OF_A_DELIBERATELY_DIFFERENT_LENGTH';

/** The prefix every default policy in core produces. */
export const MARKER_PREFIX = '[REDACTED:';

let cachedVersion = -1;
let cached: readonly (string | RegExp)[] = [];

/**
 * Every matcher that recognises a redaction the policy registry can produce.
 *
 * Derived from the registry rather than hardcoded, because `registerPolicy()`
 * accepts a `redact` of the caller's own and a guard that only knew the default
 * shape would miss exactly the deployment that customised it. Three sources,
 * in the order they are cheapest to be sure of:
 *
 * {@link MARKER_PREFIX} unconditionally, which covers every default policy and
 * every class this process has never registered. That last part is what a
 * persistence guard needs and a transport guard does not: a column written by
 * an older release, or by a service that registered a class this one does not
 * have, still holds `[REDACTED:whatever]`, and the reader has to recognise it.
 *
 * Each policy's `markerPattern`, for a value-dependent redaction that declares
 * its own shape. `deterministicRedaction()` sets it. Read through `search()`
 * rather than `test()`, because a caller's pattern may carry `g` despite the
 * warning on the field, and `test()` on a global pattern advances `lastIndex`
 * so the next call starts mid-string and misses.
 *
 * Each policy's constant redaction, discovered with the two probes above.
 *
 * Memoized against {@link policyRegistryVersion}, so the probes run once per
 * registry change rather than once per bound parameter. The version moves on an
 * `overwrite` re-registration too, which a memo keyed on the set of class names
 * would not see.
 */
export function redactionMatchers(): readonly (string | RegExp)[] {
  const version = policyRegistryVersion();
  if (version === cachedVersion) return cached;

  const matchers: (string | RegExp)[] = [MARKER_PREFIX];

  for (const klass of getRegisteredClasses()) {
    let policy;
    try {
      policy = getPolicy(klass);
    } catch {
      // Registered a moment ago and gone now. Nothing to derive.
      continue;
    }

    // Declared on `SensitivityPolicy` by core, and checked rather than trusted:
    // a policy arrives from an application and the field is optional.
    if (policy.markerPattern instanceof RegExp) matchers.push(policy.markerPattern);

    let first: string;
    let second: string;
    try {
      first = policy.redact(PROBE_A);
      second = policy.redact(PROBE_B);
    } catch {
      // A policy that refuses to redact a probe contributes no needle. The
      // prefix above still covers it if it uses the default format.
      continue;
    }

    if (typeof first !== 'string' || first === '' || first !== second) continue;
    if (!matchers.includes(first)) matchers.push(first);
  }

  cachedVersion = version;
  cached = matchers;
  return matchers;
}

/**
 * Whether a string carries a redaction marker anywhere in it.
 *
 * Containment rather than equality, because the ways a marker reaches a column
 * or a request body are concatenation and interpolation as often as a bare
 * assignment: a template string built over a wrapped value produces a marker
 * embedded in a longer one, and that value is corrupt in exactly the same way.
 */
export function containsRedactionMarker(value: string): boolean {
  if (typeof value !== 'string' || value === '') return false;

  for (const matcher of redactionMatchers()) {
    if (typeof matcher === 'string' ? value.includes(matcher) : value.search(matcher) !== -1) {
      return true;
    }
  }

  return false;
}

/**
 * Drop the memo.
 *
 * Rarely needed: {@link policyRegistryVersion} already moves on every
 * registration and every reset. It exists for a test that mutates a policy
 * object in place, which the registry cannot see.
 */
export function resetRedactionMarkerCache(): void {
  cachedVersion = -1;
  cached = [];
}
