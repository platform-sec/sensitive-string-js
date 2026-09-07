import { getPolicy, getRegisteredClasses } from '@platform-sec/sensitive-string-core';

/**
 * Two probes with nothing in common, used to tell a fixed marker from a mask.
 *
 * A policy's `redact` takes the value, so a custom one may return a partial
 * mask that differs per value. Only a redaction that is the same for both
 * probes is a marker this package can look for in a column, and a policy whose
 * redaction depends on the value cannot be recognised after the fact by
 * anything short of the value itself.
 */
const PROBE_A = 'aaaaaaaaaaaaaaaa';
const PROBE_B = 'ZZZZ-9999-ZZZZ-9999';

let cachedKey = '';
let cachedMarkers: ReadonlySet<string> = new Set();

/**
 * Every fixed redaction marker the policy registry can currently produce.
 *
 * Derived rather than hardcoded to the default shape, because
 * `registerPolicy()` accepts a `redact` of the caller's own and a package that
 * only knew the default would miss exactly the deployment that customised it.
 *
 * The default shape is included for every registered class regardless, so a row
 * written under the defaults is still recognised in a process that has since
 * replaced the policy.
 *
 * Recomputed when the set of registered class *names* changes, which is the
 * only signal core offers. Two consequences worth knowing, and neither matters
 * to an application that registers its policies at startup before it builds a
 * database handle, which is the ordinary shape:
 *
 * A policy re-registered under a name that already existed keeps the earlier
 * marker in the set. That is the safe direction, because the old marker may
 * still be sitting in a column written before the change.
 *
 * It does not pick up the *new* marker until the class list changes or
 * `resetMarkerCache()` is called. A process that replaces a policy after the
 * first read or write of a classified column should call it.
 */
export function redactionMarkers(): ReadonlySet<string> {
  const classes = getRegisteredClasses();
  const key = classes.join(' ');
  if (key === cachedKey) return cachedMarkers;

  const markers = new Set<string>(cachedMarkers);
  for (const klass of classes) {
    markers.add(`[REDACTED:${klass}]`);
    try {
      const a = getPolicy(klass).redact(PROBE_A);
      const b = getPolicy(klass).redact(PROBE_B);
      // A redaction that varies with the value is a mask, not a marker. There
      // is nothing to search a column for, and adding one probe's output would
      // make the check wrong in both directions at once.
      if (typeof a === 'string' && a === b && a !== '') markers.add(a);
    } catch {
      // A policy whose redaction throws cannot contribute a marker. It is not
      // this package's job to report that, and the default shape above still
      // covers the class.
    }
  }

  cachedKey = key;
  cachedMarkers = markers;
  return markers;
}

/**
 * Whether a string holds a redaction marker anywhere in it.
 *
 * Containment rather than equality, because the ways a marker reaches a column
 * are concatenation and interpolation as often as a bare assignment: a template
 * string built over a wrapped value produces a marker embedded in a longer one,
 * and that column is corrupt in exactly the same way.
 *
 * The false positive is a legitimate value that contains a marker as text.
 * Refusing it is the correct trade: the string is indistinguishable from the
 * corruption this exists to catch, and a column that holds one is a column
 * somebody needs to look at.
 */
export function containsRedactionMarker(value: string): boolean {
  for (const marker of redactionMarkers()) {
    if (value.includes(marker)) return true;
  }
  return false;
}

/** Reset the memo. Exported for tests that register a policy mid-run. */
export function resetMarkerCache(): void {
  cachedKey = '';
  cachedMarkers = new Set();
}
