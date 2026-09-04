/**
 * Label derivation, and the constraint behind it.
 *
 * A label is not private. Core's inspect hook renders
 *
 * ```
 * SensitiveString<credential:prod/db/password> { [REDACTED:credential] }
 * ```
 *
 * so the label appears in every `console.log`, every structured log line, and
 * every error tracker event that touches the value. A label is as public as the
 * redaction marker itself.
 *
 * Every provider has a natural identifier that is unsafe under that rule: an
 * AWS ARN carries the account ID, a Key Vault URL carries the tenant's DNS
 * name, a GCP resource name carries the project number, a Vault endpoint
 * carries an internal hostname and port. The rule is that a label is the
 * logical path within the store, and everything identifying the account,
 * project, tenancy, subscription, cluster, or host is stripped.
 *
 * The account-scoped identifier is not discarded. It goes on
 * `ResolvedSecretRef.metadata`, which reaches the load hook and never reaches
 * redacted output.
 */

/** A scheme and authority, `https://vault.internal:8200/`, at the head of a value. */
const AUTHORITY = /^[a-z][a-z0-9+.-]*:\/\/[^/]*\/?/i;

/** A query string or fragment, which carries nothing a label needs. */
const TRAILING = /[?#].*$/;

/**
 * Reduce a provider identifier to the logical path within its store.
 *
 * Strips a scheme and authority, a leading slash, a query string, and a
 * fragment, then collapses repeated separators. It does not attempt to
 * recognize an ARN or an OCID: those are shaped per provider, and each provider
 * package extracts its logical path before calling here rather than asking this
 * function to guess.
 */
export function logicalLabel(identifier: string): string {
  const withoutAuthority = identifier.replace(AUTHORITY, '');
  const withoutTrailing = withoutAuthority.replace(TRAILING, '');

  return withoutTrailing
    .replace(/\/{2,}/g, '/')
    .replace(/^\/+/, '')
    .replace(/\/+$/, '');
}

/**
 * The label for one field of a multi-value secret.
 *
 * `prod/db#password` keeps the field name attached to the class in redacted
 * output while staying inside the rule above, because the path half was already
 * reduced to the logical path.
 */
export function fieldLabel(path: string, field: string): string {
  return `${path}#${field}`;
}

/**
 * Patterns that indicate a label still carries something the rule strips.
 *
 * Exported because the check that matters is a test rather than a runtime
 * guard: nothing stops a caller passing `label` explicitly, and nothing can,
 * since a label is a free string. Provider packages get the default right and
 * assert it with this list.
 */
export const DISCLOSING_LABEL_PATTERNS: readonly { name: string; pattern: RegExp }[] = [
  { name: 'scheme and authority', pattern: /^[a-z][a-z0-9+.-]*:\/\//i },
  // Written without a nested quantifier on purpose: the suite runs every
  // pattern here through `safe-regex2`, and the obvious `(\.[a-z0-9-]+)+`
  // form fails it.
  { name: 'host and port', pattern: /[a-z0-9][a-z0-9.-]*\.[a-z0-9-]+:\d+/i },
  { name: 'AWS ARN', pattern: /^arn:/i },
  { name: 'OCID', pattern: /^ocid\d*\./i },
  { name: 'AWS account id', pattern: /\b\d{12}\b/ },
  { name: 'GCP project number', pattern: /^projects\/\d+/ },
];

/**
 * Which disclosure rules a label trips, if any.
 *
 * Returns the names rather than throwing, so a provider package can assert an
 * empty result in its suite and a caller can report one without the library
 * deciding to fail a load over a string it did not choose.
 */
export function describeLabelDisclosure(label: string): string[] {
  return DISCLOSING_LABEL_PATTERNS.filter(({ pattern }) => pattern.test(label)).map(
    ({ name }) => name
  );
}
