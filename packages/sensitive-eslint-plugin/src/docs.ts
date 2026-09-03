/**
 * Where a rule's documentation lives.
 *
 * `meta.docs.url` is what an editor turns into the "learn more" link on a
 * report, and ESLint requires an absolute URL for it. This project has no
 * public repository yet, so there is no honest absolute URL to give: pointing
 * the link at a guessed host would put a dead link in front of every developer
 * who hovers a finding, which is worse than no link at all.
 *
 * The markdown under `docs/rules/` ships in the package either way, so the
 * documentation is present in `node_modules` regardless. When the project gets
 * a home, set {@link DOCS_BASE_URL} and every rule picks the link up.
 */

/** The published location of `docs/rules/`, with a trailing slash, or `undefined`. */
export const DOCS_BASE_URL: string | undefined = undefined;

/**
 * The `docs` block for a rule, carrying a `url` only when there is one to give.
 *
 * `url` is omitted rather than set to `undefined` because `exactOptionalPropertyTypes`
 * distinguishes the two, and because ESLint's own config-inspector renders an
 * explicit `undefined` as a broken link.
 */
export function ruleDocs(
  ruleName: string,
  description: string,
  recommended: boolean,
  base: string | undefined = DOCS_BASE_URL
): { readonly description: string; readonly recommended: boolean; readonly url?: string } {
  if (base === undefined) {
    return { description, recommended };
  }
  return { description, recommended, url: `${base}${ruleName}.md` };
}
