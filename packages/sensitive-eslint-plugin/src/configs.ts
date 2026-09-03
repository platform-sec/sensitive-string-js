/**
 * The shipped presets.
 *
 * Two shapes of the same two presets. ESLint 9 reads flat config and ESLint 8
 * reads eslintrc, and the difference is not cosmetic: a flat config names the
 * plugin by holding the plugin object, an eslintrc names it by a string that
 * ESLint resolves itself. A preset written for one is silently inert in the
 * other, so both are built here from one list of rule settings and cannot drift
 * apart.
 *
 * The two type-aware rules the design calls for, `no-stringify-sensitive` and
 * `prefer-safe-log`, are not in these presets because they are not implemented.
 * A preset naming a rule that does not exist fails the whole lint run.
 */
import type { Plugin } from './types.js';

/**
 * The name a config file uses to reach these rules.
 *
 * ESLint derives it from the package name by dropping `eslint-plugin-`, so
 * `@platform-sec/eslint-plugin-sensitive-string` is written as
 * `@platform-sec/sensitive-string`. Spelling it out here keeps the flat and
 * eslintrc presets addressing the same rules.
 */
export const PLUGIN_NAMESPACE = '@platform-sec/sensitive-string';

/** A rule's setting, in the form both config formats accept. */
type RuleEntry = 'off' | 'warn' | 'error' | readonly ['off' | 'warn' | 'error', unknown];

/**
 * The default posture.
 *
 * The three rules that catch a value actually escaping are errors. The two that
 * ask for more auditability are warnings, because each has a shape it cannot
 * see (a context installed in a caller, a class supplied through a spread) and
 * a warning is the honest severity for a check that can be wrong.
 */
const RECOMMENDED_RULES: Readonly<Record<string, RuleEntry>> = {
  'no-log-reveal': 'error',
  'no-credential-equality': 'error',
  'no-network-sensitive': 'error',
  'explicit-class': 'warn',
  'require-reveal-context': 'warn',
};

/**
 * Everything on, at error, with the reveal context required to say why.
 *
 * `allowWithContext: false` also drops the exemption that lets an audited
 * reveal reach the network, so the only way a value leaves the process is
 * through `serialize()`.
 */
const STRICT_RULES: Readonly<Record<string, RuleEntry>> = {
  'no-log-reveal': 'error',
  'no-credential-equality': 'error',
  'no-network-sensitive': ['error', { allowWithContext: false }],
  'explicit-class': 'error',
  'require-reveal-context': ['error', { requireReason: true }],
};

/** Rule settings keyed by their fully qualified name. */
function qualify(rules: Readonly<Record<string, RuleEntry>>): Record<string, RuleEntry> {
  return Object.fromEntries(
    Object.entries(rules).map(([name, entry]) => [`${PLUGIN_NAMESPACE}/${name}`, entry])
  );
}

/** A flat-config object, for `eslint.config.js`. */
function flatConfig(
  plugin: Plugin,
  name: string,
  rules: Readonly<Record<string, RuleEntry>>
): Record<string, unknown> {
  return {
    name: `${PLUGIN_NAMESPACE}/${name}`,
    plugins: { [PLUGIN_NAMESPACE]: plugin },
    rules: qualify(rules),
  };
}

/** An eslintrc config object, for `.eslintrc.*`. */
function legacyConfig(rules: Readonly<Record<string, RuleEntry>>): Record<string, unknown> {
  return {
    plugins: [PLUGIN_NAMESPACE],
    rules: qualify(rules),
  };
}

/**
 * Every preset, built against the finished plugin object.
 *
 * A flat preset has to hold the plugin it configures, and the plugin has to
 * hold its presets, so one of the two references is filled in after the fact.
 * Taking the plugin as an argument keeps that knot in `index.ts`, where it is
 * visible, rather than hiding it behind a lazy getter.
 */
export function buildConfigs(plugin: Plugin): Record<string, unknown> {
  return {
    recommended: flatConfig(plugin, 'recommended', RECOMMENDED_RULES),
    strict: flatConfig(plugin, 'strict', STRICT_RULES),
    'legacy-recommended': legacyConfig(RECOMMENDED_RULES),
    'legacy-strict': legacyConfig(STRICT_RULES),
  };
}
