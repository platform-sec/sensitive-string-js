/**
 * The shipped presets.
 *
 * Two shapes of the same presets. ESLint 9 reads flat config and ESLint 8
 * reads eslintrc, and the difference is not cosmetic: a flat config names the
 * plugin by holding the plugin object, an eslintrc names it by a string that
 * ESLint resolves itself. A preset written for one is silently inert in the
 * other, so both are built here from one list of rule settings and cannot drift
 * apart.
 *
 * The other split is type information. `no-stringify-sensitive` and
 * `prefer-safe-log` have to ask what a value's type contains, so they belong
 * only in a preset whose consumer has configured a TypeScript program. Put in
 * `recommended`, they would report a misconfiguration on every plain
 * JavaScript file, which is the noise that gets a plugin removed. They live in
 * the `-type-checked` presets instead, and `disable-type-checked` turns them
 * back off for the files in a mixed project that have no program.
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

/**
 * The two rules that need a program, at the severity `recommended` would give
 * them.
 *
 * `no-stringify-sensitive` is an error because both things it catches are
 * definite: a `serialize()` result written out in the clear, and a redaction
 * substituted for a value that was supposed to arrive somewhere. Neither is a
 * judgement call.
 *
 * `prefer-safe-log` is a warning because most of what it reports is not yet a
 * leak. A `SensitiveString` inside a logged object redacts itself today,
 * through whichever of `toJSON` and `util.inspect` the transport reaches for;
 * the rule is about not depending on that. The one case that is a leak, a
 * `serialize()` result in a log line, gets its own message.
 */
const TYPE_AWARE_RULES: Readonly<Record<string, RuleEntry>> = {
  'no-stringify-sensitive': 'error',
  'prefer-safe-log': 'warn',
};

/** The same two at error, for `strict-type-checked`. */
const STRICT_TYPE_AWARE_RULES: Readonly<Record<string, RuleEntry>> = {
  'no-stringify-sensitive': 'error',
  'prefer-safe-log': 'error',
};

/**
 * The type-aware rules off.
 *
 * For the block of a flat config that matches the files a program does not
 * cover: plain JavaScript, generated code, anything outside `tsconfig.json`.
 * Layered after a `-type-checked` preset it silences the two rules there,
 * which is what those rules do instead of failing quietly on a file whose
 * types they cannot see.
 */
const DISABLED_TYPE_AWARE_RULES: Readonly<Record<string, RuleEntry>> = {
  'no-stringify-sensitive': 'off',
  'prefer-safe-log': 'off',
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
  const recommendedTypeChecked = { ...RECOMMENDED_RULES, ...TYPE_AWARE_RULES };
  const strictTypeChecked = { ...STRICT_RULES, ...STRICT_TYPE_AWARE_RULES };

  return {
    recommended: flatConfig(plugin, 'recommended', RECOMMENDED_RULES),
    strict: flatConfig(plugin, 'strict', STRICT_RULES),
    'recommended-type-checked': flatConfig(
      plugin,
      'recommended-type-checked',
      recommendedTypeChecked
    ),
    'strict-type-checked': flatConfig(plugin, 'strict-type-checked', strictTypeChecked),
    'disable-type-checked': flatConfig(plugin, 'disable-type-checked', DISABLED_TYPE_AWARE_RULES),
    'legacy-recommended': legacyConfig(RECOMMENDED_RULES),
    'legacy-strict': legacyConfig(STRICT_RULES),
    'legacy-recommended-type-checked': legacyConfig(recommendedTypeChecked),
    'legacy-strict-type-checked': legacyConfig(strictTypeChecked),
    'legacy-disable-type-checked': legacyConfig(DISABLED_TYPE_AWARE_RULES),
  };
}
