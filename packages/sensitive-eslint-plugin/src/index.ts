/**
 * @platform-sec/eslint-plugin-sensitive-string
 *
 * Lint rules for the mistakes `SensitiveString`'s type system cannot catch.
 *
 * A type keeps a secret wrapped. It cannot stop `console.log(secret.reveal())`,
 * because the reveal produces an ordinary string and logging a string is
 * ordinary code. Seven rules read the call instead.
 *
 * Five of them read syntax alone, so they run under any parser and cost
 * nothing beyond the parse:
 *
 * - `no-log-reveal` stops a revealed value reaching a logger.
 * - `no-credential-equality` stops `===` on a revealed value, which leaks its
 *   contents through timing.
 * - `no-network-sensitive` stops an unaudited reveal crossing the network.
 * - `explicit-class` asks for the sensitivity class at construction.
 * - `require-reveal-context` asks a reveal to say who is reading and why.
 *
 * Two answer a question no syntax can, "does this value carry a sensitive one
 * inside it", and so need typescript-eslint's type-aware mode:
 *
 * - `no-stringify-sensitive` stops `JSON.stringify` silently substituting a
 *   redaction, and stops it writing a `serialize()` result in the clear.
 * - `prefer-safe-log` moves the redaction of a logged structure out of
 *   whichever serializer the transport installed and into the call site.
 *
 * The type-aware pair lives only in the `*-type-checked` presets, so a
 * consumer who has not configured a program never meets them.
 *
 * @example Flat config
 * ```js
 * import sensitive from '@platform-sec/eslint-plugin-sensitive-string';
 *
 * export default [sensitive.configs.recommended];
 * ```
 *
 * @example eslintrc
 * ```js
 * module.exports = {
 *   extends: ['plugin:@platform-sec/sensitive-string/legacy-recommended'],
 * };
 * ```
 *
 * @packageDocumentation
 */
import { buildConfigs } from './configs.js';
import { explicitClass } from './rules/explicit-class.js';
import { noCredentialEquality } from './rules/no-credential-equality.js';
import { noLogReveal } from './rules/no-log-reveal.js';
import { noNetworkSensitive } from './rules/no-network-sensitive.js';
import { noStringifySensitive } from './rules/no-stringify-sensitive.js';
import { preferSafeLog } from './rules/prefer-safe-log.js';
import { requireRevealContext } from './rules/require-reveal-context.js';
import type { Plugin, RuleModule } from './types.js';

/** Every rule this plugin defines, keyed by the name a config uses. */
export const rules: Readonly<Record<string, RuleModule>> = {
  'explicit-class': explicitClass,
  'no-credential-equality': noCredentialEquality,
  'no-log-reveal': noLogReveal,
  'no-network-sensitive': noNetworkSensitive,
  'no-stringify-sensitive': noStringifySensitive,
  'prefer-safe-log': preferSafeLog,
  'require-reveal-context': requireRevealContext,
};

/**
 * Plugin identity, which flat config uses to name the plugin in its output and
 * which ESLint's config inspector reads.
 */
export const meta = {
  name: '@platform-sec/eslint-plugin-sensitive-string',
  version: '0.1.0',
} as const;

/**
 * The presets: `recommended`, `strict`, their `-type-checked` forms and
 * `disable-type-checked`, each in a flat and a `legacy-` eslintrc shape.
 *
 * Filled in after the plugin exists, because a flat preset holds the plugin
 * object it configures and the plugin holds its presets. The two names are one
 * object, so a config reached through `plugin.configs` and one reached through
 * this export cannot come apart.
 */
export const configs: Record<string, unknown> = {};

const plugin: Plugin = { meta, rules, configs };
Object.assign(configs, buildConfigs(plugin));

export {
  explicitClass,
  noCredentialEquality,
  noLogReveal,
  noNetworkSensitive,
  noStringifySensitive,
  preferSafeLog,
  requireRevealContext,
};
export { PLUGIN_NAMESPACE } from './configs.js';
export type {
  AstNode,
  Plugin,
  ReportDescriptor,
  RuleContext,
  RuleFix,
  RuleFixer,
  RuleListener,
  RuleMeta,
  RuleMetaDocs,
  RuleModule,
  SourceCode,
  SuggestionDescriptor,
} from './types.js';

/**
 * The plugin object.
 *
 * Both module shapes work on purpose. Flat config does
 * `import plugin from '...'` and gets this default; eslintrc does
 * `require('...')` and gets the module namespace, whose `rules` and `configs`
 * named exports are the same objects this default holds. Neither format needs
 * an interop shim.
 */
export default plugin;
