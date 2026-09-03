/**
 * @platform-sec/eslint-plugin-sensitive-string
 *
 * Lint rules for the mistakes `SensitiveString`'s type system cannot catch.
 *
 * A type keeps a secret wrapped. It cannot stop `console.log(secret.reveal())`,
 * because the reveal produces an ordinary string and logging a string is
 * ordinary code. These five rules read the shape of the call instead.
 *
 * - `no-log-reveal` stops a revealed value reaching a logger.
 * - `no-credential-equality` stops `===` on a revealed value, which leaks its
 *   contents through timing.
 * - `no-network-sensitive` stops an unaudited reveal crossing the network.
 * - `explicit-class` asks for the sensitivity class at construction.
 * - `require-reveal-context` asks a reveal to say who is reading and why.
 *
 * All five work from the syntax alone, so they run under any parser and cost
 * nothing beyond the parse. The two rules the design also calls for,
 * `no-stringify-sensitive` and `prefer-safe-log`, need type information to say
 * whether a value is sensitive at all; guessing from a variable's name would
 * report the wrong lines and, worse, stay quiet on the right ones. They are not
 * shipped here.
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
import { requireRevealContext } from './rules/require-reveal-context.js';
import type { Plugin, RuleModule } from './types.js';

/** Every rule this plugin defines, keyed by the name a config uses. */
export const rules: Readonly<Record<string, RuleModule>> = {
  'explicit-class': explicitClass,
  'no-credential-equality': noCredentialEquality,
  'no-log-reveal': noLogReveal,
  'no-network-sensitive': noNetworkSensitive,
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

const plugin: Plugin = { meta, rules, configs: {} };

/**
 * The presets: `recommended` and `strict` for flat config,
 * `legacy-recommended` and `legacy-strict` for eslintrc.
 *
 * Assigned onto the plugin after it exists because a flat preset holds the
 * plugin object it configures.
 */
export const configs: Record<string, unknown> = buildConfigs(plugin);
Object.assign(plugin.configs, configs);

export {
  explicitClass,
  noCredentialEquality,
  noLogReveal,
  noNetworkSensitive,
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
