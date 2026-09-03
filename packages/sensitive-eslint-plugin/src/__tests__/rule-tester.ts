/**
 * The `RuleTester` setup every rule suite shares.
 *
 * Two testers, because a rule in this plugin has to hold under both parsers.
 * `espree` is what ESLint uses on a `.js` file and is the baseline; the
 * TypeScript parser produces the extra nodes (`TSAsExpression`,
 * `TSNonNullExpression`) that a cast or a non-null assertion wraps a reveal in,
 * and those are the shapes a rule most easily misses. Each suite runs its core
 * cases under `espree` and its cast-and-assert cases under TypeScript.
 */
import { ESLint, RuleTester } from 'eslint';
import type { Linter, Rule } from 'eslint';
import * as typescriptParser from '@typescript-eslint/parser';
import type { RuleModule } from '../types.js';

/** The test-case shapes `RuleTester.run` accepts, so a suite can be typed. */
export type RuleTests = Parameters<RuleTester['run']>[2];

/**
 * A rule as ESLint's own types describe it.
 *
 * The rules are written against the structural types in `../types.js` so the
 * published `.d.ts` carries no dependency on ESLint's types. Those are the same
 * objects seen through a different declaration, so the crossing is a cast and
 * nothing more.
 */
function toEslintRule(rule: RuleModule): Rule.RuleModule {
  return rule as unknown as Rule.RuleModule;
}

/** A tester using `espree`, ESLint's default parser. */
export function createEspreeTester(): RuleTester {
  return new RuleTester({
    languageOptions: { ecmaVersion: 2022, sourceType: 'module' },
  });
}

/**
 * A tester using `@typescript-eslint/parser`, with no type information.
 *
 * Flat config takes the parser as the module object itself. Under eslintrc it
 * was an absolute path that ESLint required on our behalf, which needed the
 * package's entry *file* resolved through `createRequire` and a walk up from
 * the working directory to find whichever `node_modules` held the install.
 * Handing over the import erases all of that.
 */
export function createTypeScriptTester(): RuleTester {
  return new RuleTester({
    languageOptions: {
      parser: typescriptParser,
      ecmaVersion: 2022,
      sourceType: 'module',
    },
  });
}

/** Run a suite under `espree`. */
export function runRuleTests(name: string, rule: RuleModule, tests: RuleTests): void {
  createEspreeTester().run(name, toEslintRule(rule), tests);
}

/** Run a suite under `@typescript-eslint/parser`. */
export function runTypeScriptRuleTests(name: string, rule: RuleModule, tests: RuleTests): void {
  createTypeScriptTester().run(name, toEslintRule(rule), tests);
}

/**
 * One finding, as ESLint's flat-config linter returns it.
 *
 * Declared structurally, rather than reusing `Linter.LintMessage`, for the same
 * reason `../types.js` declares the rule API: it keeps a suite asserting on the
 * fields it actually reads instead of tracking a shape ESLint is free to widen.
 */
export interface FlatLintMessage {
  readonly ruleId: string | null;
  readonly severity: number;
  readonly message: string;
  /**
   * Present only on a message the rule attached suggestions to. Spelled
   * with an explicit `undefined` because `exactOptionalPropertyTypes` keeps
   * an optional marker from implying it, and ESLint's own `LintMessage`
   * declares the property as present-and-undefined.
   */
  readonly suggestions?: readonly unknown[] | undefined;
}

/**
 * Lint a source under a flat config, the way an `eslint.config.js` does.
 *
 * `config` is one config object or the layered array a real `eslint.config.js`
 * exports, so a test can stack a parser layer under a preset. It arrives as
 * `unknown` because the presets are published that way, and the cast here is
 * the one place that is narrowed.
 *
 * Worth running even though the rule suites pass: a `RuleTester` hands a rule
 * straight to a linter and never reads the plugin's presets or export shape, so
 * everything that can be wrong about packaging a plugin is invisible to it.
 */
export async function lintFlat(
  code: string,
  config: unknown,
  filePath = 'sample.js'
): Promise<readonly FlatLintMessage[]> {
  const overrideConfig = (Array.isArray(config) ? config : [config]) as Linter.Config[];

  // `overrideConfigFile: true` stops ESLint searching upwards for the
  // repository's own `eslint.config.mjs`, which would otherwise merge into
  // every one of these assertions.
  const eslint = new ESLint({ overrideConfigFile: true, overrideConfig });
  const [result] = await eslint.lintText(code, { filePath });

  return result?.messages ?? [];
}
