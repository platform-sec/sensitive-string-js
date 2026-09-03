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
import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { RuleTester } from 'eslint';
import type { Rule } from 'eslint';
import type { RuleModule } from '../types.js';

/** The test-case shapes `RuleTester.run` accepts, so a suite can be typed. */
export type RuleTests = Parameters<RuleTester['run']>[2];

/**
 * The TypeScript parser's entry file, as an absolute path.
 *
 * Two things make this less direct than it looks.
 *
 * `RuleTester` takes a parser as a path that it requires itself, and asserts
 * the path is absolute, so a bare specifier will not do. The path also has to
 * name the entry *file*: `@typescript-eslint/parser` ships an `exports` map and
 * no `main`, and `require()` of a directory consults only `main`, so requiring
 * the package directory fails outright.
 *
 * Resolution therefore runs through `createRequire`, which honours `exports`,
 * anchored at whichever directory above the working directory actually holds
 * the install. Walking up is what makes the suite indifferent to where it was
 * started: `pnpm test` runs from the repository root and
 * `cd packages/... && pnpm test` runs from the package, and neither
 * `import.meta.url` nor `__dirname` is available under both the Vitest
 * transform and the NodeNext CommonJS type-check.
 */
function resolveTypeScriptParser(): string {
  let directory = process.cwd();

  for (;;) {
    if (existsSync(path.join(directory, 'node_modules', '@typescript-eslint', 'parser'))) {
      return createRequire(path.join(directory, 'package.json')).resolve(
        '@typescript-eslint/parser'
      );
    }

    const parent = path.dirname(directory);
    if (parent === directory) {
      throw new Error(
        `Could not find @typescript-eslint/parser above ${process.cwd()}. Run pnpm install.`
      );
    }
    directory = parent;
  }
}

/**
 * A rule as ESLint's own types describe it.
 *
 * The rules are written against the structural types in `../types.js` so the
 * published `.d.ts` carries no dependency on `@types/eslint`. That package is a
 * development dependency here and its `Rule.RuleModule` is the same object seen
 * through a different declaration, so the crossing is a cast and nothing more.
 */
function toEslintRule(rule: RuleModule): Rule.RuleModule {
  return rule as unknown as Rule.RuleModule;
}

/** A tester using `espree`, ESLint's default parser. */
export function createEspreeTester(): RuleTester {
  return new RuleTester({
    parserOptions: { ecmaVersion: 2022, sourceType: 'module' },
  });
}

/** A tester using `@typescript-eslint/parser`, with no type information. */
export function createTypeScriptTester(): RuleTester {
  return new RuleTester({
    parser: resolveTypeScriptParser(),
    parserOptions: { ecmaVersion: 2022, sourceType: 'module' },
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
 * Declared here because ESLint 8 ships flat config behind an unstable entry
 * point that `@types/eslint@8` names but does not describe. The cast in
 * {@link lintFlat} is the only place the untyped surface is crossed.
 */
export interface FlatLintMessage {
  readonly ruleId: string | null;
  readonly severity: number;
  readonly message: string;
  readonly suggestions?: readonly unknown[];
}

interface FlatLintResult {
  readonly messages: readonly FlatLintMessage[];
}

interface FlatEslint {
  lintText(code: string, options: { filePath: string }): Promise<readonly FlatLintResult[]>;
}

interface FlatEslintModule {
  readonly FlatESLint: new (options: {
    overrideConfigFile: boolean;
    overrideConfig: readonly unknown[];
  }) => FlatEslint;
}

/**
 * Lint a source under a flat config, the way ESLint 9 and a modern ESLint 8
 * project do.
 *
 * `config` is one config object or the layered array a real `eslint.config.js`
 * exports, so a test can stack a parser layer under a preset.
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
  const { FlatESLint } = (await import(
    'eslint/use-at-your-own-risk'
  )) as unknown as FlatEslintModule;

  const eslint = new FlatESLint({
    overrideConfigFile: true,
    overrideConfig: Array.isArray(config) ? config : [config],
  });
  const [result] = await eslint.lintText(code, { filePath });

  return result?.messages ?? [];
}
