/**
 * The `RuleTester` setup every rule suite shares.
 *
 * Three testers, because a rule in this plugin has to hold under more than one
 * parser. `espree` is what ESLint uses on a `.js` file and is the baseline; the
 * TypeScript parser produces the extra nodes (`TSAsExpression`,
 * `TSNonNullExpression`) that a cast or a non-null assertion wraps a reveal in,
 * and those are the shapes a rule most easily misses. Each suite runs its core
 * cases under `espree` and its cast-and-assert cases under TypeScript.
 *
 * The third adds a `ts.Program`, which is the whole difference between a rule
 * that can ask what a value's type contains and one that cannot. Only the two
 * rules that need one use it, because building a program is the expensive part
 * of a type-aware lint run.
 */
import { existsSync } from 'node:fs';
import nodePath from 'node:path';
import { ESLint, RuleTester } from 'eslint';
import type { Linter, Rule } from 'eslint';
import * as typescriptParser from '@typescript-eslint/parser';
import type { RuleModule } from '../types.js';

/**
 * The workspace root, found by walking up for the pnpm workspace manifest.
 *
 * Neither `import.meta.url` nor `__dirname` exists under both the Vitest
 * transform and the NodeNext CommonJS type-check, and the suites run from the
 * repository root and from the package directory alike, so the only reliable
 * anchor is a file that marks the root.
 */
export function workspaceRoot(): string {
  let directory = process.cwd();

  for (;;) {
    if (existsSync(nodePath.join(directory, 'pnpm-workspace.yaml'))) {
      return directory;
    }

    const parent = nodePath.dirname(directory);
    if (parent === directory) {
      throw new Error(`Could not find the workspace root above ${process.cwd()}.`);
    }
    directory = parent;
  }
}

/** This package's directory, wherever the suite was started from. */
export function packageRoot(): string {
  return nodePath.join(workspaceRoot(), 'packages', 'sensitive-eslint-plugin');
}

/**
 * The throwaway TypeScript project the type-aware suites lint inside.
 *
 * A rule that reads types needs a `ts.Program`, and a program needs a
 * `tsconfig.json` that contains the file being linted. The fixture holds
 * nothing but that: every test case declares the types it is about, so the
 * program has no dependencies and nothing in it can drift.
 */
const TYPE_AWARE_FIXTURE = () => nodePath.join(packageRoot(), 'src', '__tests__', 'fixtures');

/*
 * Both type-aware configurations below set `disallowAutomaticSingleRunInference`.
 *
 * `@typescript-eslint/parser` switches to "single run" mode when `CI=true` is
 * set, which every CI provider does. In that mode it builds the program once
 * from the files on disk and never swaps in the source a test case lints, so
 * each case is type-checked against the empty `file.ts` instead of its own
 * declarations. A rule that walks a property type still finds something, but
 * one that needs a lib type (an array, `Record`, `Partial`, a tuple) finds
 * nothing and the case reports no error. Measured: the suite passes locally
 * and 14 cases fail with `CI=true` and no other change.
 * `@typescript-eslint/rule-tester` sets the same option for the same reason.
 */

/** The name the fixture project includes, and so the name a case must lint as. */
const TYPE_AWARE_FILENAME = 'file.ts';

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

/**
 * A tester using `@typescript-eslint/parser` *with* type information.
 *
 * The difference from {@link createTypeScriptTester} is `project`, which is
 * what builds a `ts.Program` and puts a type checker on `parserServices`. It
 * costs a TypeScript program per suite, which is why only the two rules that
 * cannot work without one use it.
 */
export function createTypeAwareTester(): RuleTester {
  return new RuleTester({
    languageOptions: {
      parser: typescriptParser,
      ecmaVersion: 2022,
      sourceType: 'module',
      parserOptions: {
        project: './tsconfig.json',
        tsconfigRootDir: TYPE_AWARE_FIXTURE(),
        disallowAutomaticSingleRunInference: true,
      },
    },
  });
}

/**
 * Every case pinned to the one filename the fixture project contains.
 *
 * `RuleTester` defaults to `file.js`, which is not in the project, and
 * `@typescript-eslint/parser` treats a file outside the project as an error
 * rather than as an untyped file. Setting it per case rather than asking each
 * suite to remember is the difference between a rule suite and a suite about
 * `parserOptions`.
 */
function withFixtureFilename(tests: RuleTests): RuleTests {
  const pin = (test: RuleTests['valid'][number] | RuleTests['invalid'][number]): unknown =>
    typeof test === 'string'
      ? { code: test, filename: TYPE_AWARE_FILENAME }
      : { ...test, filename: TYPE_AWARE_FILENAME };

  return {
    valid: tests.valid.map(pin),
    invalid: tests.invalid.map(pin),
  } as RuleTests;
}

/** Run a suite under a parser that has a program, so types are available. */
export function runTypeAwareRuleTests(name: string, rule: RuleModule, tests: RuleTests): void {
  createTypeAwareTester().run(name, toEslintRule(rule), withFixtureFilename(tests));
}

/**
 * The fixture file's absolute path, for a lint run driven through `ESLint`
 * rather than through a `RuleTester`.
 */
export function typeAwareFilePath(): string {
  return nodePath.join(TYPE_AWARE_FIXTURE(), TYPE_AWARE_FILENAME);
}

/**
 * The flat-config layer that gives the fixture's files their types.
 *
 * Stacked under a `-type-checked` preset, this is what an `eslint.config.js`
 * doing type-aware linting looks like: one block naming the parser and the
 * project, and the preset on top of it.
 */
export function typeAwareLayer(): Record<string, unknown> {
  return {
    files: ['**/*.ts'],
    languageOptions: {
      parser: typescriptParser,
      ecmaVersion: 2022,
      sourceType: 'module',
      parserOptions: {
        project: './tsconfig.json',
        tsconfigRootDir: TYPE_AWARE_FIXTURE(),
        disallowAutomaticSingleRunInference: true,
      },
    },
  };
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
