/**
 * End-to-end checks: the plugin loaded the way a project loads it.
 *
 * The rule suites exercise each rule against a `RuleTester`, which hands the
 * rule straight to a linter and never reads the plugin's manifest, its presets,
 * or its export shape. Everything that can be wrong about *packaging* a plugin
 * is therefore invisible to them: a preset naming a rule that does not exist, a
 * flat config holding the wrong object, an export shape one config format
 * cannot consume. Those are the failures a consumer meets first, so they are
 * checked here by running ESLint itself, in both config formats.
 */
import { readFileSync } from 'node:fs';
import nodePath from 'node:path';
import { describe, it, expect } from 'vitest';
import { Linter } from 'eslint';
import plugin, { PLUGIN_NAMESPACE, configs, rules } from './index.js';
import {
  lintFlat,
  packageRoot,
  typeAwareFilePath,
  typeAwareLayer,
} from './__tests__/rule-tester.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

/**
 * This package's own manifest.
 *
 * Located by walking up to the workspace root rather than from the module's own
 * path, because neither `import.meta.url` nor `__dirname` exists under both the
 * Vitest transform and the NodeNext CommonJS type-check, and the suite runs
 * from the repository root and from the package directory alike.
 */
function readPluginManifest(): { readonly name: string; readonly version: string } {
  const manifest = nodePath.join(packageRoot(), 'package.json');
  return JSON.parse(readFileSync(manifest, 'utf8')) as { name: string; version: string };
}

/** Code every preset must flag, carrying the raw value a miss would leak. */
const LEAKY_SOURCE = `const secret = new SensitiveString('${CANARY}', 'credential');\nconsole.log(secret.reveal());\n`;

/** A finding as `severity rule-name`, with the plugin prefix stripped. */
function describeFinding(message: { ruleId: string | null; severity: number }): string {
  const name = (message.ruleId ?? '(fatal)').replace(`${PLUGIN_NAMESPACE}/`, '');
  return `${message.severity === 2 ? 'error' : 'warn'} ${name}`;
}

/** The rule ids ESLint reports for a source under an eslintrc config. */
function lintLegacy(code: string, config: Record<string, unknown>): string[] {
  // The eslintrc presets are what an ESLint 8 consumer extends, so they have to
  // be exercised through the legacy linter. ESLint 9 still ships it behind
  // `configType`, and ESLint 10 removes it; when that floor moves, these two
  // cases go with it.
  const linter = new Linter({ configType: 'eslintrc' });
  linter.defineRules(
    Object.fromEntries(
      Object.entries(rules).map(([name, rule]) => [
        `${PLUGIN_NAMESPACE}/${name}`,
        rule as unknown as Parameters<Linter['defineRule']>[1],
      ])
    )
  );

  // An eslintrc names its plugin by a specifier ESLint resolves from disk. The
  // rules are registered directly here instead, which exercises the preset's
  // rule settings without publishing the package first.
  const { plugins: _plugins, ...withoutPluginName } = config;

  return linter
    .verify(code, {
      parserOptions: { ecmaVersion: 2022, sourceType: 'module' },
      ...withoutPluginName,
    })
    .map((message) => message.ruleId ?? '(fatal)');
}

describe('plugin', () => {
  it('exports the same objects as a default and as named exports', () => {
    // Flat config imports the default; eslintrc requires the module and reads
    // its named exports. Both have to reach the same rules.
    expect(plugin.rules).toBe(rules);
    expect(plugin.configs).toBe(configs);
  });

  it('declares the name and version the manifest does', () => {
    // `meta` is written by hand, because reading the manifest from `src` would
    // pull a file outside `rootDir` into the build. Nothing else would notice
    // it drifting: a stale version shows up only in ESLint's config inspector
    // and in the cache key it derives, both of them quiet failures.
    const manifest = readPluginManifest();

    expect(plugin.meta.name).toBe(manifest.name);
    expect(plugin.meta.version).toBe(manifest.version);
  });

  it('is named by the specifier ESLint derives from the package name', () => {
    // ESLint strips `eslint-plugin-` from a package name to get the prefix a
    // config writes. If these drift apart, every documented rule id is wrong.
    expect(plugin.meta.name.replace('eslint-plugin-', '')).toBe(PLUGIN_NAMESPACE);
  });

  describe('TST-ESL-INT-005: flat config', () => {
    it.each(['recommended', 'strict'])('%s loads and reports', async (name) => {
      const reported = (await lintFlat(LEAKY_SOURCE, configs[name])).map(
        (message) => message.ruleId
      );

      expect(reported).toContain(`${PLUGIN_NAMESPACE}/no-log-reveal`);
      expect(reported).not.toContain(null);
    });

    it('reports nothing on code that keeps the value wrapped', async () => {
      const clean = `const secret = new SensitiveString(raw, 'credential');\nconsole.log(secret);\n`;

      expect(await lintFlat(clean, configs['recommended'])).toEqual([]);
    });
  });

  describe('TST-ESL-INT-006: eslintrc config', () => {
    it.each(['legacy-recommended', 'legacy-strict'])('%s loads and reports', (name) => {
      const reported = lintLegacy(LEAKY_SOURCE, configs[name] as Record<string, unknown>);

      expect(reported).toContain(`${PLUGIN_NAMESPACE}/no-log-reveal`);
      expect(reported).not.toContain('(fatal)');
    });

    it.each(['legacy-recommended-type-checked', 'legacy-strict-type-checked'])(
      '%s loads, and its type-aware rules say what they are missing',
      (name) => {
        // ESLint 8 does type-aware linting too, through `parserOptions.project`.
        // This run has no program, so what it proves is that the eslintrc form
        // of the preset loads and that both rules report the configuration
        // rather than throwing or falling silent. `parserServices` lives on the
        // context rather than on `SourceCode` under this linter, which is the
        // path a flat-config run never takes.
        const reported = lintLegacy(LEAKY_SOURCE, configs[name] as Record<string, unknown>);

        expect(reported).not.toContain('(fatal)');
        expect(reported).toContain(`${PLUGIN_NAMESPACE}/no-stringify-sensitive`);
        expect(reported).toContain(`${PLUGIN_NAMESPACE}/prefer-safe-log`);
      }
    );

    it.each(['legacy-disable-type-checked'])('%s sets both to off', (name) => {
      const reported = lintLegacy(LEAKY_SOURCE, configs[name] as Record<string, unknown>);

      expect(reported).toEqual([]);
    });
  });

  describe('TST-ESL-INT-001 and INT-002: what each preset catches', () => {
    /** One file exercising three rules at once. */
    const MIXED_SOURCE = `const secret = new SensitiveString(raw);\nconsole.log(secret.reveal());\n`;

    async function findings(config: unknown): Promise<string[]> {
      return (await lintFlat(MIXED_SOURCE, config)).map(describeFinding).sort();
    }

    it('recommended errors on the leak and warns on the two auditability gaps', async () => {
      expect(await findings(configs['recommended'])).toEqual([
        'error no-log-reveal',
        'warn explicit-class',
        'warn require-reveal-context',
      ]);
    });

    it('strict raises the same three findings to errors', async () => {
      expect(await findings(configs['strict'])).toEqual([
        'error explicit-class',
        'error no-log-reveal',
        'error require-reveal-context',
      ]);
    });

    it('strict, unlike recommended, rejects an audited reveal on the wire', async () => {
      const send = `fetch(url, { headers: { Authorization: token.reveal({ name: 'auth' }) } });\n`;

      expect(await lintFlat(send, configs['recommended'])).toEqual([]);
      expect((await lintFlat(send, configs['strict'])).map((message) => message.ruleId)).toContain(
        `${PLUGIN_NAMESPACE}/no-network-sensitive`
      );
    });
  });

  describe('TST-ESL-INT-007: the type-checked presets', () => {
    /** A payload whose type holds a wrapper, and a log line that hands it over. */
    const TYPED_SOURCE = [
      'declare class SensitiveString { readonly klass: string }',
      'declare const payload: { token: SensitiveString };',
      'console.log(payload);',
      'JSON.stringify(payload);',
      '',
    ].join('\n');

    async function findings(config: unknown): Promise<string[]> {
      const messages = await lintFlat(
        TYPED_SOURCE,
        [typeAwareLayer(), config],
        typeAwareFilePath()
      );
      return messages.map(describeFinding).sort();
    }

    it('recommended-type-checked reports both type-aware rules at their own severities', async () => {
      expect(await findings(configs['recommended-type-checked'])).toEqual([
        'error no-stringify-sensitive',
        'warn prefer-safe-log',
      ]);
    });

    it('strict-type-checked raises both to errors', async () => {
      expect(await findings(configs['strict-type-checked'])).toEqual([
        'error no-stringify-sensitive',
        'error prefer-safe-log',
      ]);
    });

    it('recommended reports neither, because neither rule is in it', async () => {
      expect(await findings(configs['recommended'])).toEqual([]);
    });

    it('disable-type-checked silences them for a file with no program', async () => {
      // Layered over the type-checked preset, which is how a mixed project
      // keeps the two rules off the files a `tsconfig.json` does not cover.
      const layered = [configs['recommended-type-checked'], configs['disable-type-checked']];
      const messages = await lintFlat('console.log(payload);', layered, 'sample.js');

      expect(messages).toEqual([]);
    });

    it('says so, rather than falling silent, when the types are missing', async () => {
      // The failure this guards against is a clean run being read as a clean
      // file. Applied without a program, the rules report the configuration.
      const messages = await lintFlat('console.log(payload);', configs['recommended-type-checked']);

      expect(messages.map(describeFinding).sort()).toEqual([
        'error no-stringify-sensitive',
        'warn prefer-safe-log',
      ]);
      for (const message of messages) {
        expect(message.message).toContain('type information');
      }
    });
  });

  describe('TST-ESL-INT-003: TypeScript sources', () => {
    it('reports through a cast that would hide the reveal from a shallower check', async () => {
      const typescriptFiles = {
        files: ['**/*.ts'],
        languageOptions: {
          parser: await import('@typescript-eslint/parser'),
          parserOptions: { ecmaVersion: 2022, sourceType: 'module' },
        },
      };
      const source = `declare const secret: SensitiveString<'credential'>;\nconsole.log(secret.reveal() as string);\n`;

      const reported = (
        await lintFlat(source, [typescriptFiles, configs['recommended']], 'sample.ts')
      )
        .map(describeFinding)
        .sort();

      // The cast is transparent to the rules, so the log is still an error and
      // the contextless reveal is still a warning.
      expect(reported).toEqual(['error no-log-reveal', 'warn require-reveal-context']);
    });
  });
});
