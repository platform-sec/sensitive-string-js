import { describe, it, expect } from 'vitest';
import plugin, { PLUGIN_NAMESPACE, configs, rules } from './index.js';

/** The rule names a preset sets, with the plugin prefix stripped. */
function ruleNamesIn(config: unknown): string[] {
  const setting = (config as { rules?: Record<string, unknown> }).rules ?? {};
  return Object.keys(setting).map((name) => name.slice(`${PLUGIN_NAMESPACE}/`.length));
}

/** The severity a preset sets for a rule, whether or not options accompany it. */
function severityIn(config: unknown, ruleName: string): string | undefined {
  const setting = (config as { rules?: Record<string, unknown> }).rules ?? {};
  const entry = setting[`${PLUGIN_NAMESPACE}/${ruleName}`];
  return Array.isArray(entry) ? (entry[0] as string) : (entry as string | undefined);
}

const FLAT_TO_LEGACY: Readonly<Record<string, string>> = {
  recommended: 'legacy-recommended',
  strict: 'legacy-strict',
};

describe('configs', () => {
  it('ships a flat and an eslintrc form of each preset', () => {
    expect(Object.keys(configs).sort()).toEqual([
      'legacy-recommended',
      'legacy-strict',
      'recommended',
      'strict',
    ]);
  });

  it.each(Object.keys(configs))('%s names only rules the plugin defines', (name) => {
    const configured = ruleNamesIn(configs[name]);

    expect(configured.length).toBeGreaterThan(0);
    for (const ruleName of configured) {
      // A preset naming a rule that does not exist fails the entire lint run
      // for every consumer, so this is the check that has to hold.
      expect(Object.keys(rules)).toContain(ruleName);
    }
  });

  it.each(Object.entries(FLAT_TO_LEGACY))(
    '%s and %s configure the same rules at the same severities',
    (flatName, legacyName) => {
      const flat = configs[flatName];
      const legacy = configs[legacyName];

      expect(ruleNamesIn(legacy).sort()).toEqual(ruleNamesIn(flat).sort());
      for (const ruleName of ruleNamesIn(flat)) {
        expect(severityIn(legacy, ruleName)).toBe(severityIn(flat, ruleName));
      }
    }
  );

  it('covers every rule in both presets, so no rule ships unreachable', () => {
    for (const name of Object.keys(configs)) {
      expect(ruleNamesIn(configs[name]).sort()).toEqual(Object.keys(rules).sort());
    }
  });

  describe('recommended', () => {
    it('errors on the rules that catch a value escaping', () => {
      for (const ruleName of ['no-log-reveal', 'no-credential-equality', 'no-network-sensitive']) {
        expect(severityIn(configs['recommended'], ruleName)).toBe('error');
      }
    });

    it('warns on the two rules that cannot see the whole program', () => {
      // Each has a shape it provably cannot resolve without types: a context
      // installed in a caller, a class supplied through a spread. A warning is
      // the honest severity for a check that can be wrong.
      for (const ruleName of ['explicit-class', 'require-reveal-context']) {
        expect(severityIn(configs['recommended'], ruleName)).toBe('warn');
      }
    });
  });

  describe('strict', () => {
    it('errors on everything', () => {
      for (const ruleName of Object.keys(rules)) {
        expect(severityIn(configs['strict'], ruleName)).toBe('error');
      }
    });

    it('requires a reason and forbids even an audited reveal on the wire', () => {
      const setting = (configs['strict'] as { rules: Record<string, unknown> }).rules;

      expect(setting[`${PLUGIN_NAMESPACE}/require-reveal-context`]).toEqual([
        'error',
        { requireReason: true },
      ]);
      expect(setting[`${PLUGIN_NAMESPACE}/no-network-sensitive`]).toEqual([
        'error',
        { allowWithContext: false },
      ]);
    });
  });

  describe('flat form', () => {
    it.each(['recommended', 'strict'])('%s carries the plugin object itself', (name) => {
      const config = configs[name] as { plugins: Record<string, unknown>; name: string };

      // A flat config names a plugin by holding it. Holding anything but this
      // object would configure rules that are never loaded.
      expect(config.plugins[PLUGIN_NAMESPACE]).toBe(plugin);
      expect(config.name).toBe(`${PLUGIN_NAMESPACE}/${name}`);
    });
  });

  describe('eslintrc form', () => {
    it.each(['legacy-recommended', 'legacy-strict'])('%s names the plugin by string', (name) => {
      // An eslintrc names a plugin by a specifier ESLint resolves itself, and
      // must not hold the object.
      expect(configs[name]).toMatchObject({ plugins: [PLUGIN_NAMESPACE] });
    });
  });
});
