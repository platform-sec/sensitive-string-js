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
  'recommended-type-checked': 'legacy-recommended-type-checked',
  'strict-type-checked': 'legacy-strict-type-checked',
  'disable-type-checked': 'legacy-disable-type-checked',
};

/** The rules that cannot say anything without a TypeScript program. */
const TYPE_AWARE_RULE_NAMES = Object.entries(rules)
  .filter(([, rule]) => rule.meta.docs.requiresTypeChecking === true)
  .map(([name]) => name)
  .sort();

/** Everything else, which runs on syntax alone. */
const UNTYPED_RULE_NAMES = Object.keys(rules)
  .filter((name) => !TYPE_AWARE_RULE_NAMES.includes(name))
  .sort();

describe('configs', () => {
  it('ships a flat and an eslintrc form of each preset', () => {
    expect(Object.keys(configs).sort()).toEqual(
      [
        'disable-type-checked',
        'legacy-disable-type-checked',
        'legacy-recommended',
        'legacy-recommended-type-checked',
        'legacy-strict',
        'legacy-strict-type-checked',
        'recommended',
        'strict',
        'strict-type-checked',
        'recommended-type-checked',
      ].sort()
    );
  });

  it('marks exactly the two rules that need a program', () => {
    // The flag is what `configs.ts` splits the presets on, so it is also what
    // decides whether a new rule lands in a preset that runs over plain
    // JavaScript. Naming the pair here means adding a third cannot happen by
    // accident.
    expect(TYPE_AWARE_RULE_NAMES).toEqual(['no-stringify-sensitive', 'prefer-safe-log']);
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

  it.each(['recommended', 'strict'])('%s holds only rules that work without a program', (name) => {
    // A type-aware rule in an untyped preset reports a misconfiguration on
    // every plain JavaScript file in the project, which is the noise that
    // gets a plugin removed rather than configured.
    expect(ruleNamesIn(configs[name]).sort()).toEqual(UNTYPED_RULE_NAMES);
  });

  it.each(['recommended-type-checked', 'strict-type-checked'])(
    '%s covers every rule, so none ships unreachable',
    (name) => {
      expect(ruleNamesIn(configs[name]).sort()).toEqual(Object.keys(rules).sort());
    }
  );

  it('disable-type-checked turns off exactly the rules that need a program', () => {
    expect(ruleNamesIn(configs['disable-type-checked']).sort()).toEqual(TYPE_AWARE_RULE_NAMES);

    for (const ruleName of TYPE_AWARE_RULE_NAMES) {
      expect(severityIn(configs['disable-type-checked'], ruleName)).toBe('off');
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

  describe('recommended-type-checked', () => {
    it('adds the two type-aware rules to what recommended already sets', () => {
      // An error for the rule whose findings are both definite, a warning for
      // the one whose subject is mostly defence in depth.
      expect(severityIn(configs['recommended-type-checked'], 'no-stringify-sensitive')).toBe(
        'error'
      );
      expect(severityIn(configs['recommended-type-checked'], 'prefer-safe-log')).toBe('warn');

      for (const ruleName of UNTYPED_RULE_NAMES) {
        expect(severityIn(configs['recommended-type-checked'], ruleName)).toBe(
          severityIn(configs['recommended'], ruleName)
        );
      }
    });
  });

  describe('strict', () => {
    it('errors on every rule it sets', () => {
      for (const ruleName of UNTYPED_RULE_NAMES) {
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

  describe('strict-type-checked', () => {
    it('errors on everything, the two type-aware rules included', () => {
      for (const ruleName of Object.keys(rules)) {
        expect(severityIn(configs['strict-type-checked'], ruleName)).toBe('error');
      }
    });
  });

  describe('flat form', () => {
    it.each(Object.keys(FLAT_TO_LEGACY))('%s carries the plugin object itself', (name) => {
      const config = configs[name] as { plugins: Record<string, unknown>; name: string };

      // A flat config names a plugin by holding it. Holding anything but this
      // object would configure rules that are never loaded.
      expect(config.plugins[PLUGIN_NAMESPACE]).toBe(plugin);
      expect(config.name).toBe(`${PLUGIN_NAMESPACE}/${name}`);
    });
  });

  describe('eslintrc form', () => {
    it.each(Object.values(FLAT_TO_LEGACY))('%s names the plugin by string', (name) => {
      // An eslintrc names a plugin by a specifier ESLint resolves itself, and
      // must not hold the object.
      expect(configs[name]).toMatchObject({ plugins: [PLUGIN_NAMESPACE] });
    });
  });
});
