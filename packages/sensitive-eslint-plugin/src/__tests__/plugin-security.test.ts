/**
 * Adversarial coverage: the ways a leak stays quiet.
 *
 * A lint rule that silently misses a case is worse than no rule, because a
 * clean run is read as a clean file. This suite is about the second kind of
 * failure. It writes each leak the way someone avoiding the rule would, and
 * asserts a finding comes back; and it asserts the metadata invariants that
 * would let a rule rewrite code on its own.
 */
import { describe, it, expect } from 'vitest';
import { Linter } from 'eslint';
import type { ESLint } from 'eslint';
import { PLUGIN_NAMESPACE, configs, rules } from '../index.js';
import { lintFlat, typeAwareFilePath, typeAwareLayer } from './rule-tester.js';
import type { FlatLintMessage } from './rule-tester.js';
import type { RuleModule } from '../types.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

/**
 * Every finding for a source linted under the strict preset.
 *
 * Flat config carries the plugin object in the config itself, which is why
 * there is no registration step: ESLint 9 removed `defineRule` from the flat
 * linter, and a config naming its plugin inline replaces it.
 */
function lintStrictMessages(code: string): Linter.LintMessage[] {
  const { rules: strictRules } = configs['strict'] as { rules: Linter.RulesRecord };

  return new Linter().verify(code, {
    languageOptions: { ecmaVersion: 2022, sourceType: 'module' },
    plugins: { [PLUGIN_NAMESPACE]: { rules } as unknown as ESLint.Plugin },
    rules: strictRules,
  });
}

/** Every rule id reported for a source under the strict preset. */
function lintStrict(code: string): string[] {
  return lintStrictMessages(code).map((message) =>
    (message.ruleId ?? '(fatal)').replace(`${PLUGIN_NAMESPACE}/`, '')
  );
}

describe('rule metadata', () => {
  const entries = Object.entries(rules);

  it.each(entries)('%s declares no auto-fix', (_name, rule: RuleModule) => {
    // INV-ESL-001. `--fix` rewrites files with nobody reading the diff, and
    // every rewrite these rules would make changes behaviour: `.equals()` can
    // throw where `.reveal()` did not, and a sensitivity class cannot be
    // guessed at all. Everything actionable is offered as a suggestion, which
    // a person accepts one at a time.
    expect(rule.meta).not.toHaveProperty('fixable');
  });

  it.each(entries)('%s documents itself', (_name, rule: RuleModule) => {
    expect(rule.meta.docs.description).not.toBe('');
    expect(typeof rule.meta.docs.recommended).toBe('boolean');
    expect(Object.keys(rule.meta.messages).length).toBeGreaterThan(0);
  });

  it.each(entries)('%s explains the fix in every message', (_name, rule: RuleModule) => {
    for (const message of Object.values(rule.meta.messages)) {
      // INV-ESL-006. A finding that only says "do not do this" leaves the
      // developer to guess, and the guess is often `// eslint-disable`.
      expect(message.length).toBeGreaterThan(20);
    }
  });

  it.each(entries)('%s validates its options', (_name, rule: RuleModule) => {
    expect(Array.isArray(rule.meta.schema)).toBe(true);

    for (const entry of rule.meta.schema) {
      // `additionalProperties: false` is what turns a misspelled option into an
      // error instead of a silently ignored setting, which would leave a rule
      // running at defaults while its config says otherwise.
      expect(entry).toMatchObject({ type: 'object', additionalProperties: false });
    }
  });

  it('declares hasSuggestions on exactly the rules that offer one', () => {
    // Driven through the linter rather than read off the source, because
    // ESLint is the thing that enforces the pairing: a rule that reports a
    // suggestion without the flag throws, and a rule that sets the flag and
    // never suggests advertises an offer it does not keep.
    const source = `new SensitiveString(v);\nif (t.reveal() === input) { grant(); }\n`;
    const messages = lintStrictMessages(source);

    const offering = new Set(
      messages
        .filter((message) => (message.suggestions ?? []).length > 0)
        .map((message) => (message.ruleId ?? '').replace(`${PLUGIN_NAMESPACE}/`, ''))
    );
    const declaring = new Set(
      Object.entries(rules)
        .filter(([, rule]) => rule.meta.hasSuggestions === true)
        .map(([name]) => name)
    );

    expect(offering).toEqual(declaring);
    expect(declaring).toEqual(new Set(['explicit-class', 'no-credential-equality']));
  });
});

describe('no silent bypass', () => {
  /**
   * Leaks written the way they would be written by someone working around a
   * name-matching rule. Each entry is the source and the rule that must fire.
   */
  const BYPASS_ATTEMPTS: ReadonlyArray<readonly [string, string, string]> = [
    ['computed method name', `console.log(secret['reveal']());`, 'no-log-reveal'],
    ['computed log method', `console['error'](secret.reveal());`, 'no-log-reveal'],
    ['optional chain', 'console?.log(secret?.reveal());', 'no-log-reveal'],
    ['string concatenation', `console.log('t=' + secret.reveal());`, 'no-log-reveal'],
    ['template literal', 'console.log(`t=${secret.reveal()}`);', 'no-log-reveal'],
    ['array wrapper', 'console.log([secret.reveal()]);', 'no-log-reveal'],
    ['callback', 'console.log(list.map((s) => s.reveal()));', 'no-log-reveal'],
    ['truncated value', 'console.log(secret.reveal().slice(0, 4));', 'no-log-reveal'],
    [
      'redactor over a raw string',
      'console.log(safeLog({ s: secret.reveal() }));',
      'no-log-reveal',
    ],
    ['serialized wire format', 'console.log(token.serialize());', 'no-log-reveal'],
    ['logger behind a builder', 'logger.child({}).info(secret.reveal());', 'no-log-reveal'],
    ['logger on this', 'class A { m() { this.logger.info(s.reveal()); } }', 'no-log-reveal'],
    ['raw stream', 'process.stdout.write(secret.reveal());', 'no-log-reveal'],
    ['loose equality', 'if (token.reveal() == input) { grant(); }', 'no-credential-equality'],
    ['reversed operands', 'if (input === token.reveal()) { grant(); }', 'no-credential-equality'],
    ['negated', 'if (token.reveal() !== input) { deny(); }', 'no-credential-equality'],
    ['switch dispatch', 'switch (token.reveal()) { case a: break; }', 'no-credential-equality'],
    ['url interpolation', 'fetch(`/x?t=${token.reveal()}`);', 'no-network-sensitive'],
    [
      'nested request body',
      'fetch(u, { body: { a: { b: t.reveal() } } });',
      'no-network-sensitive',
    ],
    ['builder chain', 'superagent.post(u).send(t.reveal());', 'no-network-sensitive'],
    ['placeholder context', 'secret.reveal(undefined);', 'require-reveal-context'],
    ['void placeholder', 'secret.reveal(void 0);', 'require-reveal-context'],
    // Passing `undefined` satisfies a signature and decides nothing, so it is
    // the cheapest way to make a rule that only counts arguments fall silent.
    // Every rule that asks for an argument has to reject it, not just the one
    // whose subject the argument is.
    ['placeholder on the wire', 'fetch(u, { body: t.reveal(undefined) });', 'no-network-sensitive'],
    [
      'void placeholder on the wire',
      'fetch(u, { body: t.reveal(void 0) });',
      'no-network-sensitive',
    ],
    ['placeholder class', 'new SensitiveString(v, undefined);', 'explicit-class'],
    ['void placeholder class', 'new SensitiveString(v, void 0);', 'explicit-class'],
    ['unrelated wrapper', 'withTransaction(() => secret.reveal());', 'require-reveal-context'],
    ['namespaced constructor', 'new core.SensitiveString(v);', 'explicit-class'],
  ];

  it.each(BYPASS_ATTEMPTS)('%s is still reported by %s', (_label, code, expectedRule) => {
    expect(lintStrict(code)).toContain(expectedRule);
  });
});

describe('canary', () => {
  it('never puts a revealed value into a finding', () => {
    // A rule's message and its data are written into editors, CI logs, and
    // SARIF uploads. Quoting the source it flagged would move a secret from one
    // file into every one of those, which is the leak the plugin exists to
    // prevent. Only rewrites the developer explicitly asks for may quote code,
    // and those go in `suggestions`, not in the message.
    const source = `const s = new SensitiveString('${CANARY}', 'credential');\nconsole.log(s.reveal());\nif (s.reveal() === '${CANARY}') { grant(); }\nfetch(u, { body: '${CANARY}' });\n`;

    const messages = lintStrictMessages(source);

    expect(messages.length).toBeGreaterThan(0);
    for (const message of messages) {
      expect(message.message).not.toContain(CANARY);
    }
  });

  it('reports every leak in the canary source', () => {
    const source = `const s = new SensitiveString('${CANARY}');\nconsole.log(s.reveal());\nif (s.reveal() === input) { grant(); }\nfetch(u, { body: s.reveal() });\n`;

    expect(new Set(lintStrict(source))).toEqual(
      new Set([
        'explicit-class',
        'no-log-reveal',
        'require-reveal-context',
        'no-credential-equality',
        'no-network-sensitive',
      ])
    );
  });
});

describe('type-aware rules', () => {
  /**
   * The library's shapes, declared per case.
   *
   * Both rules match a type by its name, so a local declaration exercises what
   * a real import would. It is also the plain statement of the limitation:
   * anything called `SensitiveString` is treated as one, and a wrapper called
   * anything else is invisible until `sensitiveTypes` names it.
   */
  const DECLARATIONS = [
    'declare class SensitiveString { readonly klass: string; reveal(): string }',
    'interface SerializedSensitiveString { __sensitive: true; klass: string; value: string }',
    '',
  ].join('\n');

  /** Every finding for a source linted under the strict type-checked preset. */
  async function lintTyped(source: string): Promise<readonly FlatLintMessage[]> {
    return lintFlat(
      DECLARATIONS + source,
      [typeAwareLayer(), configs['strict-type-checked']],
      typeAwareFilePath()
    );
  }

  /** Every rule id reported, with the plugin prefix stripped. */
  async function typedRuleIds(source: string): Promise<string[]> {
    return (await lintTyped(source)).map((message) =>
      (message.ruleId ?? '(fatal)').replace(`${PLUGIN_NAMESPACE}/`, '')
    );
  }

  describe('no silent bypass', () => {
    /**
     * Structures written the way they would be written by someone who found
     * the shape the rule reported and reached for the nearest variation.
     */
    const BYPASS_ATTEMPTS: ReadonlyArray<readonly [string, string, string]> = [
      [
        'spread copy',
        'declare const p: { token: SensitiveString };\nJSON.stringify({ ...p });',
        'no-stringify-sensitive',
      ],
      [
        'assignment through a local',
        'declare const p: { token: SensitiveString };\nconst copy = p;\nJSON.stringify(copy);',
        'no-stringify-sensitive',
      ],
      [
        'cast that keeps the field',
        'declare const p: unknown;\nJSON.stringify(p as { token: SensitiveString });',
        'no-stringify-sensitive',
      ],
      [
        'mapped type',
        'declare const p: Partial<{ token: SensitiveString }>;\nJSON.stringify(p);',
        'no-stringify-sensitive',
      ],
      [
        'readonly wrapper',
        'declare const p: Readonly<{ token: SensitiveString }>;\nJSON.stringify(p);',
        'no-stringify-sensitive',
      ],
      [
        'getter rather than a field',
        'declare const p: { get token(): SensitiveString };\nconsole.log(p);',
        'prefer-safe-log',
      ],
      [
        'function returning the payload',
        'declare function build(): { token: SensitiveString };\nconsole.log(build());',
        'prefer-safe-log',
      ],
      [
        'wire format one level down',
        'declare const p: { body: { auth: SerializedSensitiveString } };\nconsole.log(p);',
        'prefer-safe-log',
      ],
      [
        'wire format in an array',
        'declare const p: SerializedSensitiveString[];\nJSON.stringify(p);',
        'no-stringify-sensitive',
      ],
    ];

    it.each(BYPASS_ATTEMPTS)('%s is still reported by %s', async (_label, code, expectedRule) => {
      expect(await typedRuleIds(code)).toContain(expectedRule);
    });
  });

  describe('canary', () => {
    it('never puts a value into a finding', async () => {
      // Both messages name a *type*, never the expression they flagged. A rule
      // that quoted the source would move whatever literal it found into every
      // editor, CI log and SARIF upload that reads the finding.
      const source = [
        `declare const p: { token: SensitiveString; note: '${CANARY}' };`,
        'console.log(p);',
        'JSON.stringify(p);',
        '',
      ].join('\n');

      const messages = await lintTyped(source);

      expect(messages.length).toBeGreaterThan(0);
      for (const message of messages) {
        expect(message.message).not.toContain(CANARY);
      }
    });
  });

  describe('what the rules deliberately allow', () => {
    it('leaves the value itself alone, which is how it is meant to be logged', async () => {
      // `SensitiveString` redacts through toString(), toJSON() and
      // util.inspect. Reporting `console.log(token)` would contradict the
      // library's own documentation and bury the finding that matters.
      const source = 'declare const t: SensitiveString;\nconsole.log(t);\nconsole.log([t]);';

      expect(await typedRuleIds(source)).not.toContain('prefer-safe-log');
    });

    it('still reports stringifying the value itself, which substitutes silently', async () => {
      // The opposite call: JSON.stringify writes the redaction where the value
      // was expected, and the failure surfaces at the far end rather than here.
      const source = 'declare const t: SensitiveString;\nJSON.stringify(t);';

      expect(await typedRuleIds(source)).toContain('no-stringify-sensitive');
    });
  });
});
