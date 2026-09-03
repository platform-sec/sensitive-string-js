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
import { PLUGIN_NAMESPACE, configs, rules } from '../index.js';
import type { RuleModule } from '../types.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

/** A linter with every rule of this plugin registered under its full name. */
function createLinter(): Linter {
  const linter = new Linter();
  for (const [name, rule] of Object.entries(rules)) {
    linter.defineRule(
      `${PLUGIN_NAMESPACE}/${name}`,
      rule as unknown as Parameters<Linter['defineRule']>[1]
    );
  }
  return linter;
}

/** Every rule id reported for a source under the strict preset. */
function lintStrict(code: string): string[] {
  const { rules: strictRules } = configs['strict'] as { rules: Record<string, unknown> };

  return createLinter()
    .verify(code, {
      parserOptions: { ecmaVersion: 2022, sourceType: 'module' },
      rules: strictRules as Linter.RulesRecord,
    })
    .map((message) => (message.ruleId ?? '(fatal)').replace(`${PLUGIN_NAMESPACE}/`, ''));
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
    const messages = createLinter().verify(source, {
      parserOptions: { ecmaVersion: 2022, sourceType: 'module' },
      rules: (configs['strict'] as { rules: Linter.RulesRecord }).rules,
    });

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

    const messages = createLinter().verify(source, {
      parserOptions: { ecmaVersion: 2022, sourceType: 'module' },
      rules: (configs['strict'] as { rules: Linter.RulesRecord }).rules,
    });

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
