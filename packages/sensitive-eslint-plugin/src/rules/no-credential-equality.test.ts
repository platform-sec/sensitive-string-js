import { describe } from 'vitest';
import { noCredentialEquality } from './no-credential-equality.js';
import { runRuleTests, runTypeScriptRuleTests } from '../__tests__/rule-tester.js';

describe('no-credential-equality', () => {
  runRuleTests('no-credential-equality', noCredentialEquality, {
    valid: [
      // TST-ESL-NCE-004: the constant-time path.
      'if (password.equals(input)) { grant(); }',
      "if (token.equals(new SensitiveString(stored, 'credential'))) { grant(); }",
      'if (password.equals(input, { name: "login" })) { grant(); }',

      // Comparisons that do not touch the value.
      'if (secret.klass === "credential") { audit(); }',
      'if (secret.label === "api_key") { audit(); }',
      'if (raw === input) { grant(); }',

      // Relational and identity operators are not equality comparisons.
      'if (a.reveal() < b) { order(); }',
      'if (secret instanceof SensitiveString) { ok(); }',

      // Reading the method without calling it.
      'if (secret.reveal === undefined) { fail(); }',

      // A reveal that is not being compared.
      'const raw = secret.reveal();',
      'switch (mode) { case "a": break; }',
    ],

    invalid: [
      // TST-ESL-NCE-001 through 003: every equality operator.
      {
        code: 'if (password.reveal() === userInput) { grant(); }',
        errors: [
          {
            messageId: 'useEquals',
            data: { operator: '===' },
            suggestions: [
              {
                messageId: 'useEqualsSuggestion',
                output: 'if (password.equals(userInput)) { grant(); }',
              },
            ],
          },
        ],
      },
      {
        code: 'if (token.reveal() == storedToken) { grant(); }',
        errors: [
          {
            messageId: 'useEquals',
            suggestions: [
              {
                messageId: 'useEqualsSuggestion',
                output: 'if (token.equals(storedToken)) { grant(); }',
              },
            ],
          },
        ],
      },
      {
        code: 'const differs = password.reveal() !== expected;',
        errors: [
          {
            messageId: 'useEquals',
            suggestions: [
              {
                messageId: 'useEqualsSuggestion',
                output: 'const differs = !password.equals(expected);',
              },
            ],
          },
        ],
      },
      {
        code: 'const differs = password.reveal() != expected;',
        errors: [
          {
            messageId: 'useEquals',
            suggestions: [
              {
                messageId: 'useEqualsSuggestion',
                output: 'const differs = !password.equals(expected);',
              },
            ],
          },
        ],
      },

      // The reveal on the right-hand side.
      {
        code: 'if (userInput === password.reveal()) { grant(); }',
        errors: [
          {
            messageId: 'useEquals',
            suggestions: [
              {
                messageId: 'useEqualsSuggestion',
                output: 'if (password.equals(userInput)) { grant(); }',
              },
            ],
          },
        ],
      },

      // TST-ESL-NCE-005: both sides reveal, reported once.
      {
        code: 'if (a.reveal() === b.reveal()) { same(); }',
        errors: [
          {
            messageId: 'useEquals',
            suggestions: [
              { messageId: 'useEqualsSuggestion', output: 'if (a.equals(b)) { same(); }' },
            ],
          },
        ],
      },

      // A context on the reveal moves to equals(), which takes it second.
      {
        code: 'if (token.reveal({ name: "login" }) === input) { grant(); }',
        errors: [
          {
            messageId: 'useEquals',
            suggestions: [
              {
                messageId: 'useEqualsSuggestion',
                output: 'if (token.equals(input, { name: "login" })) { grant(); }',
              },
            ],
          },
        ],
      },
      // Including when the reveal that carries it is the right operand.
      {
        code: 'if (input === token.reveal(ctx)) { grant(); }',
        errors: [
          {
            messageId: 'useEquals',
            suggestions: [
              {
                messageId: 'useEqualsSuggestion',
                output: 'if (token.equals(input, ctx)) { grant(); }',
              },
            ],
          },
        ],
      },

      // A placeholder context is dropped rather than copied into the rewrite.
      {
        code: 'if (token.reveal(undefined) === input) { grant(); }',
        errors: [
          {
            messageId: 'useEquals',
            suggestions: [
              { messageId: 'useEqualsSuggestion', output: 'if (token.equals(input)) { grant(); }' },
            ],
          },
        ],
      },

      // A member-expression receiver survives the rewrite intact.
      {
        code: 'if (this.user.password.reveal() === input) { grant(); }',
        errors: [
          {
            messageId: 'useEquals',
            suggestions: [
              {
                messageId: 'useEqualsSuggestion',
                output: 'if (this.user.password.equals(input)) { grant(); }',
              },
            ],
          },
        ],
      },
    ],
  });

  describe('declined suggestions', () => {
    runRuleTests('no-credential-equality', noCredentialEquality, {
      valid: [],
      invalid: [
        // An optional call short-circuits to `undefined`, not to `false`, so the
        // rewrite would change which branch runs.
        {
          code: 'if (token?.reveal() === input) { grant(); }',
          errors: [{ messageId: 'useEquals', suggestions: [] }],
        },
        // A comment inside the comparison would be deleted by the replacement.
        {
          code: 'if (token.reveal() === /* legacy */ input) { grant(); }',
          errors: [{ messageId: 'useEquals', suggestions: [] }],
        },
        // Two contexts, and equals() has room for one.
        {
          code: 'if (a.reveal(c1) === b.reveal(c2)) { same(); }',
          errors: [{ messageId: 'useEquals', suggestions: [] }],
        },
        // A comma expression's text would split into two arguments, promoting
        // its second half to the audit context.
        {
          code: 'if (token.reveal() === (a, b)) { grant(); }',
          errors: [{ messageId: 'useEquals', suggestions: [] }],
        },
        // The `?.` is a link further down than the two nearest the call, and
        // the expression is still `undefined` when `a` is.
        {
          code: 'if (a?.b.reveal() === input) { grant(); }',
          errors: [{ messageId: 'useEquals', suggestions: [] }],
        },
        {
          code: 'if (a?.b.c.reveal() === input) { grant(); }',
          errors: [{ messageId: 'useEquals', suggestions: [] }],
        },
      ],
    });
  });

  describe('switch', () => {
    runRuleTests('no-credential-equality', noCredentialEquality, {
      valid: ['switch (secret.klass) { case "credential": break; }'],
      invalid: [
        {
          code: 'switch (token.reveal()) { case a: break; default: break; }',
          errors: [{ messageId: 'noSwitchOnReveal' }],
        },
        {
          code: 'switch (token.reveal({ name: "route" })) { case a: break; }',
          errors: [{ messageId: 'noSwitchOnReveal' }],
        },
      ],
    });
  });

  describe('under the TypeScript parser', () => {
    runTypeScriptRuleTests('no-credential-equality', noCredentialEquality, {
      valid: ['const ok: boolean = password.equals(input);'],
      invalid: [
        // The comparand is quoted back into the rewrite exactly as written, so
        // a cast on the other side is not silently dropped from it.
        {
          code: 'if (password.reveal() === (input as string)) { grant(); }',
          errors: [
            {
              messageId: 'useEquals',
              suggestions: [
                {
                  messageId: 'useEqualsSuggestion',
                  output: 'if (password.equals(input as string)) { grant(); }',
                },
              ],
            },
          ],
        },
        // A cast must not hide the comparison.
        {
          code: 'if ((password.reveal() as string) === input) { grant(); }',
          errors: [{ messageId: 'useEquals' }],
        },
        {
          code: 'if (password!.reveal() === input) { grant(); }',
          errors: [{ messageId: 'useEquals' }],
        },
        {
          code: 'if (password.reveal() satisfies string === input) { grant(); }',
          errors: [{ messageId: 'useEquals' }],
        },
      ],
    });
  });
});
