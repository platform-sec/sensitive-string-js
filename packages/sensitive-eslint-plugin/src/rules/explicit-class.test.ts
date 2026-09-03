import { describe } from 'vitest';
import { explicitClass } from './explicit-class.js';
import { runRuleTests, runTypeScriptRuleTests } from '../__tests__/rule-tester.js';

describe('explicit-class', () => {
  runRuleTests('explicit-class', explicitClass, {
    valid: [
      "new SensitiveString(value, 'credential');",
      "new SensitiveString(value, 'sensitive', 'email');",
      "new SensitiveString(value, 'credential', 'api_key', { ttl: 60 });",
      'new SensitiveString(value, klass);',
      "new core.SensitiveString(value, 'credential');",

      // A spread makes the argument count unknowable, so the rule stays quiet
      // rather than report code that may well be correct.
      'new SensitiveString(...args);',
      'new SensitiveString(value, ...rest);',

      // Some other constructor.
      'new URL(value);',
      'new Map();',
      'new String(value);',

      // Not a construction.
      'SensitiveString(value);',

      // A configured constructor narrows what is checked.
      {
        code: 'new SensitiveString(value);',
        options: [{ constructorNames: ['Secret'] }],
      },
    ],

    invalid: [
      {
        code: 'new SensitiveString(value);',
        errors: [
          {
            messageId: 'missingClass',
            data: { name: 'SensitiveString' },
            suggestions: [
              {
                messageId: 'addClass',
                data: { klass: 'sensitive' },
                output: "new SensitiveString(value, 'sensitive');",
              },
              {
                messageId: 'addClass',
                data: { klass: 'credential' },
                output: "new SensitiveString(value, 'credential');",
              },
            ],
          },
        ],
      },

      // The namespaced form.
      {
        code: 'new core.SensitiveString(value);',
        errors: [
          {
            messageId: 'missingClass',
            suggestions: [
              { messageId: 'addClass', output: "new core.SensitiveString(value, 'sensitive');" },
              { messageId: 'addClass', output: "new core.SensitiveString(value, 'credential');" },
            ],
          },
        ],
      },

      // An expression argument is preserved verbatim by the suggestion.
      {
        code: 'new SensitiveString(await load(id));',
        errors: [
          {
            messageId: 'missingClass',
            suggestions: [
              {
                messageId: 'addClass',
                output: "new SensitiveString(await load(id), 'sensitive');",
              },
              {
                messageId: 'addClass',
                output: "new SensitiveString(await load(id), 'credential');",
              },
            ],
          },
        ],
      },

      // A placeholder names no class. The suggestion overwrites it rather than
      // inserting ahead of it, which would leave the `undefined` behind in the
      // `label` position where it is accepted and means nothing.
      {
        code: 'new SensitiveString(value, undefined);',
        errors: [
          {
            messageId: 'missingClass',
            suggestions: [
              { messageId: 'addClass', output: "new SensitiveString(value, 'sensitive');" },
              { messageId: 'addClass', output: "new SensitiveString(value, 'credential');" },
            ],
          },
        ],
      },
      {
        code: 'new SensitiveString(value, void 0);',
        errors: [
          {
            messageId: 'missingClass',
            suggestions: [
              { messageId: 'addClass', output: "new SensitiveString(value, 'sensitive');" },
              { messageId: 'addClass', output: "new SensitiveString(value, 'credential');" },
            ],
          },
        ],
      },

      // No arguments at all is broken in a way a class does not fix, so it is
      // reported without a suggestion.
      {
        code: 'new SensitiveString();',
        errors: [{ messageId: 'missingClass', suggestions: [] }],
      },

      // A renamed constructor, once configured.
      {
        code: 'new Secret(value);',
        options: [{ constructorNames: ['Secret'] }],
        errors: [
          {
            messageId: 'missingClass',
            data: { name: 'Secret' },
            suggestions: [
              { messageId: 'addClass', output: "new Secret(value, 'sensitive');" },
              { messageId: 'addClass', output: "new Secret(value, 'credential');" },
            ],
          },
        ],
      },
    ],
  });

  describe('under the TypeScript parser', () => {
    runTypeScriptRuleTests('explicit-class', explicitClass, {
      valid: ["const s = new SensitiveString<'credential'>(value, 'credential');"],
      invalid: [
        {
          code: 'const s = new SensitiveString(value as string);',
          errors: [
            {
              messageId: 'missingClass',
              suggestions: [
                {
                  messageId: 'addClass',
                  output: "const s = new SensitiveString(value as string, 'sensitive');",
                },
                {
                  messageId: 'addClass',
                  output: "const s = new SensitiveString(value as string, 'credential');",
                },
              ],
            },
          ],
        },
      ],
    });
  });
});
