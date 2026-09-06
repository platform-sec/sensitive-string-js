import { describe } from 'vitest';
import { requireRevealContext } from './require-reveal-context.js';
import {
  runRuleTests,
  runTypeAwareRuleTests,
  runTypeScriptRuleTests,
} from '../__tests__/rule-tester.js';

describe('require-reveal-context', () => {
  runRuleTests('require-reveal-context', requireRevealContext, {
    valid: [
      // TST-ESL-RRC-002: an explicit context.
      "const raw = secret.reveal({ name: 'payment' });",
      "const raw = secret.reveal({ name: 'payment', reason: 'charging the card' });",
      'const raw = secret.reveal(ctx);',
      'const raw = secret.reveal(buildContext());',

      // TST-ESL-RRC-003: a context installed for the whole scope.
      "withRevealContext({ name: 'handler' }, () => secret.reveal());",
      "await withRevealContext({ name: 'handler' }, async () => { const raw = secret.reveal(); return raw; });",
      'withAuditedReveals(sink, () => { secret.reveal(); });',
      'withRevealContext(ctx, () => { function inner() { return secret.reveal(); } return inner(); });',

      // Not a reveal.
      'secret.toString();',
      'secret.mask();',
      'reveal();',

      // hash() and hmac() are audited reads, but the name is not enough to know
      // that this one is: without types, these are as likely to be bcrypt.
      "secret.hash('sha256');",
      'bcrypt.hash(password, 12);',
      "crypto.hash('sha256', payload);",
      "signer.hmac('sha256', key);",

      // A configured wrapper.
      {
        code: 'withAudit(ctx, () => secret.reveal());',
        options: [{ contextFunctions: ['withAudit'] }],
      },
    ],

    invalid: [
      // TST-ESL-RRC-001: no argument at all.
      {
        code: 'const raw = secret.reveal();',
        errors: [
          {
            messageId: 'missingContext',
            data: { method: 'reveal', contextFunction: 'withRevealContext' },
          },
        ],
      },
      {
        code: 'function f() { return token.reveal(); }',
        options: [{ contextFunctions: ['withAudit'] }],
        errors: [
          { messageId: 'missingContext', data: { method: 'reveal', contextFunction: 'withAudit' } },
        ],
      },

      // A placeholder argument is not a context.
      {
        code: 'secret.reveal(undefined);',
        errors: [{ messageId: 'missingContext' }],
      },
      {
        code: 'secret.reveal(void 0);',
        errors: [{ messageId: 'missingContext' }],
      },

      // A different wrapper does not install this library's context.
      {
        code: 'withTransaction(() => secret.reveal());',
        errors: [{ messageId: 'missingContext' }],
      },

      // A call that merely mentions the wrapper's name as an argument.
      {
        code: 'register(withRevealContext, () => secret.reveal());',
        errors: [{ messageId: 'missingContext' }],
      },

      // Computed and optional forms reach the same method.
      {
        code: "secret['reveal']();",
        errors: [{ messageId: 'missingContext' }],
      },
      {
        code: 'secret?.reveal();',
        errors: [{ messageId: 'missingContext' }],
      },
    ],
  });

  describe('requireReason', () => {
    runRuleTests('require-reveal-context', requireRevealContext, {
      valid: [
        // TST-ESL-RRC-004: the reason is present, spelled either way.
        {
          code: "secret.reveal({ name: 'a', reason: 'b' });",
          options: [{ requireReason: true }],
        },
        {
          code: "secret.reveal({ name: 'a', 'reason': 'b' });",
          options: [{ requireReason: true }],
        },
        // A spread may carry it, and reading that needs types this rule lacks.
        {
          code: "secret.reveal({ name: 'a', ...base });",
          options: [{ requireReason: true }],
        },
        // Not an object literal, so there is nothing to inspect.
        {
          code: 'secret.reveal(ctx);',
          options: [{ requireReason: true }],
        },
        // Off by default.
        "secret.reveal({ name: 'a' });",
      ],

      invalid: [
        {
          code: "secret.reveal({ name: 'a' });",
          options: [{ requireReason: true }],
          errors: [{ messageId: 'missingReason' }],
        },
        // A computed key could be anything, so it does not satisfy the check.
        {
          code: "secret.reveal({ name: 'a', [key]: 'b' });",
          options: [{ requireReason: true }],
          errors: [{ messageId: 'missingReason' }],
        },
        // Missing entirely still reports the missing context, not the reason.
        {
          code: 'secret.reveal();',
          options: [{ requireReason: true }],
          errors: [{ messageId: 'missingContext' }],
        },
      ],
    });
  });

  describe('with type information', () => {
    /**
     * The receiver types the rule separates, declared per case.
     *
     * `.hash()` is the reason this half of the rule needs types at all: the
     * wrapper and the KDF module are the same syntax and only the receiver
     * tells them apart, so both are declared here and both are exercised.
     */
    const DECLARATIONS = [
      'declare class SensitiveString {',
      '  reveal(ctx?: unknown): string;',
      '  hash(algorithm: string, options?: unknown, ctx?: unknown): SensitiveString;',
      '  hmac(algorithm: string, key: unknown, options?: unknown, ctx?: unknown): SensitiveString;',
      '}',
      'declare class ApiKey extends SensitiveString {}',
      'declare const secret: SensitiveString;',
      'declare const derived: ApiKey;',
      'declare const maybe: SensitiveString | undefined;',
      'declare const bcrypt: { hash(value: string, rounds: number): Promise<string> };',
      'declare const holder: { token: SensitiveString; hash(value: string): string };',
      'declare const key: Uint8Array;',
      'declare const ctx: { name: string };',
      'declare const args: [string];',
      'declare const password: string;',
      'declare function withRevealContext<T>(context: unknown, run: () => T): T;',
      '',
    ].join('\n');

    const code = (source: string): string => DECLARATIONS + source;

    runTypeAwareRuleTests('require-reveal-context', requireRevealContext, {
      valid: [
        // The context is in the argument the method actually takes it in.
        code("secret.hash('sha256', {}, { name: 'lookup' });"),
        code("secret.hmac('sha256', key, {}, ctx);"),

        // Or from the scope, as for a reveal.
        code("withRevealContext(ctx, () => secret.hash('sha256'));"),

        // Not a wrapper, whatever the method is called.
        code('bcrypt.hash(password, 12);'),
        code("holder.hash('sha256');"),

        // A configured list that does not name the library's type narrows the
        // rule to nothing, the same way it does for the type-aware rules.
        {
          code: code("secret.hash('sha256');"),
          options: [{ sensitiveTypes: ['SomeOtherWrapper'] }],
        },

        // A spread ahead of the context: which argument it is stops being a
        // question this rule can answer, so it says nothing.
        code('secret.hash(...args);'),

        // reveal() is unchanged by any of this.
        code("secret.reveal({ name: 'payment' });"),
      ],

      invalid: [
        {
          code: code("secret.hash('sha256');"),
          errors: [
            {
              messageId: 'missingContext',
              data: { method: 'hash', contextFunction: 'withRevealContext' },
            },
          ],
        },
        // The options object is not the context: it sits one argument earlier.
        {
          code: code("secret.hash('sha256', { encoding: 'base64' });"),
          errors: [
            {
              messageId: 'missingContext',
              data: { method: 'hash', contextFunction: 'withRevealContext' },
            },
          ],
        },
        {
          code: code("secret.hash('sha256', {}, undefined);"),
          errors: [
            {
              messageId: 'missingContext',
              data: { method: 'hash', contextFunction: 'withRevealContext' },
            },
          ],
        },
        {
          code: code("secret.hmac('sha256', key);"),
          errors: [
            {
              messageId: 'missingContext',
              data: { method: 'hmac', contextFunction: 'withRevealContext' },
            },
          ],
        },
        // A subclass is still a wrapper.
        {
          code: code("derived.hash('sha256');"),
          errors: [
            {
              messageId: 'missingContext',
              data: { method: 'hash', contextFunction: 'withRevealContext' },
            },
          ],
        },
        // So is an optional one, which is a union with undefined.
        {
          code: code("maybe?.hash('sha256');"),
          errors: [
            {
              messageId: 'missingContext',
              data: { method: 'hash', contextFunction: 'withRevealContext' },
            },
          ],
        },
        // The reason check reaches the context wherever it sits.
        {
          code: code("secret.hash('sha256', {}, { name: 'lookup' });"),
          options: [{ requireReason: true }],
          errors: [{ messageId: 'missingReason', data: { method: 'hash' } }],
        },
        {
          code: code('secret.reveal();'),
          errors: [
            {
              messageId: 'missingContext',
              data: { method: 'reveal', contextFunction: 'withRevealContext' },
            },
          ],
        },
      ],
    });
  });

  describe('under the TypeScript parser', () => {
    runTypeScriptRuleTests('require-reveal-context', requireRevealContext, {
      valid: ["const raw: string = secret.reveal({ name: 'a' } satisfies RevealContext);"],
      invalid: [
        {
          code: 'const raw: string = secret!.reveal();',
          errors: [{ messageId: 'missingContext' }],
        },
        {
          code: 'const raw = (secret as SensitiveString<"credential">).reveal();',
          errors: [{ messageId: 'missingContext' }],
        },
      ],
    });
  });
});
