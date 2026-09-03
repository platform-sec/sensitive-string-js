import { describe } from 'vitest';
import { requireRevealContext } from './require-reveal-context.js';
import { runRuleTests, runTypeScriptRuleTests } from '../__tests__/rule-tester.js';

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
        errors: [{ messageId: 'missingContext', data: { contextFunction: 'withRevealContext' } }],
      },
      {
        code: 'function f() { return token.reveal(); }',
        options: [{ contextFunctions: ['withAudit'] }],
        errors: [{ messageId: 'missingContext', data: { contextFunction: 'withAudit' } }],
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
