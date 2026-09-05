import { describe } from 'vitest';
import { noStringifySensitive } from './no-stringify-sensitive.js';
import {
  runRuleTests,
  runTypeAwareRuleTests,
  runTypeScriptRuleTests,
} from '../__tests__/rule-tester.js';

/**
 * The library's shapes, declared per case rather than imported.
 *
 * The rule matches a type by name, so a local declaration exercises exactly
 * what a real import would and keeps the fixture project free of dependencies.
 * Declaring them here is also the honest demonstration of the rule's one big
 * limitation: it believes any type called `SensitiveString`.
 */
const DECLARATIONS = [
  'declare class SensitiveString { readonly klass: string; reveal(): string; toString(): string }',
  'interface SerializedSensitiveString { __sensitive: true; klass: string; value: string }',
  'declare function safeStringify(value: unknown): string;',
  'declare function safeLog(value: unknown): unknown;',
  '',
].join('\n');

/** A case's source, with the declarations it needs in front of it. */
function code(source: string): string {
  return DECLARATIONS + source;
}

describe('no-stringify-sensitive', () => {
  runTypeAwareRuleTests('no-stringify-sensitive', noStringifySensitive, {
    valid: [
      // Nothing sensitive anywhere in the type.
      code('declare const user: { name: string; age: number };\nJSON.stringify(user);'),
      code('JSON.stringify({ ok: true });'),
      code('JSON.stringify("plain");'),

      // The two calls this rule points at.
      code('declare const p: { token: SensitiveString };\nsafeStringify(p);'),
      code('declare const p: { token: SensitiveString };\nJSON.stringify(safeLog(p));'),

      // Already reduced to a redacted string.
      code('declare const t: SensitiveString;\nJSON.stringify(t.toString());'),

      // A method that returns one is not a structure that holds one.
      code('declare const api: { getToken(): SensitiveString };\nJSON.stringify(api);'),

      // Not JSON.stringify.
      code('declare const p: { token: SensitiveString };\nqs.stringify(p);'),
      code('declare const p: { token: SensitiveString };\nJSON.parse(raw);'),

      // No argument to inspect.
      'JSON.stringify();',

      // The rule believes names, and a narrowed configuration must narrow.
      {
        code: code('declare const p: { token: SensitiveString };\nJSON.stringify(p);'),
        options: [{ sensitiveTypes: ['SomeOtherWrapper'], serializedTypes: [] }],
      },
      // A structurally identical shape under a different name is not the wire
      // format. Matching by shape would report every `{ value: string }`.
      {
        code: 'declare const p: { __sensitive: true; klass: string; value: string };\nJSON.stringify(p);',
      },
    ],

    invalid: [
      // The headline case: a payload holding a live wrapper.
      {
        code: code('declare const p: { token: SensitiveString };\nJSON.stringify(p);'),
        errors: [{ messageId: 'stringifySensitive', data: { name: 'SensitiveString' } }],
      },

      // The value itself. `JSON.stringify(token)` is a string of the redaction,
      // which is exactly the substitution nothing at the call site announces.
      {
        code: code('declare const t: SensitiveString;\nJSON.stringify(t);'),
        errors: [{ messageId: 'stringifySensitive' }],
      },

      // Several levels down.
      {
        code: code(
          'declare const p: { req: { headers: { auth: SensitiveString } } };\nJSON.stringify(p);'
        ),
        errors: [{ messageId: 'stringifySensitive' }],
      },

      // Through an array.
      {
        code: code('declare const p: SensitiveString[];\nJSON.stringify(p);'),
        errors: [{ messageId: 'stringifySensitive' }],
      },
      {
        code: code('declare const p: { tokens: SensitiveString[] };\nJSON.stringify(p);'),
        errors: [{ messageId: 'stringifySensitive' }],
      },

      // Through a tuple.
      {
        code: code('declare const p: [string, SensitiveString];\nJSON.stringify(p);'),
        errors: [{ messageId: 'stringifySensitive' }],
      },

      // Through an index signature, which is what `Record<string, T>` becomes.
      {
        code: code('declare const p: Record<string, SensitiveString>;\nJSON.stringify(p);'),
        errors: [{ messageId: 'stringifySensitive' }],
      },

      // Optional and union-typed fields.
      {
        code: code('declare const p: { token?: SensitiveString };\nJSON.stringify(p);'),
        errors: [{ messageId: 'stringifySensitive' }],
      },
      {
        code: code('declare const p: { token: SensitiveString | null };\nJSON.stringify(p);'),
        errors: [{ messageId: 'stringifySensitive' }],
      },

      // A subclass, reached through the base type's name.
      {
        code: code(
          'declare class ApiKey extends SensitiveString {}\ndeclare const p: { key: ApiKey };\nJSON.stringify(p);'
        ),
        errors: [{ messageId: 'stringifySensitive' }],
      },

      // The wire format, which is the opposite failure: the raw value goes out.
      {
        code: code('declare const wire: SerializedSensitiveString;\nJSON.stringify(wire);'),
        errors: [{ messageId: 'stringifySerialized' }],
      },
      {
        code: code(
          'declare const p: { credentials: SerializedSensitiveString };\nJSON.stringify(p);'
        ),
        errors: [{ messageId: 'stringifySerialized' }],
      },

      // A replacer and an indent do not change what the first argument is.
      {
        code: code(
          'declare const p: { token: SensitiveString };\ndeclare const r: () => void;\nJSON.stringify(p, r, 2);'
        ),
        errors: [{ messageId: 'stringifySensitive' }],
      },

      // Reached through the global object rather than the bare name.
      {
        code: code('declare const p: { token: SensitiveString };\nglobalThis.JSON.stringify(p);'),
        errors: [{ messageId: 'stringifySensitive' }],
      },

      // The computed spelling of the same call, which is the shortest way to
      // write one a name-matching rule would miss.
      {
        code: code("declare const p: { token: SensitiveString };\nJSON['stringify'](p);"),
        errors: [{ messageId: 'stringifySensitive' }],
      },

      // A type that contains itself. The visited set is what makes this
      // terminate; without it the walk would not return at all.
      {
        code: code(
          'interface Tree { child: Tree; token: SensitiveString }\ndeclare const t: Tree;\nJSON.stringify(t);'
        ),
        errors: [{ messageId: 'stringifySensitive' }],
      },

      // A spread, where the argument node is not the value it stands for.
      {
        code: code('declare const args: [{ token: SensitiveString }];\nJSON.stringify(...args);'),
        errors: [{ messageId: 'stringifySensitive' }],
      },

      // A project's own wrapper name, configured.
      {
        code: 'declare class Secret { readonly klass: string }\ndeclare const p: { s: Secret };\nJSON.stringify(p);',
        options: [{ sensitiveTypes: ['Secret'] }],
        errors: [{ messageId: 'stringifySensitive', data: { name: 'Secret' } }],
      },
    ],
  });

  describe('type aliases', () => {
    runTypeAwareRuleTests('no-stringify-sensitive', noStringifySensitive, {
      valid: [],
      invalid: [
        // A union written behind an alias carries the alias's name as well as
        // its members', so a project that spells the type one way can configure
        // that spelling.
        {
          code: code(
            'type Nullable = SensitiveString | null;\ndeclare const p: { t: Nullable };\nJSON.stringify(p);'
          ),
          options: [{ sensitiveTypes: ['Nullable'] }],
          errors: [{ messageId: 'stringifySensitive', data: { name: 'Nullable' } }],
        },
      ],
    });
  });

  describe('without type information', () => {
    /**
     * A rule that reports nothing looks exactly like a rule that found
     * nothing, and this one is read as "no sensitive value is being
     * stringified in this file". It says so instead, once per file.
     */
    const missing = {
      valid: [],
      invalid: [
        {
          code: 'JSON.stringify(payload);',
          errors: [{ messageId: 'missingTypeInformation' }],
        },
        {
          // Even a file with no `JSON.stringify` in it, because the point of
          // the report is the configuration, not the call.
          code: 'const a = 1;',
          errors: [{ messageId: 'missingTypeInformation' }],
        },
      ],
    };

    runRuleTests('no-stringify-sensitive', noStringifySensitive, missing);
    // The TypeScript parser without a `project` is the configuration this is
    // really about: the parser is right and the program is missing.
    runTypeScriptRuleTests('no-stringify-sensitive', noStringifySensitive, missing);
  });
});
