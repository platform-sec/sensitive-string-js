import { describe } from 'vitest';
import { preferSafeLog } from './prefer-safe-log.js';
import {
  runRuleTests,
  runTypeAwareRuleTests,
  runTypeScriptRuleTests,
} from '../__tests__/rule-tester.js';

/** The library's shapes, declared per case. See `no-stringify-sensitive.test.ts`. */
const DECLARATIONS = [
  'declare class SensitiveString { readonly klass: string; reveal(): string; toString(): string }',
  'interface SerializedSensitiveString { __sensitive: true; klass: string; value: string }',
  'declare function safeLog(value: unknown): unknown;',
  '',
].join('\n');

/** A case's source, with the declarations it needs in front of it. */
function code(source: string): string {
  return DECLARATIONS + source;
}

describe('prefer-safe-log', () => {
  runTypeAwareRuleTests('prefer-safe-log', preferSafeLog, {
    valid: [
      // The value itself, which is the documented way to log one: the class
      // redacts through toString(), toJSON() and util.inspect alike.
      code('declare const t: SensitiveString;\nconsole.log(t);'),
      code('declare const t: SensitiveString;\nlogger.info("token:", t);'),

      // A plain list of them delegates to each element, so it is the same case.
      code('declare const ts: SensitiveString[];\nconsole.log(ts);'),
      code('declare const ts: [SensitiveString, SensitiveString];\nconsole.log(ts);'),

      // Already redacted.
      code('declare const p: { token: SensitiveString };\nconsole.log(safeLog(p));'),
      code('declare const t: SensitiveString;\nconsole.log(t.toString());'),

      // Nothing sensitive in the type.
      code('declare const user: { name: string };\nconsole.log(user);'),
      'console.log("starting up");',

      // A method returning one is not a structure holding one.
      code('declare const api: { getToken(): SensitiveString };\nconsole.log(api);'),

      // Not a logger, despite the method name.
      code('declare const p: { token: SensitiveString };\nmetrics.info(p);'),

      // Not a log method, despite the object name.
      code('declare const p: { token: SensitiveString };\nlogger.child(p);'),

      // A narrowed configuration must actually narrow.
      {
        code: code('declare const p: { token: SensitiveString };\nlogger.info(p);'),
        options: [{ logObjects: ['console'] }],
      },
      {
        code: code('declare const p: { token: SensitiveString };\nconsole.log(p);'),
        options: [{ sensitiveTypes: [], serializedTypes: [] }],
      },
    ],

    invalid: [
      // The headline case: a record holding one, where what gets written is
      // whichever serializer the transport reached for.
      {
        code: code('declare const p: { token: SensitiveString };\nconsole.log(p);'),
        errors: [{ messageId: 'preferSafeLog', data: { name: 'SensitiveString' } }],
      },
      {
        code: code('declare const t: SensitiveString;\nlogger.info({ token: t });'),
        errors: [{ messageId: 'preferSafeLog' }],
      },

      // Every argument, not just the first.
      {
        code: code('declare const p: { token: SensitiveString };\nlogger.info("sending", p);'),
        errors: [{ messageId: 'preferSafeLog' }],
      },
      {
        code: code(
          'declare const a: { token: SensitiveString };\ndeclare const b: { key: SensitiveString };\nconsole.log(a, b);'
        ),
        errors: [{ messageId: 'preferSafeLog' }, { messageId: 'preferSafeLog' }],
      },

      // Nested, through an array, and through an index signature.
      {
        code: code('declare const p: { req: { auth: SensitiveString } };\nconsole.log(p);'),
        errors: [{ messageId: 'preferSafeLog' }],
      },
      {
        code: code('declare const p: { tokens: SensitiveString[] };\nconsole.log(p);'),
        errors: [{ messageId: 'preferSafeLog' }],
      },
      {
        code: code('declare const p: Record<string, SensitiveString>;\nconsole.log(p);'),
        errors: [{ messageId: 'preferSafeLog' }],
      },

      // The wire format, which is a leak wherever it sits: a plain object
      // carrying the raw value, and no serializer redacts one.
      {
        code: code('declare const wire: SerializedSensitiveString;\nconsole.log(wire);'),
        errors: [{ messageId: 'logsSerialized' }],
      },
      {
        code: code('declare const p: { credentials: SerializedSensitiveString };\nlogger.warn(p);'),
        errors: [{ messageId: 'logsSerialized' }],
      },
      {
        code: code('declare const wire: SerializedSensitiveString[];\nconsole.log(wire);'),
        errors: [{ messageId: 'logsSerialized' }],
      },

      // A serialize() call handed straight to a logger. `no-log-reveal` reports
      // this one too, from the call rather than the type; the two findings
      // agree on the fix, and the documentation says so.
      {
        code: code(
          'declare const t: { serialize(): SerializedSensitiveString };\nconsole.log(t.serialize());'
        ),
        errors: [{ messageId: 'logsSerialized' }],
      },

      // A spread, where the argument node is not the value it stands for.
      // Reporting it is the conservative direction, and the case exists here
      // because reading a type off a `SpreadElement` is where a type-aware rule
      // would otherwise throw rather than report.
      {
        code: code('declare const args: [{ token: SensitiveString }];\nconsole.log(...args);'),
        errors: [{ messageId: 'preferSafeLog' }],
      },

      // A class instance, whose fields are properties like any other.
      {
        code: code(
          'declare class Box { token: SensitiveString }\ndeclare const b: Box;\nconsole.log(b);'
        ),
        errors: [{ messageId: 'preferSafeLog' }],
      },

      // A logger the project named itself.
      {
        code: code('declare const p: { token: SensitiveString };\nreport.warn(p);'),
        options: [{ logObjects: ['report'] }],
        errors: [{ messageId: 'preferSafeLog' }],
      },
    ],
  });

  describe('logger shapes', () => {
    runTypeAwareRuleTests('prefer-safe-log', preferSafeLog, {
      valid: [],
      invalid: [
        // Reached as a property of `this`, which the design's sketch missed.
        {
          code: code(
            'declare const p: { token: SensitiveString };\nclass A { logger!: { info(v: unknown): void }; m() { this.logger.info(p); } }'
          ),
          errors: [{ messageId: 'preferSafeLog' }],
        },
        // Behind a builder call.
        {
          code: code(
            'declare const p: { token: SensitiveString };\ndeclare const logger: { child(v: unknown): { info(v: unknown): void } };\nlogger.child({}).info(p);'
          ),
          errors: [{ messageId: 'preferSafeLog' }],
        },
      ],
    });
  });

  describe('without type information', () => {
    const missing = {
      valid: [],
      invalid: [
        {
          code: 'console.log(payload);',
          errors: [{ messageId: 'missingTypeInformation' }],
        },
        {
          code: 'const a = 1;',
          errors: [{ messageId: 'missingTypeInformation' }],
        },
      ],
    };

    runRuleTests('prefer-safe-log', preferSafeLog, missing);
    runTypeScriptRuleTests('prefer-safe-log', preferSafeLog, missing);
  });
});
