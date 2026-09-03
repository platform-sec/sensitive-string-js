import { describe } from 'vitest';
import { noLogReveal } from './no-log-reveal.js';
import { runRuleTests, runTypeScriptRuleTests } from '../__tests__/rule-tester.js';

describe('no-log-reveal', () => {
  runRuleTests('no-log-reveal', noLogReveal, {
    valid: [
      // The redacting paths are the fix the rule points at.
      'console.log(secret);',
      'console.log(secret.toString());',
      'console.log(String(secret));',
      'console.log(safeLog({ secret }));',
      'console.log(safeStringify(body));',
      'console.log(secret.mask());',
      'logger.info("token present:", Boolean(token));',

      // A reveal that is not being logged.
      'const raw = secret.reveal();',
      'authenticate(secret.reveal());',
      'db.query(sql, [secret.reveal()]);',

      // Reading the method without calling it is not a reveal.
      'console.log(typeof secret.reveal);',

      // Not a logger, despite the method name.
      'metrics.info(secret.reveal());',
      'account.log(secret.reveal());',

      // Not a log method, despite the object name.
      'logger.child({ id: secret.reveal() });',

      // A narrowed configuration must actually narrow.
      {
        code: 'logger.info(secret.reveal());',
        options: [{ logObjects: ['console'] }],
      },
      {
        code: 'console.log(token.serialize());',
        options: [{ revealMethods: ['reveal'] }],
      },
    ],

    invalid: [
      // TST-ESL-NLR-001: the headline case.
      {
        code: 'console.log(secret.reveal());',
        errors: [{ messageId: 'noLogReveal', data: { method: 'reveal' } }],
      },

      // TST-ESL-NLR-002: nested one level down in an object argument.
      {
        code: 'logger.info({ key: secret.reveal() });',
        errors: [{ messageId: 'noLogRevealNested' }],
      },

      // TST-ESL-NLR-003: interpolated into a template literal.
      {
        code: 'console.log(`token: ${token.reveal()}`);',
        errors: [{ messageId: 'noLogRevealNested' }],
      },

      // TST-ESL-NLR-007: inside an array.
      {
        code: 'console.debug([a.reveal(), b]);',
        errors: [{ messageId: 'noLogRevealNested' }],
      },

      // TST-ESL-NLR-008: several levels of object and array nesting.
      {
        code: 'logger.error({ req: { headers: [{ auth: token.reveal() }] } });',
        errors: [{ messageId: 'noLogRevealNested' }],
      },

      // TST-ESL-NLR-006: a logger the project named itself.
      {
        code: 'report.warn(secret.reveal());',
        options: [{ logObjects: ['report'] }],
        errors: [{ messageId: 'noLogReveal' }],
      },

      // Every argument is checked, and every reveal within one.
      {
        code: 'console.log(a.reveal(), b.reveal());',
        errors: [{ messageId: 'noLogReveal' }, { messageId: 'noLogReveal' }],
      },
      {
        code: 'console.log({ a: a.reveal(), b: b.reveal() });',
        errors: [{ messageId: 'noLogRevealNested' }, { messageId: 'noLogRevealNested' }],
      },

      // A partial reveal is still the value.
      {
        code: 'console.log(secret.reveal().slice(0, 4));',
        errors: [{ messageId: 'noLogRevealNested' }],
      },
      {
        code: 'console.log("token: " + token.reveal());',
        errors: [{ messageId: 'noLogRevealNested' }],
      },

      // safeLog cannot redact a string that is already raw.
      {
        code: 'console.log(safeLog({ token: token.reveal() }));',
        errors: [{ messageId: 'noLogRevealNested' }],
      },

      // The serialized wire format carries the value in the clear.
      {
        code: 'console.log(token.serialize());',
        errors: [{ messageId: 'noLogReveal', data: { method: 'serialize' } }],
      },
    ],
  });

  describe('logger shapes', () => {
    runRuleTests('no-log-reveal', noLogReveal, {
      valid: [],
      invalid: [
        // Reached as a property of `this`.
        {
          code: 'class S { f() { this.logger.info(this.token.reveal()); } }',
          errors: [{ messageId: 'noLogReveal' }],
        },
        // Reached as a property of a request, the Fastify and Pino-HTTP shape.
        {
          code: 'req.log.warn(secret.reveal());',
          errors: [{ messageId: 'noLogReveal' }],
        },
        // Reached through a builder call.
        {
          code: 'logger.child({ id }).info(secret.reveal());',
          errors: [{ messageId: 'noLogReveal' }],
        },
        // A bare function whose name says logger.
        {
          code: 'log(secret.reveal());',
          errors: [{ messageId: 'noLogReveal' }],
        },
        // The stream behind console.
        {
          code: 'process.stdout.write(secret.reveal());',
          errors: [{ messageId: 'noLogReveal' }],
        },
        // A computed method name resolves to the same method.
        {
          code: "console['log'](secret['reveal']());",
          errors: [{ messageId: 'noLogReveal' }],
        },
        // Optional chaining on either the logger or the value.
        {
          code: 'logger?.info(secret?.reveal());',
          errors: [{ messageId: 'noLogReveal' }],
        },
      ],
    });
  });

  describe('callbacks', () => {
    runRuleTests('no-log-reveal', noLogReveal, {
      valid: [],
      invalid: [
        // The reason the walk descends into function bodies: mapping a list of
        // secrets leaks every one of them.
        {
          code: 'console.log(secrets.map((s) => s.reveal()));',
          errors: [{ messageId: 'noLogRevealNested' }],
        },
        {
          code: 'console.log(await Promise.all(ids.map(async (id) => (await load(id)).reveal())));',
          errors: [{ messageId: 'noLogRevealNested' }],
        },
      ],
    });
  });

  describe('under the TypeScript parser', () => {
    runTypeScriptRuleTests('no-log-reveal', noLogReveal, {
      valid: ['console.log(secret satisfies Redacted);'],
      invalid: [
        // A cast is transparent, so the argument still *is* the reveal and the
        // direct message is the accurate one.
        {
          code: 'console.log(secret.reveal() as string);',
          errors: [{ messageId: 'noLogReveal' }],
        },
        {
          code: 'console.log(secret!.reveal());',
          errors: [{ messageId: 'noLogReveal' }],
        },
        {
          code: 'logger.info({ token: token.reveal() satisfies string });',
          errors: [{ messageId: 'noLogRevealNested' }],
        },
      ],
    });
  });
});
