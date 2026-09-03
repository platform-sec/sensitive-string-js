/**
 * `no-log-reveal`: a revealed value must not reach a logger.
 */
import {
  REVEAL_METHOD,
  asMethodCall,
  calleeChainNames,
  calleeOf,
  callArguments,
  findMethodCalls,
  getSourceCode,
  identifierName,
  unwrap,
} from '../ast.js';
import { ruleDocs } from '../docs.js';
import { nameListSchema, optionObject, readNameSet } from '../options.js';
import type { AstNode, RuleContext, RuleListener, RuleModule } from '../types.js';

const RULE_NAME = 'no-log-reveal';

/**
 * Method names on a logger, plus `write`.
 *
 * `write` is here for `process.stdout.write(secret.reveal())`, which leaks
 * exactly what `console.log` leaks and is the first thing reached for when a
 * log line needs no newline. It only ever matches alongside a name from
 * {@link DEFAULT_LOG_OBJECTS}, so an unrelated `stream.write` is untouched.
 */
const DEFAULT_LOG_FUNCTIONS: readonly string[] = [
  'log',
  'info',
  'warn',
  'error',
  'debug',
  'trace',
  'fatal',
  'verbose',
  'silly',
  'write',
];

/** Names a logger is reached by, anywhere along the callee chain. */
const DEFAULT_LOG_OBJECTS: readonly string[] = [
  'console',
  'logger',
  'log',
  'winston',
  'pino',
  'bunyan',
  'stdout',
  'stderr',
];

/**
 * Methods whose result is the raw value.
 *
 * `serialize` is here alongside `reveal` because the wire format carries the
 * value in the clear: the README's first security note says so, and
 * `console.log(token.serialize())` is the more dangerous of the two precisely
 * because it reads like the safe option. Nothing else on `SensitiveString`
 * returns an unprotected value; `toString`, `toJSON` and `mask` all redact, and
 * logging them is the fix this rule points at.
 */
const DEFAULT_REVEAL_METHODS: readonly string[] = [REVEAL_METHOD, 'serialize'];

/**
 * Whether a call reaches a logger.
 *
 * Two shapes count. A method call needs its method name in `logFunctions` and
 * some name along its callee chain in `logObjects`, which covers `console.log`,
 * `this.logger.info`, `req.log.warn` and `logger.child({ id }).info` alike. A
 * bare call counts when the function's own name is in `logObjects`, which is
 * how `log(...)` from a destructured import is caught.
 *
 * Matching anywhere in the chain rather than at its head is a deliberate trade:
 * it takes an object named one of eight logger names carrying a method named
 * one of ten logger methods to produce a false positive, and it is the only way
 * to see a logger that arrives as a property.
 */
function isLogCall(
  node: AstNode,
  logFunctions: ReadonlySet<string>,
  logObjects: ReadonlySet<string>
): boolean {
  const callee = calleeOf(node);
  if (callee === undefined) {
    return false;
  }

  const bareName = identifierName(callee);
  if (bareName !== undefined) {
    return logObjects.has(bareName);
  }

  if (callee.type !== 'MemberExpression') {
    return false;
  }

  const names = calleeChainNames(callee);
  const method = names[0];
  if (method === undefined || !logFunctions.has(method)) {
    return false;
  }

  return names.slice(1).some((name) => logObjects.has(name));
}

export const noLogReveal: RuleModule = {
  meta: {
    type: 'problem',
    docs: ruleDocs(RULE_NAME, 'Disallow passing a revealed sensitive value to a logger', true),
    messages: {
      noLogReveal:
        'Do not log the result of .{{method}}(). Log the value itself, which redacts, or pass it through safeLog().',
      noLogRevealNested:
        'This argument contains a .{{method}}() call, so the logged output carries the raw value. Log the value itself, which redacts, or pass it through safeLog().',
    },
    schema: [
      {
        type: 'object',
        properties: {
          logFunctions: nameListSchema(),
          logObjects: nameListSchema(),
          revealMethods: nameListSchema(),
        },
        additionalProperties: false,
      },
    ],
  },

  create(context: RuleContext): RuleListener {
    const option = optionObject(context.options, 0);
    const logFunctions = readNameSet(option, 'logFunctions', DEFAULT_LOG_FUNCTIONS);
    const logObjects = readNameSet(option, 'logObjects', DEFAULT_LOG_OBJECTS);
    const revealMethods = readNameSet(option, 'revealMethods', DEFAULT_REVEAL_METHODS);
    const visitorKeys = getSourceCode(context)?.visitorKeys;

    return {
      CallExpression(node: AstNode): void {
        if (!isLogCall(node, logFunctions, logObjects)) {
          return;
        }

        for (const argument of callArguments(node)) {
          for (const reveal of findMethodCalls(argument, revealMethods, visitorKeys)) {
            context.report({
              node: reveal,
              messageId: unwrap(argument) === reveal ? 'noLogReveal' : 'noLogRevealNested',
              data: { method: asMethodCall(reveal)?.method ?? REVEAL_METHOD },
            });
          }
        }
      },
    };
  },
};
