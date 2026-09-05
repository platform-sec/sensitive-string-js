/**
 * `no-log-reveal`: a revealed value must not reach a logger.
 */
import {
  REVEAL_METHOD,
  asMethodCall,
  callArguments,
  findMethodCalls,
  getSourceCode,
  unwrap,
} from '../ast.js';
import { ruleDocs } from '../docs.js';
import { DEFAULT_LOG_FUNCTIONS, DEFAULT_LOG_OBJECTS, isLogCall } from '../log-calls.js';
import { nameListSchema, optionObject, readNameSet } from '../options.js';
import type { AstNode, RuleContext, RuleListener, RuleModule } from '../types.js';

const RULE_NAME = 'no-log-reveal';

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
