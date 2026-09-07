/**
 * `no-allow-unaudited`: accepting a worker payload without the audit hook its
 * sender asked for.
 */
import {
  calleeChainNames,
  calleeOf,
  callArguments,
  isExplicitUndefined,
  isSpread,
  objectProperties,
  staticKeyName,
  unwrap,
} from '../ast.js';
import { ruleDocs } from '../docs.js';
import { nameListSchema, optionObject, readNameSet } from '../options.js';
import type { AstNode, RuleContext, RuleListener, RuleModule } from '../types.js';

const RULE_NAME = 'no-allow-unaudited';

/** The option this rule is about. */
const FLAG = 'allowUnaudited';

/**
 * The functions that consume a worker payload and take the flag.
 *
 * Both take it in an options object, and both drop the sender's audit hook
 * when it is set: a payload built under an audited context arrives with
 * `audited: true` and no hook, because a function cannot cross an isolate,
 * and the flag says to go ahead without one.
 */
const DEFAULT_PAYLOAD_FUNCTIONS: readonly string[] = ['fromWorkerPayload', 'withWorkerPayload'];

/**
 * Whether a property value is the literal `false`.
 *
 * `allowUnaudited: false` is the default spelled out, which is worth writing
 * in a config object that is built up and passed around, and there is nothing
 * to report about it.
 */
function isLiteralFalse(node: AstNode): boolean {
  const value = unwrap(node);
  return value.type === 'Literal' && (value as unknown as { value?: unknown }).value === false;
}

export const noAllowUnaudited: RuleModule = {
  meta: {
    type: 'problem',
    docs: ruleDocs(
      RULE_NAME,
      'Disallow allowUnaudited on fromWorkerPayload() and withWorkerPayload(), which drops an audit hook the sender asked for',
      true
    ),
    messages: {
      allowUnaudited:
        '{{function}}() with allowUnaudited accepts a payload whose sender installed an audit hook and records none of the reveals it authorizes, because the hook could not cross the thread boundary. Pass auditReveal so this side records what the sender asked to have recorded. If reveals here genuinely need no record, say why in a disable comment on this line.',
    },
    schema: [
      {
        type: 'object',
        properties: {
          payloadFunctions: nameListSchema(),
        },
        additionalProperties: false,
      },
    ],
  },

  create(context: RuleContext): RuleListener {
    const option = optionObject(context.options, 0);
    const payloadFunctions = readNameSet(option, 'payloadFunctions', DEFAULT_PAYLOAD_FUNCTIONS);

    return {
      CallExpression(node: AstNode): void {
        const callee = calleeOf(node);
        if (callee === undefined) {
          return;
        }

        // The nearest name in the chain, so `core.fromWorkerPayload(...)` and
        // a bare import both match.
        const [called] = calleeChainNames(callee);
        if (called === undefined || !payloadFunctions.has(called)) {
          return;
        }

        // Every argument is read rather than only the second: the flag has
        // exactly one meaning wherever it appears in one of these calls, and
        // reading by position would miss it behind a leading spread.
        for (const argument of callArguments(node)) {
          if (isSpread(argument)) {
            continue;
          }

          for (const property of objectProperties(unwrap(argument))) {
            if (isSpread(property) || staticKeyName(property) !== FLAG) {
              continue;
            }

            const value = (property as unknown as { value?: AstNode }).value;
            if (value !== undefined && (isLiteralFalse(value) || isExplicitUndefined(value))) {
              continue;
            }

            context.report({
              node: property,
              messageId: 'allowUnaudited',
              data: { function: called },
            });
          }
        }
      },
    };
  },
};
