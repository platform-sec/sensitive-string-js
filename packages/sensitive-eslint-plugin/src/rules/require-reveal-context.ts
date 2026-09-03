/**
 * `require-reveal-context`: a reveal should say who is reading and why.
 */
import {
  REVEAL_METHOD,
  asMethodCall,
  calleeChainNames,
  calleeOf,
  callArguments,
  getAncestors,
  isExplicitUndefined,
  isSpread,
  objectProperties,
  staticKeyName,
  unwrap,
} from '../ast.js';
import { ruleDocs } from '../docs.js';
import { nameListSchema, optionObject, readBoolean, readNameSet } from '../options.js';
import type { AstNode, RuleContext, RuleListener, RuleModule } from '../types.js';

const RULE_NAME = 'require-reveal-context';

/**
 * Functions that install a reveal context for everything they run.
 *
 * A reveal inside one of these needs no argument of its own: the context comes
 * from `AsyncLocalStorage`, and the audit record is written either way.
 */
const DEFAULT_CONTEXT_FUNCTIONS: readonly string[] = ['withRevealContext', 'withAuditedReveals'];

/**
 * Whether the reveal sits inside a call that installs a context.
 *
 * The check is lexical, so it sees the ordinary shape,
 * `withRevealContext(ctx, async () => { secret.reveal(); })`, and misses a
 * reveal in a function that is merely *called* from inside one. That miss is
 * the reason this rule ships as a warning: it costs a needless warning on
 * correct code, never a missed one on incorrect code.
 */
function insideContextCall(
  ancestors: readonly AstNode[],
  contextFunctions: ReadonlySet<string>
): boolean {
  return ancestors.some((ancestor) => {
    if (ancestor.type !== 'CallExpression') {
      return false;
    }

    const callee = calleeOf(ancestor);
    if (callee === undefined) {
      return false;
    }

    const [called] = calleeChainNames(callee);
    return called !== undefined && contextFunctions.has(called);
  });
}

/**
 * Whether an object literal spells out a `reason` property.
 *
 * A spread counts as satisfied. Reading what `{ ...base }` contributes needs
 * types this rule does not have, and warning on a context that is very likely
 * complete would train people to disable the rule.
 */
function hasReason(objectExpression: AstNode): boolean {
  return objectProperties(objectExpression).some(
    (property) => isSpread(property) || staticKeyName(property) === 'reason'
  );
}

export const requireRevealContext: RuleModule = {
  meta: {
    type: 'suggestion',
    docs: ruleDocs(
      RULE_NAME,
      'Require an audit context on reveal(), from an argument or an enclosing withRevealContext()',
      false
    ),
    messages: {
      missingContext:
        'reveal() has no audit context. Pass { name: "..." } or run the call inside {{contextFunction}}() so the access is attributable.',
      missingReason:
        'reveal() context has no "reason". Add one so the audit record says why the value was read, not just who read it.',
    },
    schema: [
      {
        type: 'object',
        properties: {
          requireReason: { type: 'boolean' },
          contextFunctions: nameListSchema(),
        },
        additionalProperties: false,
      },
    ],
  },

  create(context: RuleContext): RuleListener {
    const option = optionObject(context.options, 0);
    const requireReason = readBoolean(option, 'requireReason', false);
    const contextFunctions = readNameSet(option, 'contextFunctions', DEFAULT_CONTEXT_FUNCTIONS);
    const [suggestedFunction] = contextFunctions;

    return {
      CallExpression(node: AstNode): void {
        const call = asMethodCall(node);
        if (call === undefined || call.method !== REVEAL_METHOD) {
          return;
        }

        if (insideContextCall(getAncestors(context, node), contextFunctions)) {
          return;
        }

        const [first] = callArguments(node);
        if (first === undefined || isExplicitUndefined(first)) {
          context.report({
            node,
            messageId: 'missingContext',
            data: { contextFunction: suggestedFunction ?? 'withRevealContext' },
          });
          return;
        }

        const givenContext = unwrap(first);
        if (requireReason && givenContext.type === 'ObjectExpression' && !hasReason(givenContext)) {
          context.report({ node, messageId: 'missingReason' });
        }
      },
    };
  },
};
