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
import { DEFAULT_SENSITIVE_TYPES, getTypeServices, isSensitiveWrapper } from '../type-info.js';
import type { AstNode, RuleContext, RuleListener, RuleModule } from '../types.js';

const RULE_NAME = 'require-reveal-context';

/**
 * Functions that install a reveal context for everything they run.
 *
 * A reveal inside one of these needs no argument of its own: the context comes
 * from `AsyncLocalStorage`, and the audit record is written either way.
 */
const DEFAULT_CONTEXT_FUNCTIONS: readonly string[] = ['withRevealContext', 'withAuditedReveals'];

/** Where a method takes its `RevealContext`, and what it takes to match it. */
interface ContextArgument {
  /** The argument the context is passed in. */
  readonly index: number;
  /**
   * Whether the receiver's type has to confirm the match.
   *
   * `reveal` is rare enough in ordinary code that matching it by name is the
   * documented tradeoff of an untyped rule, and `magician.reveal()` being
   * reported is the accepted cost. The others are not in that category:
   * `bcrypt` and `node:crypto` have a `hash`, every ORM and form library has a
   * `serialize`, and `mask` belongs to half the input libraries on npm. A rule
   * that reported those in a codebase would be turned off within the hour, so
   * they are checked only where the receiver's type can be read, and are
   * skipped in a file that has no type information.
   *
   * `reveal` by name and everything else by type is the whole rule in a line.
   */
  readonly typedOnly: boolean;
}

/**
 * The reads that take a `RevealContext`.
 *
 * `hash()` and `hmac()` are here because the library audits them exactly as it
 * audits a reveal: they read the raw value, charge the reveal budget, and write
 * an audit record. A record saying a digest of a credential was taken, with
 * nothing about who took it or why, is the gap this rule exists to close.
 *
 * `mask()` is a partial reveal that returns a plain string, and `serialize()`
 * returns the raw value in a wire object, so both belong here for a plainer
 * reason than the digests do.
 *
 * One table rather than a list of names and a second list of the typed ones,
 * so the two cannot come to disagree about a method that is in one and not the
 * other. What is not here is the transforms, `substring` and `map` and the
 * rest: they audit too, and requiring a context on `token.trim()` would make
 * the rule unusable long before it made an audit log better.
 */
const CONTEXT_METHODS: ReadonlyMap<string, ContextArgument> = new Map([
  [REVEAL_METHOD, { index: 0, typedOnly: false }],
  ['mask', { index: 1, typedOnly: true }],
  ['hash', { index: 2, typedOnly: true }],
  ['hmac', { index: 3, typedOnly: true }],
  ['serialize', { index: 0, typedOnly: true }],
]);

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
      'Require an audit context on reveal(), and on mask(), hash(), hmac() and serialize() where types are available, from an argument or an enclosing withRevealContext()',
      false
    ),
    messages: {
      missingContext:
        '{{method}}() has no audit context. Pass { name: "..." } or run the call inside {{contextFunction}}() so the access is attributable.',
      missingReason:
        '{{method}}() context has no "reason". Add one so the audit record says why the value was read, not just who read it.',
    },
    schema: [
      {
        type: 'object',
        properties: {
          requireReason: { type: 'boolean' },
          contextFunctions: nameListSchema(),
          sensitiveTypes: nameListSchema(),
        },
        additionalProperties: false,
      },
    ],
  },

  create(context: RuleContext): RuleListener {
    const option = optionObject(context.options, 0);
    const requireReason = readBoolean(option, 'requireReason', false);
    const contextFunctions = readNameSet(option, 'contextFunctions', DEFAULT_CONTEXT_FUNCTIONS);
    const sensitiveTypes = readNameSet(option, 'sensitiveTypes', DEFAULT_SENSITIVE_TYPES);
    const [suggestedFunction] = contextFunctions;
    const services = getTypeServices(context);

    return {
      CallExpression(node: AstNode): void {
        const call = asMethodCall(node);
        if (call === undefined) {
          return;
        }

        const method = CONTEXT_METHODS.get(call.method);
        if (method === undefined) {
          return;
        }

        // The lexical check first: it is a walk up the ancestors, where the
        // receiver check builds and searches a type.
        if (insideContextCall(getAncestors(context, node), contextFunctions)) {
          return;
        }

        if (
          method.typedOnly &&
          (services === undefined || !isSensitiveWrapper(call.receiver, services, sensitiveTypes))
        ) {
          return;
        }

        const index = method.index;

        const args = callArguments(node);

        // A spread ahead of the context moves everything after it, so which
        // argument is the context stops being a question syntax can answer.
        if (args.slice(0, index + 1).some((argument) => isSpread(argument))) {
          return;
        }

        const given = args[index];
        if (given === undefined || isExplicitUndefined(given)) {
          context.report({
            node,
            messageId: 'missingContext',
            data: {
              method: call.method,
              contextFunction: suggestedFunction ?? 'withRevealContext',
            },
          });
          return;
        }

        const givenContext = unwrap(given);
        if (requireReason && givenContext.type === 'ObjectExpression' && !hasReason(givenContext)) {
          context.report({ node, messageId: 'missingReason', data: { method: call.method } });
        }
      },
    };
  },
};
