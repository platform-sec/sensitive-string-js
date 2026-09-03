/**
 * `no-network-sensitive`: a secret leaves the process only on purpose.
 */
import {
  REVEAL_METHOD,
  callArguments,
  calleeChainNames,
  calleeOf,
  findMethodCalls,
  getSourceCode,
} from '../ast.js';
import { ruleDocs } from '../docs.js';
import { nameListSchema, optionObject, readBoolean, readNameSet } from '../options.js';
import type { AstNode, RuleContext, RuleListener, RuleModule } from '../types.js';

const RULE_NAME = 'no-network-sensitive';

/**
 * Names an HTTP client is reached by, anywhere along the callee chain.
 *
 * The list is of clients, not of methods, because `post` and `get` are far too
 * common to key on: matching `superagent.post(url).send(x)` has to recognise
 * `superagent`, and matching a bare `client.post(...)` would report every
 * mailbox and cache wrapper in a codebase.
 *
 * `request` is deliberately absent even though the library of that name exists.
 * Fastify calls its request object `request`, so the name appears in ordinary
 * handler code that sends nothing anywhere. A project using that library adds
 * it back through `networkFunctions`.
 */
const DEFAULT_NETWORK_FUNCTIONS: readonly string[] = [
  'fetch',
  '$fetch',
  'axios',
  'got',
  'ky',
  'superagent',
  'undici',
  'http',
  'https',
  'XMLHttpRequest',
];

/** Whether a call reaches an HTTP client. */
function isNetworkCall(node: AstNode, networkFunctions: ReadonlySet<string>): boolean {
  const callee = calleeOf(node);
  if (callee === undefined) {
    return false;
  }
  return calleeChainNames(callee).some((name) => networkFunctions.has(name));
}

export const noNetworkSensitive: RuleModule = {
  meta: {
    type: 'problem',
    docs: ruleDocs(
      RULE_NAME,
      'Disallow sending an unaudited revealed value in a network request',
      true
    ),
    messages: {
      noNetworkReveal:
        'This request sends the result of an unaudited reveal(). Give the reveal a context, as in reveal({ name: "auth-header" }), so the transmission is recorded, or send token.serialize() instead.',
      noNetworkRevealStrict:
        "This request sends a revealed value. Send token.serialize() instead, which keeps the wire format under the library's control.",
    },
    schema: [
      {
        type: 'object',
        properties: {
          networkFunctions: nameListSchema(),
          allowWithContext: { type: 'boolean' },
        },
        additionalProperties: false,
      },
    ],
  },

  create(context: RuleContext): RuleListener {
    const option = optionObject(context.options, 0);
    const networkFunctions = readNameSet(option, 'networkFunctions', DEFAULT_NETWORK_FUNCTIONS);

    /**
     * Whether a reveal that names its purpose may cross the network.
     *
     * On by default, which resolves what the two source documents say
     * differently. The roadmap's table describes the rule as catching any
     * `reveal()` inside a `fetch`, while the design document lists
     * `fetch(url, { headers: { Authorization: token.reveal({ name: 'auth-header' }) } })`
     * among its correct examples. They cannot both hold, and the design
     * document has the better of it: sending a credential is what an
     * `Authorization` header is for, so the rule that helps is one separating a
     * deliberate, audited send from an incidental one. Turn this off to forbid
     * both, for a service that must transmit only the serialized wire format.
     */
    const allowWithContext = readBoolean(option, 'allowWithContext', true);
    const revealMethods = new Set([REVEAL_METHOD]);
    const visitorKeys = getSourceCode(context)?.visitorKeys;

    return {
      CallExpression(node: AstNode): void {
        if (!isNetworkCall(node, networkFunctions)) {
          return;
        }

        for (const argument of callArguments(node)) {
          for (const reveal of findMethodCalls(argument, revealMethods, visitorKeys)) {
            const audited = callArguments(reveal).length > 0;
            if (allowWithContext && audited) {
              continue;
            }
            context.report({
              node: reveal,
              messageId: allowWithContext ? 'noNetworkReveal' : 'noNetworkRevealStrict',
            });
          }
        }
      },
    };
  },
};
