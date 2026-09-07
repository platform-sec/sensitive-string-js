/**
 * `no-password-fast-hash`: a fast digest is not password storage.
 */
import { asMethodCall, calleeChainNames } from '../ast.js';
import { ruleDocs } from '../docs.js';
import { nameListSchema, optionObject, readNameSet } from '../options.js';
import type { AstNode, RuleContext, RuleListener, RuleModule } from '../types.js';

const RULE_NAME = 'no-password-fast-hash';

/**
 * The library's fast digests.
 *
 * `hmac()` is here beside `hash()` because a key does not make a fast function
 * slow. Peppering a password with an HMAC and storing the result is a real
 * pattern, and a defensible one only *on top of* a KDF, never instead of it.
 */
const FAST_HASH_METHODS: ReadonlySet<string> = new Set(['hash', 'hmac']);

/**
 * What a password is called.
 *
 * Matched case-insensitively as a fragment, so `newPassword`, `user.passwd`
 * and `plainPwd` all count. `secret`, `token` and `key` are deliberately
 * absent: those are the values `hash()` is *for*, and a rule that reported
 * them would be reporting the feature.
 */
const DEFAULT_PASSWORD_NAMES: readonly string[] = ['password', 'passwd', 'passphrase', 'pwd'];

/**
 * The name of the value being hashed.
 *
 * The first name in the receiver's chain, which is the value itself rather
 * than whatever holds it: `user.password.hash()` reports on `password`, and
 * `passwordService.token.hash()` reports on `token`, which is to say not at
 * all. A call is stepped through, so `getPassword().hash()` is reached.
 */
function hashedValueName(receiver: AstNode): string | undefined {
  const [nearest] = calleeChainNames(receiver);
  return nearest;
}

function looksLikeAPassword(name: string, fragments: ReadonlySet<string>): boolean {
  const lowered = name.toLowerCase();

  for (const fragment of fragments) {
    if (lowered.includes(fragment.toLowerCase())) {
      return true;
    }
  }

  return false;
}

export const noPasswordFastHash: RuleModule = {
  meta: {
    type: 'problem',
    docs: ruleDocs(
      RULE_NAME,
      'Disallow hashing a password with hash() or hmac(), which are fast by design',
      false
    ),
    messages: {
      fastHash:
        '{{method}}() is a fast digest, not password storage: a wordlist runs through SHA-256 at billions of guesses a second, and a salt does not slow that down for whoever has the row it is stored in. Use hashForStorage() from @platform-sec/sensitive-string-kdf.',
    },
    schema: [
      {
        type: 'object',
        properties: {
          passwordNames: nameListSchema(),
        },
        additionalProperties: false,
      },
    ],
  },

  create(context: RuleContext): RuleListener {
    const option = optionObject(context.options, 0);
    const passwordNames = readNameSet(option, 'passwordNames', DEFAULT_PASSWORD_NAMES);

    return {
      CallExpression(node: AstNode): void {
        const call = asMethodCall(node);
        if (call === undefined || !FAST_HASH_METHODS.has(call.method)) {
          return;
        }

        const name = hashedValueName(call.receiver);
        if (name === undefined || !looksLikeAPassword(name, passwordNames)) {
          return;
        }

        context.report({ node, messageId: 'fastHash', data: { method: call.method } });
      },
    };
  },
};
