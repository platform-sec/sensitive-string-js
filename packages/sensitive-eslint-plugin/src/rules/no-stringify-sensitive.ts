/**
 * `no-stringify-sensitive`: `JSON.stringify` is the wrong tool for a structure
 * holding a sensitive value, in both directions.
 */
import { callArguments, calleeChainNames, calleeOf, staticPropertyName } from '../ast.js';
import { ruleDocs } from '../docs.js';
import { nameListSchema, optionObject, readNameSet } from '../options.js';
import {
  DEFAULT_SENSITIVE_TYPES,
  DEFAULT_SERIALIZED_TYPES,
  findSensitiveType,
  getTypeServices,
} from '../type-info.js';
import type { AstNode, RuleContext, RuleListener, RuleModule } from '../types.js';

const RULE_NAME = 'no-stringify-sensitive';

/**
 * Whether a call is `JSON.stringify(...)`.
 *
 * Keyed on the method name with `JSON` somewhere along the chain, the same way
 * the other call-matching rules work, so `globalThis.JSON.stringify` and a
 * `JSON` reached through an alias both count. No option widens this: `JSON` is
 * a global with one spelling, and a project's own serializer is a different
 * rule's subject.
 */
function isJsonStringify(node: AstNode): boolean {
  const callee = calleeOf(node);
  if (callee === undefined || callee.type !== 'MemberExpression') {
    return false;
  }

  if (staticPropertyName(callee) !== 'stringify') {
    return false;
  }

  return calleeChainNames(callee).slice(1).includes('JSON');
}

export const noStringifySensitive: RuleModule = {
  meta: {
    type: 'problem',
    docs: {
      ...ruleDocs(
        RULE_NAME,
        'Disallow JSON.stringify on a structure whose type carries a sensitive value',
        true
      ),
      requiresTypeChecking: true,
    },
    messages: {
      stringifySensitive:
        'JSON.stringify writes the redaction of this {{name}}, not its value, and nothing at the call site says so. Use safeStringify() when redacted JSON is what you want, or serialize() on the field when the value has to reach the other side.',
      stringifySerialized:
        'A serialize() result reaches JSON.stringify here: a plain object holding the raw value, which it writes out in the clear. Send that only over the transport it was serialized for, and use safeStringify() for anything going to a log or a store.',
      missingTypeInformation:
        'This rule needs type information and has none, so it is reporting nothing at all. Configure typescript-eslint type-aware linting for this file, or apply the disable-type-checked preset to files that have no TypeScript program.',
    },
    schema: [
      {
        type: 'object',
        properties: {
          sensitiveTypes: nameListSchema(),
          serializedTypes: nameListSchema(),
        },
        additionalProperties: false,
      },
    ],
  },

  create(context: RuleContext): RuleListener {
    const option = optionObject(context.options, 0);
    const names = {
      sensitive: readNameSet(option, 'sensitiveTypes', DEFAULT_SENSITIVE_TYPES),
      serialized: readNameSet(option, 'serializedTypes', DEFAULT_SERIALIZED_TYPES),
    };
    const services = getTypeServices(context);

    if (services === undefined) {
      // Silence would be the worse failure. A rule that reports nothing looks
      // exactly like a rule that found nothing, and this one is read as
      // "no sensitive value reaches JSON.stringify in this file".
      return {
        Program(node: AstNode): void {
          context.report({ node, messageId: 'missingTypeInformation' });
        },
      };
    }

    return {
      CallExpression(node: AstNode): void {
        if (!isJsonStringify(node)) {
          return;
        }

        // Only the first argument. The second is a replacer and the third is
        // an indent, and neither is written into the output as a value.
        const [value] = callArguments(node);
        if (value === undefined) {
          return;
        }

        const match = findSensitiveType(value, services, names);
        if (match === undefined) {
          return;
        }

        context.report({
          node: value,
          messageId: match.serialized ? 'stringifySerialized' : 'stringifySensitive',
          data: { name: match.name },
        });
      },
    };
  },
};
