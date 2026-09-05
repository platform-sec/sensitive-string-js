/**
 * `prefer-safe-log`: redact before the logger, not inside it.
 */
import { callArguments } from '../ast.js';
import { ruleDocs } from '../docs.js';
import { DEFAULT_LOG_FUNCTIONS, DEFAULT_LOG_OBJECTS, isLogCall } from '../log-calls.js';
import { nameListSchema, optionObject, readNameSet } from '../options.js';
import {
  DEFAULT_SENSITIVE_TYPES,
  DEFAULT_SERIALIZED_TYPES,
  findSensitiveType,
  getTypeServices,
} from '../type-info.js';
import type { AstNode, RuleContext, RuleListener, RuleModule } from '../types.js';

const RULE_NAME = 'prefer-safe-log';

export const preferSafeLog: RuleModule = {
  meta: {
    type: 'suggestion',
    docs: {
      ...ruleDocs(
        RULE_NAME,
        'Prefer safeLog() when logging a structure whose type carries a sensitive value',
        false
      ),
      requiresTypeChecking: true,
    },
    messages: {
      preferSafeLog:
        'This structure holds a {{name}}, so what gets written depends on which serializer the transport happens to call. safeLog() redacts the copy before the logger sees it, which does not.',
      logsSerialized:
        'A serialize() result reaches this logger: a plain object carrying the raw value, which nothing redacts, because it is the one shape toString() and toJSON() cannot reach. Pass it through safeLog(), which replaces it with the redaction its class would produce.',
      missingTypeInformation:
        'This rule needs type information and has none, so it is reporting nothing at all. Configure typescript-eslint type-aware linting for this file, or apply the disable-type-checked preset to files that have no TypeScript program.',
    },
    schema: [
      {
        type: 'object',
        properties: {
          logFunctions: nameListSchema(),
          logObjects: nameListSchema(),
          sensitiveTypes: nameListSchema(),
          serializedTypes: nameListSchema(),
        },
        additionalProperties: false,
      },
    ],
  },

  create(context: RuleContext): RuleListener {
    const option = optionObject(context.options, 0);
    const logFunctions = readNameSet(option, 'logFunctions', DEFAULT_LOG_FUNCTIONS);
    const logObjects = readNameSet(option, 'logObjects', DEFAULT_LOG_OBJECTS);
    const names = {
      sensitive: readNameSet(option, 'sensitiveTypes', DEFAULT_SENSITIVE_TYPES),
      serialized: readNameSet(option, 'serializedTypes', DEFAULT_SERIALIZED_TYPES),
    };
    const services = getTypeServices(context);

    if (services === undefined) {
      return {
        Program(node: AstNode): void {
          context.report({ node, messageId: 'missingTypeInformation' });
        },
      };
    }

    return {
      CallExpression(node: AstNode): void {
        if (!isLogCall(node, logFunctions, logObjects)) {
          return;
        }

        for (const argument of callArguments(node)) {
          // Every argument, not just the first: `logger.info('sending', payload)`
          // puts the message in one and the structure in the next.
          const match = findSensitiveType(argument, services, names);
          if (match === undefined) {
            continue;
          }

          // Logging the value itself, or a plain list of them, is the
          // documented way to do it: the class redacts itself through
          // `util.inspect` and through `toJSON`, and an array delegates to each
          // element. What this rule is about is a record that holds one, where
          // the redaction becomes the transport's business. A serialize()
          // result is reported wherever it sits, because nothing redacts it.
          if (!match.serialized && !match.throughProperty) {
            continue;
          }

          context.report({
            node: argument,
            messageId: match.serialized ? 'logsSerialized' : 'preferSafeLog',
            data: { name: match.name },
          });
        }
      },
    };
  },
};
