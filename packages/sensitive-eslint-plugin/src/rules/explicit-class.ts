/**
 * `explicit-class`: a sensitive value must be constructed with its class.
 */
import { callArguments, calleeChainNames, calleeOf, hasSpreadArgument } from '../ast.js';
import { ruleDocs } from '../docs.js';
import { nameListSchema, optionObject, readNameSet } from '../options.js';
import type {
  AstNode,
  RuleContext,
  RuleListener,
  RuleModule,
  SuggestionDescriptor,
} from '../types.js';

const RULE_NAME = 'explicit-class';

/** Constructors whose second parameter is the sensitivity class. */
const DEFAULT_CONSTRUCTOR_NAMES: readonly string[] = ['SensitiveString'];

/** The classes the core library defines, in the order the suggestions offer them. */
const SENSITIVITY_CLASSES: readonly string[] = ['sensitive', 'credential'];

export const explicitClass: RuleModule = {
  meta: {
    type: 'suggestion',
    docs: ruleDocs(
      RULE_NAME,
      'Require an explicit sensitivity class when constructing a SensitiveString',
      true
    ),
    messages: {
      missingClass:
        "new {{name}}() has no sensitivity class. Pass 'credential' for anything compared against user input, or 'sensitive' otherwise; the class decides redaction and whether comparison is constant-time.",
      addClass: "Pass '{{klass}}' as the sensitivity class",
    },
    hasSuggestions: true,
    schema: [
      {
        type: 'object',
        properties: {
          constructorNames: nameListSchema(),
        },
        additionalProperties: false,
      },
    ],
  },

  create(context: RuleContext): RuleListener {
    const option = optionObject(context.options, 0);
    const constructorNames = readNameSet(option, 'constructorNames', DEFAULT_CONSTRUCTOR_NAMES);

    return {
      NewExpression(node: AstNode): void {
        const callee = calleeOf(node);
        if (callee === undefined) {
          return;
        }

        // The chain covers both `new SensitiveString(v)` and the namespaced
        // `new core.SensitiveString(v)`.
        const [name] = calleeChainNames(callee);
        if (name === undefined || !constructorNames.has(name)) {
          return;
        }

        // A spread makes the argument count unknowable, and guessing would
        // report correct code. Precision matters more here than reach: the
        // constructor's TypeScript signature already requires the class, so
        // this rule is a second line for JavaScript callers and `any`-typed
        // call sites, not the only one.
        if (hasSpreadArgument(node)) {
          return;
        }

        const args = callArguments(node);
        if (args.length >= 2) {
          return;
        }

        // Offered only when there is a value argument to append to. With no
        // arguments at all the call is already broken in a way no sensitivity
        // class fixes, and the report alone is the honest answer.
        const value = args[0];
        const suggestions: readonly SuggestionDescriptor[] =
          value === undefined
            ? []
            : SENSITIVITY_CLASSES.map((klass) => ({
                messageId: 'addClass',
                data: { klass },
                fix: (fixer) => fixer.insertTextAfter(value, `, '${klass}'`),
              }));

        context.report({
          node,
          messageId: 'missingClass',
          data: { name },
          ...(suggestions.length === 0 ? {} : { suggest: suggestions }),
        });
      },
    };
  },
};
