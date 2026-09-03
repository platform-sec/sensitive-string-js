/**
 * `no-credential-equality`: comparing a revealed value with `===` leaks timing.
 */
import {
  REVEAL_METHOD,
  asMethodCall,
  callArguments,
  discriminantOf,
  getSourceCode,
  isExplicitUndefined,
  operandsOf,
  operatorOf,
} from '../ast.js';
import type { MethodCall } from '../ast.js';
import { ruleDocs } from '../docs.js';
import type {
  AstNode,
  RuleContext,
  RuleListener,
  RuleModule,
  SourceCode,
  SuggestionDescriptor,
} from '../types.js';

const RULE_NAME = 'no-credential-equality';

/** The operators that compare two values and return early on the first difference. */
const EQUALITY_OPERATORS: ReadonlySet<string> = new Set(['===', '==', '!==', '!=']);

/** Operators whose result the `.equals()` form has to negate. */
const NEGATED_OPERATORS: ReadonlySet<string> = new Set(['!==', '!=']);

/** A reveal call, if that is what the operand is. */
function asRevealCall(node: AstNode): MethodCall | undefined {
  const call = asMethodCall(node);
  return call !== undefined && call.method === REVEAL_METHOD ? call : undefined;
}

/**
 * The audit context a reveal carries, or `undefined` if it carries none.
 *
 * A placeholder `undefined` counts as none, so the rewrite does not copy
 * `equals(other, undefined)` into the file and does not treat two reveals as
 * having a context each when only one really does.
 */
function revealContext(reveal: MethodCall | undefined): AstNode | undefined {
  if (reveal === undefined) {
    return undefined;
  }
  const [context] = callArguments(reveal.call);
  return context === undefined || isExplicitUndefined(context) ? undefined : context;
}

/**
 * The `.equals()` rewrite for one comparison, or `undefined` when it cannot be
 * written safely.
 *
 * The result is offered as a suggestion and never as an auto-fix. `--fix`
 * rewrites a file without anyone reading the diff, and the two forms are not
 * interchangeable: `equals()` on a `credential` compares in constant time, and
 * it can throw where `reveal()` did not, on an expired value or under a policy
 * that demands a context. That difference is the point of the rule and exactly
 * the reason a person, not a batch job, should accept it.
 *
 * Three cases are declined outright:
 *
 * - An optional call. `x?.reveal() === y` yields `false` when `x` is nullish
 *   while `x?.equals(y)` yields `undefined`, and a suggestion must not change
 *   which branch runs.
 * - A comment inside the comparison, which a text replacement would delete.
 * - A reveal on both sides carrying different contexts, where the rewrite would
 *   have to drop one of the two audit records.
 * - A comma expression on the other side. Its text carries a top-level comma,
 *   which inside an argument list would split into two arguments and quietly
 *   promote its second half to the audit context.
 */
function buildSuggestion(
  sourceCode: SourceCode,
  node: AstNode,
  operator: string,
  reveal: MethodCall,
  other: AstNode
): SuggestionDescriptor | undefined {
  if (reveal.optional) {
    return undefined;
  }
  if (sourceCode.getCommentsInside(node).length > 0) {
    return undefined;
  }

  if (other.type === 'SequenceExpression') {
    return undefined;
  }

  const otherReveal = asRevealCall(other);
  if (otherReveal !== undefined) {
    if (otherReveal.optional) {
      return undefined;
    }
    if (revealContext(reveal) !== undefined && revealContext(otherReveal) !== undefined) {
      return undefined;
    }
  }

  const receiver = sourceCode.getText(reveal.receiver);
  const comparand = sourceCode.getText(otherReveal === undefined ? other : otherReveal.receiver);

  // `equals(other, ctx?)` takes the context in second position, so a context
  // written on either reveal survives the rewrite. Only one can, which is why
  // a pair that both carry one is declined above.
  const contextArgument = revealContext(reveal) ?? revealContext(otherReveal);
  const context = contextArgument === undefined ? '' : `, ${sourceCode.getText(contextArgument)}`;

  const call = `${receiver}.equals(${comparand}${context})`;
  // `!` and a call both bind tighter than any equality operator, so replacing
  // the comparison never needs parentheses added around it.
  const replacement = NEGATED_OPERATORS.has(operator) ? `!${call}` : call;

  return {
    messageId: 'useEqualsSuggestion',
    data: { replacement },
    fix: (fixer) => fixer.replaceText(node, replacement),
  };
}

export const noCredentialEquality: RuleModule = {
  meta: {
    type: 'problem',
    docs: ruleDocs(
      RULE_NAME,
      'Disallow comparing a revealed sensitive value with an equality operator',
      true
    ),
    messages: {
      useEquals:
        'Comparing a revealed value with {{operator}} returns on the first differing byte, which leaks its contents to a timing attack. Use .equals(), which compares in constant time for the credential class.',
      noSwitchOnReveal:
        'switch on a revealed value compares each case in turn and stops at the first match, which leaks its contents to a timing attack. Use .equals() for each candidate instead.',
      useEqualsSuggestion: 'Replace with {{replacement}}',
    },
    hasSuggestions: true,
    schema: [],
  },

  create(context: RuleContext): RuleListener {
    const sourceCode = getSourceCode(context);

    return {
      BinaryExpression(node: AstNode): void {
        const operator = operatorOf(node);
        if (operator === undefined || !EQUALITY_OPERATORS.has(operator)) {
          return;
        }

        const operands = operandsOf(node);
        if (operands === undefined) {
          return;
        }

        // Operands arrive exactly as written. `asRevealCall` unwraps for itself,
        // and quoting an operand into a suggestion needs the author's text.
        // Whichever side reveals drives the rewrite. When both do, the left one
        // becomes the receiver, which reads the way the original did.
        const left = asRevealCall(operands.left);
        const reveal = left ?? asRevealCall(operands.right);
        if (reveal === undefined) {
          return;
        }
        const other = left === undefined ? operands.left : operands.right;

        const suggestion =
          sourceCode === undefined
            ? undefined
            : buildSuggestion(sourceCode, node, operator, reveal, other);

        context.report({
          node,
          messageId: 'useEquals',
          data: { operator },
          ...(suggestion === undefined ? {} : { suggest: [suggestion] }),
        });
      },

      SwitchStatement(node: AstNode): void {
        const discriminant = discriminantOf(node);
        if (discriminant === undefined || asRevealCall(discriminant) === undefined) {
          return;
        }
        context.report({ node: discriminant, messageId: 'noSwitchOnReveal' });
      },
    };
  },
};
