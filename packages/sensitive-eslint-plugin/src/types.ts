/**
 * The slice of ESLint's rule API this plugin uses, declared structurally.
 *
 * ESLint's own types live in `@types/eslint`, which is a separate package on a
 * separate release train from `eslint` itself. Importing them here would put
 * that dependency into the emitted `.d.ts`, so every consumer would need it
 * installed to type-check against this plugin, and a consumer on ESLint 9 with
 * `@types/eslint@9` would be reading rule types from a different major than the
 * ones written against here. Declaring the shapes instead keeps the published
 * types self-contained, the same way the testing package declares
 * `pretty-format`'s plugin shape rather than depending on it.
 *
 * The types are also deliberately looser than ESLint's in one place: {@link
 * AstNode} carries nothing but `type`. A rule in this plugin has to run under
 * `espree` and under `@typescript-eslint/parser`, and the second produces nodes
 * (`TSAsExpression`, `TSNonNullExpression`) that no ESTree union contains. A
 * narrow union would make handling them a type error, which is backwards: the
 * TypeScript nodes are exactly the ones a security rule must not miss. Access
 * to a node's fields goes through the guards in `./ast.js`, which check at
 * runtime what the type system is not being asked to promise.
 */

/** Any node any parser produces. Narrow it with the guards in `./ast.js`. */
export interface AstNode {
  readonly type: string;
}

/** A single text edit. Produced by {@link RuleFixer}, applied by ESLint. */
export interface RuleFix {
  readonly range: readonly [number, number];
  readonly text: string;
}

/** The subset of ESLint's fixer used to build suggestions. */
export interface RuleFixer {
  replaceText(node: AstNode, text: string): RuleFix;
  insertTextAfter(node: AstNode, text: string): RuleFix;
}

/** One entry in a report's `suggest` list: a named, opt-in edit. */
export interface SuggestionDescriptor {
  readonly messageId: string;
  readonly data?: Readonly<Record<string, string>>;
  fix(fixer: RuleFixer): RuleFix | null;
}

/** What a rule hands to `context.report`. */
export interface ReportDescriptor {
  readonly node: AstNode;
  readonly messageId: string;
  readonly data?: Readonly<Record<string, string>>;
  readonly suggest?: readonly SuggestionDescriptor[];
}

/**
 * The subset of `SourceCode` the rules read.
 *
 * `visitorKeys` is the parser's own map of which fields of each node type hold
 * child nodes. Walking by that map rather than by a hand-written list of node
 * types is what lets one traversal cover JSX, decorators, and every TypeScript
 * node without this package knowing they exist.
 */
export interface SourceCode {
  readonly visitorKeys?: Readonly<Record<string, readonly string[]>> | undefined;
  getText(node?: AstNode): string;
  getCommentsInside(node: AstNode): readonly unknown[];
  /** ESLint 9. On ESLint 8 the equivalent lives on the context. */
  getAncestors?(node: AstNode): readonly AstNode[];
}

/**
 * The subset of `RuleContext` the rules read.
 *
 * `sourceCode` and `getSourceCode()` are both optional because they belong to
 * different ESLint majors: 9 has the property, 8 has the method, and 8.40
 * onward has both. Same story for ancestors. `./ast.js` resolves each one once
 * so no rule has to.
 */
export interface RuleContext {
  readonly options: readonly unknown[];
  readonly sourceCode?: SourceCode | undefined;
  getSourceCode?(): SourceCode;
  /** ESLint 8. Returns the ancestors of the node currently being visited. */
  getAncestors?(): readonly AstNode[];
  report(descriptor: ReportDescriptor): void;
}

/**
 * A rule's visitor, keyed by node type or by ESLint selector.
 *
 * The index signature is what keeps this general: a rule returns an object
 * literal with the handlers it needs and gets `AstNode` for the parameter by
 * contextual typing, with no union of node types to keep in step with a parser.
 */
export interface RuleListener {
  readonly [selector: string]: ((node: AstNode) => void) | undefined;
}

/** The documentation block of a rule's metadata. */
export interface RuleMetaDocs {
  readonly description: string;
  readonly recommended: boolean;
  readonly url?: string;
}

/** A rule's metadata, as ESLint reads it. */
export interface RuleMeta {
  readonly type: 'problem' | 'suggestion' | 'layout';
  readonly docs: RuleMetaDocs;
  readonly messages: Readonly<Record<string, string>>;
  /** JSON Schema for the rule's options, one entry per positional option. */
  readonly schema: readonly unknown[];
  /** Whether reports may carry `suggest` entries. No rule here auto-fixes. */
  readonly hasSuggestions?: boolean;
}

/** A rule, in the object form both ESLint 8 and 9 accept. */
export interface RuleModule {
  readonly meta: RuleMeta;
  create(context: RuleContext): RuleListener;
}

/** The plugin object itself, as a flat or legacy config consumes it. */
export interface Plugin {
  readonly meta: { readonly name: string; readonly version: string };
  readonly rules: Readonly<Record<string, RuleModule>>;
  readonly configs: Readonly<Record<string, unknown>>;
}
