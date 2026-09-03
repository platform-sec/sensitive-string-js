/**
 * Parser-agnostic AST access.
 *
 * Every rule in this plugin reduces to two questions: "is this call a call to
 * something I care about" and "does this expression contain a `.reveal()`
 * anywhere inside it". Both are answered here, once, so a gap fixed for one
 * rule is fixed for all of them.
 */
import type { AstNode, RuleContext, SourceCode } from './types.js';

/**
 * The method that hands out the raw value.
 *
 * Every rule keys off this name. It is a method name rather than a type, which
 * is the whole tradeoff of an untyped rule: `magician.reveal()` looks the same
 * as `apiKey.reveal()` to a parser. The rules that can narrow further (by
 * requiring a log call or a network call around it) do; the ones that cannot
 * say so in their documentation.
 */
export const REVEAL_METHOD = 'reveal';

/**
 * Node types that wrap an expression without changing its value, each holding
 * the wrapped expression in `expression`.
 *
 * `ChainExpression` is how ESTree represents an optional chain, so `x?.reveal()`
 * arrives as a `ChainExpression` and not as the `CallExpression` a rule is
 * looking for. The `TS*` entries are `@typescript-eslint/parser` nodes: without
 * unwrapping them, `(x.reveal() as string) === y` and `x!.reveal() === y` both
 * slip past a rule that only checks whether an operand is a `CallExpression`.
 * Casting a revealed secret is not a rare thing to write, so missing it would
 * be a bypass rather than an edge case.
 */
const TRANSPARENT_WRAPPERS: ReadonlySet<string> = new Set([
  'ChainExpression',
  'ParenthesizedExpression',
  'TSAsExpression',
  'TSSatisfiesExpression',
  'TSNonNullExpression',
  'TSTypeAssertion',
  'TSInstantiationExpression',
]);

/** Fields never followed when walking, whatever a parser puts in them. */
const NON_CHILD_KEYS: ReadonlySet<string> = new Set(['parent', 'loc', 'range', 'type']);

/** Read one field of a node without pretending to know the node's shape. */
function field(node: AstNode, key: string): unknown {
  return (node as unknown as Record<string, unknown>)[key];
}

/** Whether a value is a node: an object carrying a `type` string. */
function isNode(value: unknown): value is AstNode {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { type?: unknown }).type === 'string'
  );
}

/** A node's field as a node, or `undefined` if it does not hold one. */
function nodeField(node: AstNode, key: string): AstNode | undefined {
  const value = field(node, key);
  return isNode(value) ? value : undefined;
}

/** A node's field as a list of nodes, skipping the holes an array may contain. */
function nodeListField(node: AstNode, key: string): readonly AstNode[] {
  const value = field(node, key);
  return Array.isArray(value) ? value.filter(isNode) : [];
}

/**
 * The expression inside any number of value-preserving wrappers.
 *
 * Idempotent and safe on a cyclic-looking tree: it only ever descends, and each
 * step moves strictly inward.
 */
export function unwrap(node: AstNode): AstNode {
  let current = node;
  while (TRANSPARENT_WRAPPERS.has(current.type)) {
    const inner = nodeField(current, 'expression');
    if (inner === undefined) {
      return current;
    }
    current = inner;
  }
  return current;
}

/** An `Identifier`'s name, or `undefined` for any other node. */
export function identifierName(node: AstNode): string | undefined {
  if (node.type !== 'Identifier') {
    return undefined;
  }
  const name = field(node, 'name');
  return typeof name === 'string' ? name : undefined;
}

/**
 * The property name a member expression reads, when it is knowable statically.
 *
 * `x.reveal` and `x['reveal']` name the same method and both resolve here;
 * `x[key]` does not, and yields `undefined` rather than a guess. Handling the
 * computed-string form matters because it is the shortest way to write a call
 * that a name-matching rule would otherwise miss.
 */
export function staticPropertyName(member: AstNode): string | undefined {
  const property = nodeField(member, 'property');
  if (property === undefined) {
    return undefined;
  }

  if (field(member, 'computed') !== true) {
    return identifierName(property);
  }

  return property.type === 'Literal' ? literalString(property) : undefined;
}

/**
 * The property name an object-literal entry defines, when it is knowable
 * statically. `{ reason: r }` and `{ 'reason': r }` both resolve; `{ [k]: r }`
 * does not.
 */
export function staticKeyName(property: AstNode): string | undefined {
  const key = nodeField(property, 'key');
  if (key === undefined) {
    return undefined;
  }

  if (field(property, 'computed') !== true) {
    return identifierName(key) ?? literalString(key);
  }

  return key.type === 'Literal' ? literalString(key) : undefined;
}

/** A `Literal`'s value when it is a string, otherwise `undefined`. */
export function literalString(node: AstNode): string | undefined {
  if (node.type !== 'Literal') {
    return undefined;
  }
  const value = field(node, 'value');
  return typeof value === 'string' ? value : undefined;
}

/** An object expression's entries, or an empty list for any other node. */
export function objectProperties(node: AstNode): readonly AstNode[] {
  return nodeListField(node, 'properties');
}

/** A binary or unary expression's operator, or `undefined` for any other node. */
export function operatorOf(node: AstNode): string | undefined {
  const operator = field(node, 'operator');
  return typeof operator === 'string' ? operator : undefined;
}

/** A binary expression's operands, unwrapped, or `undefined` if it has none. */
export function operandsOf(
  node: AstNode
): { readonly left: AstNode; readonly right: AstNode } | undefined {
  const left = nodeField(node, 'left');
  const right = nodeField(node, 'right');
  if (left === undefined || right === undefined) {
    return undefined;
  }
  return { left: unwrap(left), right: unwrap(right) };
}

/** A switch statement's discriminant, unwrapped, or `undefined`. */
export function discriminantOf(node: AstNode): AstNode | undefined {
  const discriminant = nodeField(node, 'discriminant');
  return discriminant === undefined ? undefined : unwrap(discriminant);
}

/** Whether a node is a spread, in either the ESTree or the legacy spelling. */
export function isSpread(node: AstNode): boolean {
  return node.type === 'SpreadElement' || node.type === 'ExperimentalSpreadProperty';
}

/** A call expression's arguments, or an empty list for any other node. */
export function callArguments(node: AstNode): readonly AstNode[] {
  return nodeListField(node, 'arguments');
}

/** A call or `new` expression's callee, unwrapped, or `undefined`. */
export function calleeOf(node: AstNode): AstNode | undefined {
  const callee = nodeField(node, 'callee');
  return callee === undefined ? undefined : unwrap(callee);
}

/** Whether any argument is a spread, which makes the argument count unknowable. */
export function hasSpreadArgument(node: AstNode): boolean {
  return callArguments(node).some(isSpread);
}

/** A call whose callee reads a named method off some receiver. */
export interface MethodCall {
  /** The `CallExpression`, already unwrapped. */
  readonly call: AstNode;
  /** The `MemberExpression` in callee position, already unwrapped. */
  readonly callee: AstNode;
  /** The receiver the method was read from: the `x` of `x.reveal()`. */
  readonly receiver: AstNode;
  /** The method name, resolved through a computed string key when needed. */
  readonly method: string;
  /** Whether any link in the callee is optional, as in `x?.reveal()`. */
  readonly optional: boolean;
}

/**
 * A node read as a method call, or `undefined` if it is not one.
 *
 * `optional` is reported rather than ignored so a rule that rewrites code can
 * decline to: `x?.reveal() === y` and `x?.equals(y)` differ when `x` is nullish
 * (`false` against `undefined`), and a suggestion is not the place to change
 * that.
 */
export function asMethodCall(node: AstNode): MethodCall | undefined {
  const optionalOuter = node.type === 'ChainExpression';
  const call = unwrap(node);
  if (call.type !== 'CallExpression') {
    return undefined;
  }

  const rawCallee = nodeField(call, 'callee');
  if (rawCallee === undefined) {
    return undefined;
  }

  const callee = unwrap(rawCallee);
  if (callee.type !== 'MemberExpression') {
    return undefined;
  }

  const method = staticPropertyName(callee);
  const receiver = nodeField(callee, 'object');
  if (method === undefined || receiver === undefined) {
    return undefined;
  }

  return {
    call,
    callee,
    receiver,
    method,
    optional:
      optionalOuter || field(call, 'optional') === true || field(callee, 'optional') === true,
  };
}

/** Whether a node is a call to one of `methods` on some receiver. */
export function isMethodCallNamed(node: AstNode, methods: ReadonlySet<string>): boolean {
  const call = asMethodCall(node);
  return call !== undefined && methods.has(call.method);
}

/**
 * Every identifier and static property name along a callee chain.
 *
 * `console.log` yields `['log', 'console']`, `this.logger.info` yields
 * `['info', 'logger']`, and `logger.child({ req }).info` yields
 * `['info', 'child', 'logger']`. Matching against the whole chain rather than
 * against a leading identifier is what lets a rule recognise the ways a logger
 * or an HTTP client is actually reached: as a field of `this`, as a property of
 * a request, or through a builder call.
 *
 * A link whose name is not statically knowable is stepped over rather than
 * stopped at: `handlers[i].logger.info` still yields `['info', 'logger']`, so an
 * index into a collection does not hide the object behind it. The walk ends at
 * the first node that is neither a member access nor a call, which is an
 * identifier (collected) or `this` (not).
 */
export function calleeChainNames(callee: AstNode): readonly string[] {
  const names: string[] = [];
  let current: AstNode | undefined = unwrap(callee);

  while (current !== undefined) {
    if (current.type === 'MemberExpression') {
      const name = staticPropertyName(current);
      if (name !== undefined) {
        names.push(name);
      }
      const object = nodeField(current, 'object');
      current = object === undefined ? undefined : unwrap(object);
      continue;
    }

    if (current.type === 'CallExpression' || current.type === 'NewExpression') {
      const inner = nodeField(current, 'callee');
      current = inner === undefined ? undefined : unwrap(inner);
      continue;
    }

    const name = identifierName(current);
    if (name !== undefined) {
      names.push(name);
    }
    current = undefined;
  }

  return names;
}

/**
 * The `SourceCode` for the file being linted, across ESLint majors.
 *
 * ESLint 9 exposes it as a property and removed the getter; ESLint 8 has the
 * getter from the start and gained the property in 8.40.
 */
export function getSourceCode(context: RuleContext): SourceCode | undefined {
  if (context.sourceCode !== undefined) {
    return context.sourceCode;
  }
  return typeof context.getSourceCode === 'function' ? context.getSourceCode() : undefined;
}

/**
 * The ancestors of the node being visited, outermost first, across ESLint
 * majors.
 *
 * ESLint 9 moved the call from the context onto `SourceCode` and made it take
 * the node. The `SourceCode` form is tried first because ESLint 8.40, the
 * oldest release this plugin supports, has both and warns on every use of the
 * older one; a lint rule that prints a deprecation notice on each run is a rule
 * people turn off.
 */
export function getAncestors(context: RuleContext, node: AstNode): readonly AstNode[] {
  const sourceCode = getSourceCode(context);
  if (sourceCode !== undefined && typeof sourceCode.getAncestors === 'function') {
    return sourceCode.getAncestors(node);
  }

  if (typeof context.getAncestors === 'function') {
    return context.getAncestors();
  }

  return [];
}

/**
 * The children of a node, according to the parser that produced it.
 *
 * The `visitorKeys` map is the parser's own answer, so a TypeScript-only or
 * JSX-only field is followed without this package listing it.
 *
 * The fallback enumerates the node's own fields, and it runs both when the
 * parser supplies no keys at all and when it supplies keys that say nothing
 * about *this* node type. The second case is the one that matters: a custom
 * parser or a syntax plugin can produce a node the map does not describe, and
 * pruning that subtree would silently stop the search inside it. Enumerating is
 * the safe direction to be wrong in. `parent` is excluded because following it
 * would walk back up the tree and never terminate.
 */
export function childNodes(
  node: AstNode,
  visitorKeys: Readonly<Record<string, readonly string[]>> | undefined
): readonly AstNode[] {
  const keys = visitorKeys?.[node.type];
  const source = keys ?? Object.keys(node as unknown as Record<string, unknown>);
  const children: AstNode[] = [];

  for (const key of source) {
    if (keys === undefined && NON_CHILD_KEYS.has(key)) {
      continue;
    }

    const value = field(node, key);
    if (isNode(value)) {
      children.push(value);
      continue;
    }

    if (Array.isArray(value)) {
      for (const entry of value) {
        if (isNode(entry)) {
          children.push(entry);
        }
      }
    }
  }

  return children;
}

/**
 * Every call to one of `methods` inside `root`, `root` itself included, in
 * source order.
 *
 * The search descends through everything, including function bodies. That is
 * deliberate: `console.log(ids.map((id) => id.reveal()))` leaks exactly as much
 * as `console.log(id.reveal())` does, and a callback is the ordinary way to
 * write it. The cost is that logging a function that is never called, as in
 * `console.log(() => secret.reveal())`, is reported too. Reporting an unused
 * closure is a nuisance; missing a `map` over a list of secrets is a leak.
 *
 * A match does not end the descent into that node: `a.reveal().concat(b.reveal())`
 * reports both. Each node is visited once, so the walk is linear in the size of
 * the subtree.
 */
export function findMethodCalls(
  root: AstNode,
  methods: ReadonlySet<string>,
  visitorKeys: Readonly<Record<string, readonly string[]>> | undefined
): readonly AstNode[] {
  const found: AstNode[] = [];
  const pending: AstNode[] = [root];
  const seen = new Set<AstNode>();

  while (pending.length > 0) {
    const node = pending.pop();
    if (node === undefined || seen.has(node)) {
      continue;
    }
    seen.add(node);

    if (node.type === 'CallExpression' && isMethodCallNamed(node, methods)) {
      found.push(node);
    }

    const children = childNodes(node, visitorKeys);
    for (let index = children.length - 1; index >= 0; index -= 1) {
      pending.push(children[index] as AstNode);
    }
  }

  return found;
}
