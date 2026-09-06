/**
 * Type-aware access, for the two rules that cannot work without it.
 *
 * The other five rules read the shape of a call. These two have to answer a
 * different question: does this *value* carry a sensitive one anywhere inside
 * it? No amount of syntax answers that. Guessing from a variable's name is the
 * substitute usually proposed, and it is worse than nothing here: it reports
 * `JSON.stringify(token)` and stays quiet on `JSON.stringify(user)`, which is
 * the call that actually holds the secret.
 *
 * ## What is declared here, and why
 *
 * The TypeScript API is reached structurally, the same way `./types.js`
 * reaches ESLint's. This package has no dependencies and adding `typescript`
 * as one would put it in the install of every consumer who lints plain
 * JavaScript, for a pair of rules they cannot run. Nothing here is imported at
 * runtime either: the checker arrives through `parserServices`, already
 * constructed by whoever configured type-aware linting.
 *
 * The declarations are deliberately small. Every method below is public API
 * that has been stable since TypeScript 4.7, and the set is bounded by the
 * traversal in {@link findSensitiveType}, which mirrors what `JSON.stringify`
 * and `util.inspect` themselves walk: union members, array and tuple elements,
 * base classes, object properties, index signatures. Nothing else can carry a
 * value into a log line or a request body.
 */
import { getSourceCode } from './ast.js';
import type { AstNode, RuleContext } from './types.js';

/** A `ts.Symbol`, as far as this module reads one. */
interface SymbolLike {
  readonly name: string;
}

/** A `ts.Node`. Opaque here: it is only ever handed back to the checker. */
interface TsNodeLike {
  readonly kind: number;
}

/**
 * A `ts.Type`, as far as this module reads one.
 *
 * `types` is the field a union and an intersection both carry, which is why
 * this module never needs `isUnion()` or the `TypeFlags` enum behind it, and
 * so never needs `typescript` itself at runtime.
 */
interface TypeLike {
  readonly symbol?: SymbolLike | undefined;
  readonly aliasSymbol?: SymbolLike | undefined;
  /** The constituents of a union or an intersection. Absent on anything else. */
  readonly types?: readonly TypeLike[] | undefined;
  getProperties(): readonly SymbolLike[];
  /** The classes and interfaces extended. `undefined` for anything else. */
  getBaseTypes?(): readonly TypeLike[] | undefined;
}

/** One index signature of a type, as `{ [k: string]: T }` declares. */
interface IndexInfoLike {
  readonly type: TypeLike;
}

/** A `ts.TypeChecker`, as far as this module calls one. */
interface TypeCheckerLike {
  getTypeAtLocation(node: TsNodeLike): TypeLike;
  getTypeOfSymbolAtLocation(symbol: SymbolLike, node: TsNodeLike): TypeLike;
  isArrayType(type: TypeLike): boolean;
  isTupleType(type: TypeLike): boolean;
  /** Public since TypeScript 4.2. Guarded anyway, being duck-typed. */
  getTypeArguments?(type: TypeLike): readonly TypeLike[];
  /** Public since TypeScript 4.7. Guarded anyway, being duck-typed. */
  getIndexInfosOfType?(type: TypeLike): readonly IndexInfoLike[];
}

/** A `ts.Program`, as far as this module uses one. */
interface ProgramLike {
  getTypeChecker(): TypeCheckerLike;
}

/** What `@typescript-eslint/parser` hands back when type-aware mode is on. */
interface ParserServicesLike {
  readonly program?: ProgramLike | null | undefined;
  readonly esTreeNodeToTSNodeMap?: { get(node: AstNode): TsNodeLike | undefined } | undefined;
}

/** The checker, plus the one lookup a rule needs to reach it from an ESLint node. */
export interface TypeServices {
  readonly checker: TypeCheckerLike;
  /**
   * The TypeScript node an ESLint node came from.
   *
   * It is both what a type is read from and the location the read happens at,
   * which is why the walk carries it rather than resolving a type once: every
   * `getTypeOfSymbolAtLocation` below needs somewhere to stand.
   */
  tsNodeOf(node: AstNode): TsNodeLike | undefined;
}

/** Type names whose presence in a structure is what the rules report. */
export interface SensitiveTypeNames {
  /** A live wrapper, which redacts itself in every path the library controls. */
  readonly sensitive: ReadonlySet<string>;
  /** A `serialize()` result: a plain object holding the raw value. */
  readonly serialized: ReadonlySet<string>;
}

/** Where a sensitive type was found, and what kind it was. */
export interface SensitiveTypeMatch {
  /** The type name that matched, for the finding's message. */
  readonly name: string;
  /** Whether it was a wire-format type rather than a live wrapper. */
  readonly serialized: boolean;
  /**
   * Whether it was reached through a property or an index signature, rather
   * than being the value itself or an element of a plain list of them.
   *
   * `console.log(token)` and `console.log(tokens)` are the documented way to
   * log a sensitive value: the class redacts itself, and a list delegates to
   * each element. `console.log(user)` is a different thing, because whatever
   * redacts now is whichever serializer the transport happens to install.
   * `prefer-safe-log` keys on this; `no-stringify-sensitive` does not, because
   * `JSON.stringify(token)` writes the placeholder either way.
   */
  readonly throughProperty: boolean;
}

/** The library's own names, which every project gets without configuring any. */
export const DEFAULT_SENSITIVE_TYPES: readonly string[] = ['SensitiveString'];

/**
 * The wire format's name.
 *
 * Matched exactly, never by prefix: `SerializedSensitiveString` is the shape
 * `serialize()` produces and `deserialize()` consumes, so a rule that reported
 * every name containing "Sensitive" would report the recommended transmission
 * path at the point where it is correct.
 */
export const DEFAULT_SERIALIZED_TYPES: readonly string[] = ['SerializedSensitiveString'];

/**
 * How many distinct types one search may examine.
 *
 * A safety valve, not a design limit. The visited set already makes the walk
 * terminate on a recursive type; this bounds the pathological case where a
 * single argument is typed as a framework object reaching thousands of others,
 * so that one unlucky call cannot make a lint run look hung. A payload type
 * that reaches this figure without a sensitive value in it does not exist in
 * practice, and the rule's documentation says what happens if one does.
 */
const TYPE_BUDGET = 1000;

/** Whether a value is an object, for narrowing what a parser handed back. */
function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
  return typeof value === 'object' && value !== null;
}

/**
 * The type checker for the file being linted, or `undefined` when the consumer
 * has not configured type-aware linting.
 *
 * Both spellings are tried because they belong to different ESLint majors: 9
 * hangs `parserServices` off `SourceCode`, 8 hangs it off the rule context.
 * `program` is `null` rather than absent under `@typescript-eslint/parser`
 * without a `project`, which is the ordinary "TypeScript parser, no types"
 * configuration and has to read as "no type information" rather than as a
 * malformed services object.
 */
export function getTypeServices(context: RuleContext): TypeServices | undefined {
  const raw = getSourceCode(context)?.parserServices ?? context.parserServices;
  if (!isRecord(raw)) {
    return undefined;
  }

  const services = raw as ParserServicesLike;
  const program = services.program;
  const nodeMap = services.esTreeNodeToTSNodeMap;

  if (
    !isRecord(program) ||
    typeof program.getTypeChecker !== 'function' ||
    !isRecord(nodeMap) ||
    typeof nodeMap.get !== 'function'
  ) {
    return undefined;
  }

  return {
    checker: program.getTypeChecker(),
    tsNodeOf: (node: AstNode): TsNodeLike | undefined => nodeMap.get(node),
  };
}

/** The names a type answers to: its own, and the alias it was written as. */
function namesOf(type: TypeLike): readonly string[] {
  const names: string[] = [];

  // Both, not the first of the two. `type Token = SensitiveString<'credential'>`
  // has `Token` as its alias and `SensitiveString` as its own symbol, and a
  // project may well have configured either one.
  const alias = type.aliasSymbol?.name;
  if (typeof alias === 'string') {
    names.push(alias);
  }
  const own = type.symbol?.name;
  if (typeof own === 'string') {
    names.push(own);
  }

  return names;
}

/** The match a type's own names produce, or `undefined` if none do. */
function matchNames(
  type: TypeLike,
  names: SensitiveTypeNames,
  throughProperty: boolean
): SensitiveTypeMatch | undefined {
  for (const name of namesOf(type)) {
    if (names.serialized.has(name)) {
      return { name, serialized: true, throughProperty };
    }
  }

  for (const name of namesOf(type)) {
    if (names.sensitive.has(name)) {
      return { name, serialized: false, throughProperty };
    }
  }

  return undefined;
}

/** One type still to examine, and how it was reached. */
interface Pending {
  readonly type: TypeLike;
  readonly throughProperty: boolean;
}

/**
 * Everything a type can carry a value through, mirroring what a serializer
 * walks.
 *
 * Union and intersection members, array and tuple elements, and base classes
 * preserve how the type was reached: a `SensitiveString[]` is still the value
 * itself, logged as a list. Properties and index signatures do not, because
 * something else is holding the value now.
 *
 * A union and an array each answer for the whole of themselves, so neither
 * goes on to its properties. For an array that is not a nicety: `Array<T>`
 * declares a numeric index signature, so following its members would reach
 * every element back through a property edge and turn `console.log(tokens)`
 * into a finding. Its other properties are `Array.prototype`, which is not
 * payload either.
 */
function childrenOf(
  type: TypeLike,
  location: TsNodeLike,
  checker: TypeCheckerLike,
  throughProperty: boolean
): readonly Pending[] {
  const children: Pending[] = [];

  const push = (child: TypeLike | undefined, through: boolean): void => {
    if (isRecord(child)) {
      children.push({ type: child, throughProperty: through });
    }
  };

  const members = type.types ?? [];
  if (members.length > 0) {
    for (const member of members) {
      push(member, throughProperty);
    }
    return children;
  }

  if (checker.isArrayType(type) || checker.isTupleType(type)) {
    for (const element of checker.getTypeArguments?.(type) ?? []) {
      push(element, throughProperty);
    }
    return children;
  }

  // A subclass is reached by name through here and nowhere else: inherited
  // members arrive through `getProperties` already, but the base type's own
  // name does not, and a `class ApiKey extends SensitiveString` is still a
  // sensitive value.
  for (const base of type.getBaseTypes?.() ?? []) {
    push(base, throughProperty);
  }

  for (const property of type.getProperties()) {
    push(checker.getTypeOfSymbolAtLocation(property, location), true);
  }

  for (const info of checker.getIndexInfosOfType?.(type) ?? []) {
    push(info.type, true);
  }

  return children;
}

/**
 * How many types one receiver check may examine.
 *
 * Far below {@link TYPE_BUDGET}, because this walk is a different shape: it
 * follows unions and base classes only, never properties, so the count is the
 * depth of an inheritance chain and the width of a union rather than the size
 * of a payload. A receiver that reaches this figure is not a wrapper.
 */
const RECEIVER_BUDGET = 64;

/**
 * Whether an expression *is* a sensitive wrapper, rather than carrying one.
 *
 * The question `findSensitiveType` answers is "does this structure hold a
 * value", which is what a serializer walks. This one asks whether the
 * expression in hand is the wrapper itself, which is what a method call needs:
 * `bcrypt.hash(...)` and `token.hash(...)` are the same syntax, and only the
 * receiver's type separates them.
 *
 * Properties are therefore not followed. A `{ token: SensitiveString }` holds
 * one and has no `hash` method of its own, so following its properties would
 * report `user.hash()` on a `user` that has an unrelated one. Unions,
 * intersections and base classes are followed: `SensitiveString | undefined`
 * is what an optional chain produces, and `class ApiKey extends
 * SensitiveString` is still a wrapper.
 */
export function isSensitiveWrapper(
  node: AstNode,
  services: TypeServices,
  names: ReadonlySet<string>
): boolean {
  const location = services.tsNodeOf(node);
  if (location === undefined) {
    return false;
  }

  const root = services.checker.getTypeAtLocation(location);
  if (!isRecord(root)) {
    return false;
  }

  const pending: TypeLike[] = [root];
  const seen = new Set<TypeLike>();
  let budget = RECEIVER_BUDGET;

  while (pending.length > 0 && budget > 0) {
    const type = pending.pop() as TypeLike;
    if (seen.has(type)) {
      continue;
    }
    seen.add(type);
    budget -= 1;

    if (namesOf(type).some((name) => names.has(name))) {
      return true;
    }

    for (const member of type.types ?? []) {
      if (isRecord(member)) {
        pending.push(member);
      }
    }

    for (const base of type.getBaseTypes?.() ?? []) {
      if (isRecord(base)) {
        pending.push(base);
      }
    }
  }

  return false;
}

/**
 * The sensitive type an expression's type carries, or `undefined`.
 *
 * The search stops as soon as it finds one reached through a property, which
 * is the finding both rules most want to report. A match on the value itself,
 * or on an element of a list of them, is kept but does not end the walk: a
 * `SensitiveString` in hand says nothing about whether the same expression
 * also holds one inside a record, and the two produce different findings.
 *
 * Visited types are tracked separately per arrival, because the same type
 * reached directly and reached through a property is two different answers,
 * and the first must not suppress the second.
 */
export function findSensitiveType(
  node: AstNode,
  services: TypeServices,
  names: SensitiveTypeNames
): SensitiveTypeMatch | undefined {
  const location = services.tsNodeOf(node);
  if (location === undefined) {
    return undefined;
  }

  const root = services.checker.getTypeAtLocation(location);
  if (!isRecord(root)) {
    return undefined;
  }

  const pending: Pending[] = [{ type: root, throughProperty: false }];
  const seenDirectly = new Set<TypeLike>();
  const seenThroughProperty = new Set<TypeLike>();
  let budget = TYPE_BUDGET;
  let direct: SensitiveTypeMatch | undefined;

  while (pending.length > 0 && budget > 0) {
    const entry = pending.pop() as Pending;
    const seen = entry.throughProperty ? seenThroughProperty : seenDirectly;
    if (seen.has(entry.type)) {
      continue;
    }
    seen.add(entry.type);
    budget -= 1;

    const match = matchNames(entry.type, names, entry.throughProperty);
    if (match !== undefined) {
      if (match.throughProperty) {
        return match;
      }
      // A wire-format object found in hand outranks a wrapper found in hand:
      // one is a leak, the other is the documented way to pass a value around.
      if (direct === undefined || (match.serialized && !direct.serialized)) {
        direct = match;
      }
      continue;
    }

    pending.push(...childrenOf(entry.type, location, services.checker, entry.throughProperty));
  }

  return direct;
}
