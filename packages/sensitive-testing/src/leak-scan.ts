import { SensitiveString } from '@platform-sec/sensitive-string-core';
import type { SensitivityClass } from '@platform-sec/sensitive-string-core';

/**
 * `instanceof SensitiveString` narrows to `SensitiveString<any>`, because the
 * class is generic in its sensitivity class and the check says nothing about
 * which one. The predicate names the union instead, so nothing downstream of
 * the narrowing is typed `any`.
 */
export function isSensitiveString(value: unknown): value is SensitiveString<SensitivityClass> {
  return value instanceof SensitiveString;
}

/**
 * Most values the walk will look at before it gives up.
 *
 * This is a guard against a hostile target, not a limit a real one reaches. A
 * `Proxy` can fabricate a fresh object for every key forever, and a leak check
 * that hangs the suite is worse than one that stops. Nothing built by ordinary
 * code comes close to this count.
 *
 * There is deliberately no depth limit. A depth limit stops the walk in the
 * middle of a structure it could otherwise finish, and a leak below the cut is
 * then reported as no leak at all, which is the one answer a leak check must
 * never give by accident. The walk uses an explicit stack instead of recursion,
 * so depth costs heap rather than call frames and no limit is needed.
 */
const MAX_NODES = 200_000;

/** Characters of surrounding text kept on each side of a reported match. */
const CONTEXT_RADIUS = 60;

/** What a reported match stands in for, so a failure never reprints a secret. */
const LEAK_PLACEHOLDER = '[LEAKED VALUE]';

const utf8 = new TextDecoder('utf-8', { fatal: false });

/**
 * One piece of text found while walking a value, and where it came from.
 */
export interface Fragment {
  /** Where the text was found, such as `.body.headers['x-api-key']`. */
  readonly path: string;
  /** The text itself. */
  readonly text: string;
  /**
   * True when the text is the redacted rendering of a `SensitiveString` that
   * was still wrapped where it was found, rather than text the target held
   * directly.
   *
   * A leak search still checks these. A wrapper is the correct state for a
   * sensitive value to be in, and the raw value is unreachable through it, so
   * under any policy `registerPolicy` accepts the rendering cannot contain the
   * value and the wrapper is never reported. A rendering that does contain the
   * whole value comes from a policy registered with `skipRedactValidation` or
   * from a subclass that overrode `toString`, and that is a leak, not a false
   * positive: passing it over is the one failure a leak assertion must not have.
   */
  readonly wrapped: boolean;
}

/** Where a raw value was found, and enough context to locate it. */
export interface LeakLocation {
  /** Path within the target, such as `.headers['authorization']`. */
  readonly path: string;
  /**
   * The surrounding text, with every occurrence of the raw value replaced by
   * `[LEAKED VALUE]`.
   *
   * The value is withheld on purpose: an assertion message ends up in CI logs,
   * and a leak check that prints the secret to prove the secret leaked has only
   * moved the leak.
   */
  readonly context: string;
}

/**
 * Walk a value and collect every piece of text it holds.
 *
 * This deliberately does not use `JSON.stringify`. `JSON.stringify` calls
 * `toJSON`, and `toJSON` is exactly the method an object uses to decide what it
 * shows: a response class whose `toJSON` omits a field hides a raw value that
 * is still sitting on the object, and every `SensitiveString` renders as its
 * redacted form whether or not the object also holds a leaked plain copy. This
 * walk reads own properties instead, so what it reports is what the object
 * actually holds.
 *
 * Covered: strings, other primitives, arrays and the properties attached to
 * them, `Map`, `Set`, typed arrays and `Buffer` (decoded as UTF-8), `RegExp`
 * sources, own property keys, and own properties whether enumerable or not.
 * That last one is how an `Error`'s `message` and `stack` are reached, and the
 * array properties are how a `String.prototype.match` result's `input`, which
 * holds the whole subject string, is reached. Accessors are invoked, so a value
 * behind a getter is found; a getter that throws is skipped.
 *
 * Not covered: closure variables, `WeakMap` and `WeakSet` contents, unsettled
 * promises, and function bodies. A value reachable only from one of those is
 * beyond what a synchronous walk can see.
 *
 * The traversal is depth first and pre-order, so the first match a search finds
 * is the one nearest the front of the structure as it reads.
 */
export function collectFragments(root: unknown): Fragment[] {
  const fragments: Fragment[] = [];
  const seen = new WeakSet<object>();
  const stack: WalkItem[] = [{ kind: 'value', value: root, path: '' }];
  let budget = MAX_NODES;

  while (stack.length > 0 && budget > 0) {
    budget -= 1;

    const item = stack.pop();
    if (item === undefined) {
      break;
    }

    if (item.kind === 'text') {
      push(fragments, item.path, item.text, item.wrapped);
      continue;
    }

    expand(item.value, item.path, fragments, seen, stack);
  }

  return fragments;
}

/**
 * Find the first place a raw value appears in a target.
 *
 * An empty raw value is never reported: it is a substring of every string, and
 * it carries no information to leak.
 */
export function findRawValue(target: unknown, raw: string): LeakLocation | undefined {
  return findRawValueIn(collectFragments(target), raw);
}

/**
 * Find a raw value in fragments that have already been collected, for a caller
 * that also needs the joined text and should not walk the target twice.
 */
export function findRawValueIn(
  fragments: readonly Fragment[],
  raw: string
): LeakLocation | undefined {
  if (raw.length === 0) {
    return undefined;
  }

  for (const fragment of fragments) {
    const index = fragment.text.indexOf(raw);
    if (index !== -1) {
      return { path: fragment.path, context: describeContext(fragment.text, raw, index) };
    }
  }

  return undefined;
}

/**
 * Render the collected text of a value as one string, for a check that needs to
 * search the whole target rather than a single leaf.
 *
 * Fragments are joined with a newline, which no fragment contains a boundary
 * across, so a match in the result is a match within one fragment.
 */
export function joinFragments(fragments: readonly Fragment[]): string {
  return fragments.map((fragment) => fragment.text).join('\n');
}

/**
 * A value still to be walked, or text still to be recorded.
 *
 * Text is queued rather than recorded immediately so that a property name and
 * the subtree under that property keep their relative order. The path a search
 * reports depends on that order.
 */
type WalkItem =
  | { readonly kind: 'value'; readonly value: unknown; readonly path: string }
  | {
      readonly kind: 'text';
      readonly path: string;
      readonly text: string;
      readonly wrapped: boolean;
    };

/**
 * The text around a match, with the matched value replaced.
 */
function describeContext(text: string, raw: string, index: number): string {
  const start = Math.max(0, index - CONTEXT_RADIUS);
  const end = Math.min(text.length, index + raw.length + CONTEXT_RADIUS);
  // split/join replaces every occurrence without building a RegExp from the
  // raw value, which would need escaping and would put the value in a pattern.
  const window = text.slice(start, end).split(raw).join(LEAK_PLACEHOLDER);

  return `${start > 0 ? '...' : ''}${window}${end < text.length ? '...' : ''}`;
}

function push(fragments: Fragment[], path: string, text: string, wrapped = false): void {
  if (text.length > 0) {
    fragments.push({ path, text, wrapped });
  }
}

function valueItem(value: unknown, path: string): WalkItem {
  return { kind: 'value', value, path };
}

/**
 * Queue children so the stack pops them in source order.
 *
 * Reversing here is what keeps the traversal depth first and pre-order, which
 * is the order the reported path assumes.
 */
function queue(stack: WalkItem[], children: readonly WalkItem[]): void {
  for (let index = children.length - 1; index >= 0; index -= 1) {
    const child = children[index];
    if (child !== undefined) {
      stack.push(child);
    }
  }
}

/** Record what a value contributes directly, and queue what it contains. */
function expand(
  value: unknown,
  path: string,
  fragments: Fragment[],
  seen: WeakSet<object>,
  stack: WalkItem[]
): void {
  if (value === null || value === undefined) {
    return;
  }

  switch (typeof value) {
    case 'string':
      push(fragments, path, value);
      return;
    case 'number':
    case 'boolean':
    case 'bigint':
      push(fragments, path, String(value));
      return;
    case 'symbol':
      push(fragments, path, value.description ?? '');
      return;
    case 'function':
      // The name only. A function body can hold a literal secret, but reading
      // every function source in a response object costs more than it finds.
      push(fragments, `${path}.name`, value.name);
      return;
    default:
      break;
  }

  expandObject(value, path, fragments, seen, stack);
}

function expandObject(
  obj: object,
  path: string,
  fragments: Fragment[],
  seen: WeakSet<object>,
  stack: WalkItem[]
): void {
  if (isSensitiveString(obj)) {
    // The raw value is unreachable from here, which is the point: a value that
    // is still wrapped has nothing for a leak search to find. What is recorded
    // is the rendering the class policy produces, so a redaction check can look
    // for it and so a policy that renders the value itself is still caught.
    push(fragments, path, safeRedaction(obj), true);
    return;
  }

  if (seen.has(obj)) {
    return;
  }
  seen.add(obj);

  const children: WalkItem[] = [];

  if (Array.isArray(obj)) {
    obj.forEach((item, index) => {
      children.push(valueItem(item, `${path}[${index}]`));
    });

    // Arrays carry properties beyond their elements often enough to matter: a
    // `String.prototype.match` result is an array whose `input` holds the whole
    // subject string, which is the value the match came from.
    collectOwnProperties(obj, path, children, isElementKey);
    queue(stack, children);
    return;
  }

  if (obj instanceof Map) {
    let index = 0;
    for (const [key, value] of obj) {
      children.push(valueItem(key, `${path}<map key ${index}>`));
      children.push(valueItem(value, `${path}<map value ${index}>`));
      index += 1;
    }
    queue(stack, children);
    return;
  }

  if (obj instanceof Set) {
    let index = 0;
    for (const value of obj) {
      children.push(valueItem(value, `${path}<set ${index}>`));
      index += 1;
    }
    queue(stack, children);
    return;
  }

  if (obj instanceof RegExp) {
    push(fragments, `${path}.source`, obj.source);
    return;
  }

  if (ArrayBuffer.isView(obj) || obj instanceof ArrayBuffer) {
    push(fragments, path, decodeBytes(obj));
    return;
  }

  collectOwnProperties(obj, path, children);
  queue(stack, children);
}

/**
 * Queue own properties, enumerable or not.
 *
 * Non-enumerable properties are included because hiding a value behind
 * `enumerable: false` is precisely how a copy escapes `JSON.stringify`, and
 * because an `Error`'s `message` and `stack` are non-enumerable own properties.
 */
function collectOwnProperties(
  obj: object,
  path: string,
  out: WalkItem[],
  skip?: (key: string | symbol) => boolean
): void {
  for (const key of Reflect.ownKeys(obj)) {
    if (skip?.(key)) {
      continue;
    }

    const keyPath = `${path}${accessorFor(key)}`;

    if (typeof key === 'string') {
      // A raw value used as an object key, such as a cache keyed by token.
      out.push({ kind: 'text', path: `${keyPath} (key)`, text: key, wrapped: false });
    }

    const descriptor = Object.getOwnPropertyDescriptor(obj, key);
    if (descriptor === undefined) {
      continue;
    }

    if ('value' in descriptor) {
      out.push(valueItem(descriptor.value, keyPath));
      continue;
    }

    // eslint-disable-next-line @typescript-eslint/unbound-method -- read to test for presence, then invoked as getter.call(obj) below
    const getter = descriptor.get;
    if (getter === undefined) {
      continue;
    }

    // A value reachable only through a getter is still a value the object
    // holds. A getter that throws tells us nothing, so it is skipped.
    try {
      out.push(valueItem(getter.call(obj), keyPath));
    } catch {
      // Intentionally ignored.
    }
  }
}

/** Keys an array walk has already covered as elements, plus its length. */
function isElementKey(key: string | symbol): boolean {
  return typeof key === 'string' && (key === 'length' || ARRAY_INDEX.test(key));
}

const ARRAY_INDEX = /^(?:0|[1-9]\d*)$/;

const IDENTIFIER = /^[A-Za-z_$][A-Za-z0-9_$]*$/;

function accessorFor(key: string | symbol): string {
  if (typeof key === 'symbol') {
    return `[Symbol(${key.description ?? ''})]`;
  }

  return IDENTIFIER.test(key) ? `.${key}` : `[${JSON.stringify(key)}]`;
}

/**
 * The redacted rendering of a wrapped value, or a marker when the class policy
 * refuses to produce one. A policy that throws must not turn a leak check into
 * an error about the policy.
 */
function safeRedaction(value: SensitiveString<SensitivityClass>): string {
  try {
    return value.toString();
  } catch {
    return `[SensitiveString<${value.klass}> redaction threw]`;
  }
}

function decodeBytes(source: ArrayBufferView | ArrayBuffer): string {
  try {
    const bytes =
      source instanceof ArrayBuffer
        ? new Uint8Array(source)
        : new Uint8Array(source.buffer, source.byteOffset, source.byteLength);

    return utf8.decode(bytes);
  } catch {
    return '';
  }
}
