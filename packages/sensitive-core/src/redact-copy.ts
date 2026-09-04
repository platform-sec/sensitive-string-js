import { SensitiveString } from './sensitive-string.js';
import { UNREADABLE, probeEntries, probePrototype, probeProperty, probeString } from './probe.js';
import { carriesSerializedMarker, redactSerialized } from './serialized.js';
import { assignOwn } from './own-property.js';

/**
 * Copy a structure with every `SensitiveString` and every serialized sensitive
 * value replaced by its redaction, leaving everything else usable.
 *
 * This is the walk for a response body or any other value that a serializer
 * other than `JSON.stringify` is about to see. `toJSON()` already redacts on
 * the JSON path; what it cannot cover is a serializer that copies public
 * properties (NestJS's `ClassSerializerInterceptor`, for one, which copies
 * `klass` and `label` and drops the marker), and a `serialize()` result placed
 * in a body, whose raw `value` `JSON.stringify` emits faithfully. Both are
 * closed here: an instance becomes the class's redaction, and any object
 * carrying the `__sensitive: true` marker becomes the redaction of the class it
 * names, or `'[REDACTED]'` when that class is not registered.
 *
 * `redactInStructure` is the sibling for log lines. It flattens class
 * instances into plain objects, replaces a repeat visit with `'[Circular]'`,
 * and stringifies exotic objects, which is right for a log record and wrong
 * for a body that still has to serialize as the class it was. This walk instead:
 *
 * - never mutates its input, since an entity may be shared with an ORM identity
 *   map or a cache;
 * - keeps each object's prototype, so an entity `toJSON()` and a serializer's
 *   `instanceof` checks still see the class;
 * - memoizes copies, so an object referenced twice stays one shared reference
 *   and a genuine cycle produces a cyclic copy that fails at `JSON.stringify`
 *   exactly as the original would;
 * - passes through by reference what a property copy would break or that no
 *   serializer can walk: `Date`, `WeakMap`, `WeakSet`, `RegExp`, `URL`,
 *   `Error`, `Promise`, `ArrayBuffer` and its views (`Buffer` among them),
 *   boxed primitives, and anything with a `pipe()` method;
 * - copies a `Map` or a `Set` entry by entry, keys included, keeping its
 *   prototype and memoizing it like an object, because either can hold a
 *   `serialize()` result and `v8.serialize`, `structuredClone`, a worker's
 *   `postMessage` and `util.inspect` all walk entries. `JSON.stringify` does
 *   not, which is why they used to pass through, and was the wrong question
 *   for a walk whose purpose is every other serializer.
 *
 * Only own enumerable string-keyed properties are visited, which is what
 * `JSON.stringify` visits. A value reachable only through a prototype getter,
 * a symbol key, or a non-enumerable property is not copied; on the JSON path it
 * is still redacted by `toJSON()`. A key named `__proto__` is copied as the
 * own data property it was, so an entity keeps the prototype it had rather
 * than one the payload supplied: see `assignOwn`.
 *
 * @param value - The value to copy
 * @returns A copy with every sensitive value redacted, or the value itself when
 *          it is a primitive or a pass-through object
 *
 * @example
 * ```ts
 * const body = {
 *   user: userEntity, // class instance holding SensitiveString fields
 *   token: secret.serialize(),
 * };
 *
 * redactCopy(body);
 * // { user: UserEntity { ..., apiKey: '[REDACTED:credential]' }, token: '[REDACTED:credential]' }
 * ```
 */
export function redactCopy(value: unknown): unknown {
  return copyRedacted(value, new WeakMap());
}

function copyRedacted(value: unknown, copies: WeakMap<object, unknown>): unknown {
  if (value === null || typeof value !== 'object') {
    return value;
  }

  // Read once, used twice: this answers both "will every `instanceof` below
  // throw" and, further down, "what prototype does the copy get". An object
  // that refuses to name its prototype has to be caught before the first
  // `instanceof`, which walks the chain and would throw.
  const prototype = probePrototype(value);

  if (prototype === undefined) {
    return UNREADABLE;
  }

  // An instance redacts itself. Guarded, because a Proxy around one answers
  // `instanceof` through the prototype it forwards and then throws from
  // `toString()`: the brand check refuses the proxy as a receiver. The marker
  // loses nothing, since the redaction is the whole of what the copy keeps.
  if (value instanceof SensitiveString) {
    return probeString(value) ?? UNREADABLE;
  }

  if (carriesSerializedMarker(value)) {
    return redactSerialized(value);
  }

  if (passesThrough(value)) {
    return value;
  }

  const existing = copies.get(value);

  if (existing !== undefined) {
    return existing;
  }

  // Iteration is the array's own code once a Proxy stands in front of it,
  // which may refuse `length`, an index, or the iterator. The marker stands in
  // for a partial copy, memoized so a second reference gets the same answer.
  if (Array.isArray(value)) {
    const copy: unknown[] = [];

    copies.set(value, copy);

    try {
      for (const item of value) {
        copy.push(copyRedacted(item, copies));
      }
    } catch {
      copies.set(value, UNREADABLE);
      return UNREADABLE;
    }

    return copy;
  }

  // Memoized before the entries are walked, like an object, so a collection
  // referenced twice stays one reference and a cycle through one stays a
  // cycle. Iteration is the collection's own code: a Proxy around a Map throws
  // from `entries()`, and a subclass may throw from its iterator. A partial
  // copy would claim to be the whole, so the marker stands in, memoized too so
  // a second reference gets the same answer.
  if (value instanceof Map) {
    const copy = new Map<unknown, unknown>();

    copies.set(value, copy);

    try {
      for (const [key, entry] of value) {
        copy.set(copyRedacted(key, copies), copyRedacted(entry, copies));
      }
    } catch {
      copies.set(value, UNREADABLE);
      return UNREADABLE;
    }

    return finishCollection(value, copy, prototype, copies);
  }

  if (value instanceof Set) {
    const copy = new Set<unknown>();

    copies.set(value, copy);

    try {
      for (const entry of value) {
        copy.add(copyRedacted(entry, copies));
      }
    } catch {
      copies.set(value, UNREADABLE);
      return UNREADABLE;
    }

    return finishCollection(value, copy, prototype, copies);
  }

  // An object that will not be enumerated cannot be copied, and an empty copy
  // of the right class would be worse than saying so: a serializer downstream
  // would emit it as a complete object with no fields. The marker is what
  // `redactInStructure` substitutes in the same situation.
  const entries = probeEntries(value);

  if (entries === undefined) {
    return UNREADABLE;
  }

  // Plain objects, null-prototype objects, and class instances alike, the
  // prototype carried over so a serializer downstream still sees the class.
  const copy: Record<string, unknown> = Object.create(prototype) as Record<string, unknown>;

  copies.set(value, copy);

  for (const [key, child] of entries) {
    assignOwn(copy, key, copyRedacted(child, copies));
  }

  return copy;
}

/**
 * Give a copied collection the prototype and the own properties the original
 * had.
 *
 * A subclass instance answers `instanceof` for its class, and a serializer
 * downstream may check that. Its own enumerable properties are the one part of
 * a Map or a Set that `JSON.stringify` does emit, so they are copied and
 * redacted as an object's are.
 */
function finishCollection(
  original: object,
  copy: object,
  prototype: object | null,
  copies: WeakMap<object, unknown>
): unknown {
  if (prototype !== Object.getPrototypeOf(copy)) {
    Object.setPrototypeOf(copy, prototype);
  }

  const entries = probeEntries(original);

  if (entries === undefined) {
    copies.set(original, UNREADABLE);
    return UNREADABLE;
  }

  for (const [key, child] of entries) {
    assignOwn(copy, key, copyRedacted(child, copies));
  }

  return copy;
}

/**
 * Objects whose state lives in internal slots, or that no serializer can walk.
 *
 * Copying the prototype and the own properties of any of these would produce
 * something that answers `instanceof` and then throws on use, or lose the
 * message of an Error. A `WeakMap` or `WeakSet` cannot be enumerated by anyone,
 * this walk included, and `structuredClone` refuses both, so nothing inside one
 * reaches a serializer. `Map` and `Set` are not here: either can hold anything,
 * and a serializer that walks entries finds it, so they are copied above.
 */
function passesThrough(value: object): boolean {
  return (
    value instanceof Date ||
    value instanceof WeakMap ||
    value instanceof WeakSet ||
    value instanceof RegExp ||
    value instanceof URL ||
    value instanceof Error ||
    value instanceof Promise ||
    value instanceof ArrayBuffer ||
    ArrayBuffer.isView(value) ||
    value instanceof String ||
    value instanceof Number ||
    value instanceof Boolean ||
    typeof probeProperty(value, 'pipe') === 'function'
  );
}
