import { SensitiveString } from './sensitive-string.js';
import { getPolicy, hasPolicy } from './policy.js';
import type { SensitivityClass } from './types.js';

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
 * - passes through by reference what a property copy would break or cannot
 *   contain an instance: `Date`, `Map`, `Set`, `WeakMap`, `WeakSet`, `RegExp`,
 *   `URL`, `Error`, `Promise`, `ArrayBuffer` and its views (`Buffer` among
 *   them), boxed primitives, and anything with a `pipe()` method.
 *
 * Only own enumerable string-keyed properties are visited, which is what
 * `JSON.stringify` visits. A value reachable only through a prototype getter,
 * a symbol key, or a non-enumerable property is not copied; on the JSON path it
 * is still redacted by `toJSON()`.
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

  if (value instanceof SensitiveString) {
    return value.toString();
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

  if (Array.isArray(value)) {
    const copy: unknown[] = [];

    copies.set(value, copy);

    for (const item of value) {
      copy.push(copyRedacted(item, copies));
    }

    return copy;
  }

  // Plain objects, null-prototype objects, and class instances alike, the
  // prototype carried over so a serializer downstream still sees the class.
  const copy: Record<string, unknown> = Object.create(
    Object.getPrototypeOf(value) as object | null
  ) as Record<string, unknown>;

  copies.set(value, copy);

  for (const [key, child] of Object.entries(value)) {
    copy[key] = copyRedacted(child, copies);
  }

  return copy;
}

/**
 * The shape `serialize()` produces, detected by its marker alone so that a
 * malformed or truncated copy of one is still replaced rather than emitted.
 */
function carriesSerializedMarker(value: object): boolean {
  return (value as { __sensitive?: unknown }).__sensitive === true;
}

/**
 * The redaction the named class would produce for the raw value, so a custom
 * policy's marker is honoured here as it is by `toString()`. A class that is
 * not registered gets a generic marker: echoing the unknown name would put
 * input the library did not produce into the output.
 */
function redactSerialized(value: object): string {
  const { klass, value: raw } = value as { klass?: unknown; value?: unknown };

  if (typeof klass === 'string' && hasPolicy(klass as SensitivityClass)) {
    return getPolicy(klass as SensitivityClass).redact(typeof raw === 'string' ? raw : '');
  }

  return '[REDACTED]';
}

/**
 * Objects whose state lives in internal slots or that cannot hold an instance.
 *
 * Copying the prototype and the own properties of any of these would produce
 * something that answers `instanceof` and then throws on use, or lose the
 * message of an Error. None of them can reach a `SensitiveString` through
 * `JSON.stringify`, so passing them through neither leaks nor loses anything.
 */
function passesThrough(value: object): boolean {
  return (
    value instanceof Date ||
    value instanceof Map ||
    value instanceof Set ||
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
    typeof (value as { pipe?: unknown }).pipe === 'function'
  );
}
