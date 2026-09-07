import { SensitiveString } from './sensitive-string.js';
import type { SensitivityClass } from './types.js';
import { carriesSerializedMarker, redactSerialized, serializedClass } from './serialized.js';
import { assignOwn } from './own-property.js';
import { runInsideRedaction } from './redaction-scope.js';
import {
  UNREADABLE,
  isUnreadable,
  probeBuiltin,
  probeCall,
  probeEntries,
  probeMethod,
  probeProperty,
  probePrototype,
  probeString,
  probeTag,
} from './probe.js';

/**
 * Identify ordinary objects: plain objects, null-prototype objects, and class
 * instances. Exotic objects such as typed arrays, promises, boxed primitives,
 * and anything with a custom Symbol.toStringTag report a different tag and are
 * handled by the string fallback instead.
 *
 * The tag is read through a guard, because reading it goes through a
 * `Symbol.toStringTag` getter the object controls. An object that refuses is
 * treated as ordinary, which sends it to be walked and redacted rather than to
 * `String()`, which would ask the same object another question.
 */
function isOrdinaryObject(obj: object): boolean {
  return probeTag(obj) === '[object Object]';
}

/**
 * Copy own enumerable properties into a new plain object, redacting as we go.
 * Used for plain objects and class instances alike. The result is always a
 * plain object: methods, prototype getters, and private fields are not carried
 * over, which keeps the output inert for logging.
 *
 * An object that cannot be enumerated at all becomes the {@link UNREADABLE}
 * marker rather than an empty object. Both are safe; only one is honest. An
 * empty object in a log line reads as "this had no properties", which is a
 * different and more misleading claim than "this could not be read".
 *
 * A key named `__proto__` stays a key in the copy rather than becoming its
 * prototype, which would both drop that subtree from the log line and hand
 * the copy inherited properties the input never had: see `assignOwn`.
 */
function redactOwnProperties(
  obj: object,
  seen: WeakSet<object>,
  omit?: string
): Record<string, unknown> | string {
  const entries = probeEntries(obj);

  if (entries === undefined) {
    return UNREADABLE;
  }

  const result: Record<string, unknown> = {};
  for (const [key, value] of entries) {
    if (key === omit) {
      continue;
    }
    assignOwn(result, key, redactWalk(value, seen));
  }
  return result;
}

/**
 * Recursively redact SensitiveString instances in a data structure.
 *
 * Handles:
 * - Primitive values (returned as-is)
 * - SensitiveString instances (redacted via toString())
 * - Serialized sensitive values, the `{ __sensitive: true, klass, value }` shape
 *   `serialize()` produces (replaced by the redaction of the class they name,
 *   or '[REDACTED]' for a class that is not registered)
 * - Arrays, Map, and Set (recursively processed)
 * - Date (preserved as-is)
 * - Error (name, message, and stack copied into a plain object)
 * - Plain objects and class instances (own enumerable properties recursively
 *   processed into a new plain object)
 * - Objects with a toJSON() method (their JSON form, recursively processed; a
 *   reveal() from inside the method is refused, and the object's own
 *   properties are walked instead)
 * - Other exotic objects such as typed arrays or promises (string form)
 * - Circular references (replaced with '[Circular]')
 *
 * @param obj - The value to process
 * @returns A new structure with all SensitiveString instances redacted
 *
 * @example
 * ```ts
 * const data = {
 *   user: 'alice',
 *   token: new SensitiveString('secret123', 'credential', 'token'),
 *   nested: {
 *     email: new SensitiveString('alice@example.com', 'sensitive', 'email')
 *   }
 * };
 *
 * const safe = redactInStructure(data);
 * // {
 * //   user: 'alice',
 * //   token: '[REDACTED:credential]',
 * //   nested: { email: '[REDACTED:sensitive]' }
 * // }
 * ```
 */
export function redactInStructure(obj: unknown): unknown {
  return redactWalk(obj, new WeakSet<object>());
}

/**
 * The walk itself, carrying the set that catches a cycle.
 *
 * Private so the accumulator stays out of the exported signature. It used to be
 * an optional second parameter documented as internal, which is not a control:
 * a caller sharing one `seen` across a graph reaches an object the walk has
 * already visited and is told '[Circular]' for the whole payload, and the same
 * mistake on `containsSensitive` answers `false` about a payload that does hold
 * a secret. Neither is a mistake a safety helper should let a caller make.
 */
function redactWalk(obj: unknown, seen: WeakSet<object>): unknown {
  // Handle primitives and null
  if (obj === null || typeof obj !== 'object') {
    return obj;
  }

  // Read once, used twice: this answers both "will every `instanceof` below
  // throw" and, forty lines down, "is this a plain object". An object that
  // refuses to name its prototype has to be caught before the first
  // `instanceof`, which walks the chain and would throw.
  const prototype = probePrototype(obj);

  if (prototype === undefined) {
    return UNREADABLE;
  }

  // A SensitiveString redacts itself. Guarded, because a Proxy around an
  // instance answers `instanceof` through the prototype it forwards and then
  // throws from `toString()`: the private field is on the target, and the
  // brand check refuses the proxy as a receiver. The marker loses nothing,
  // since the redaction is the whole of what the walk keeps.
  if (obj instanceof SensitiveString) {
    return probeString(obj) ?? UNREADABLE;
  }

  // A serialize() result carries the raw value by design, and it is a plain
  // object, so JSON.stringify would emit it. In a log line that is the one
  // leak toJSON() cannot catch; it takes the class's redaction here instead.
  if (carriesSerializedMarker(obj)) {
    return redactSerialized(obj);
  }

  // Circular reference protection
  if (seen.has(obj)) {
    return '[Circular]';
  }
  seen.add(obj);

  // Arrays. `map` reads `length` and every index through the object, and a
  // Proxy around an array answers `Array.isArray` and may refuse both.
  if (Array.isArray(obj)) {
    return probeBuiltin(() => obj.map((item) => redactWalk(item, seen))) ?? UNREADABLE;
  }

  // Date, preserved as-is for the logger to format. A Proxy around a Date
  // answers `instanceof` and then throws from every method, including the
  // `toJSON()` that `JSON.stringify` calls on it later, so the walk asks it
  // one question now rather than leaving the throw for the serializer.
  if (obj instanceof Date) {
    return probeBuiltin(() => obj.getTime()) === undefined ? UNREADABLE : obj;
  }

  // Error: name, message and stack, each read through a guard, because any of
  // the three may be a getter the object controls. A property that refuses
  // reads as absent while the others still read, which is the rule
  // `probeEntries` applies to every other object.
  if (obj instanceof Error) {
    return {
      name: probeProperty(obj, 'name'),
      message: probeProperty(obj, 'message'),
      stack: probeProperty(obj, 'stack'),
    };
  }

  // Map and Set, entry by entry. Iteration is the collection's own code: a
  // Proxy around either throws from `entries()` or `values()`, and a subclass
  // may throw from its iterator. A partial copy would claim to be the whole.
  if (obj instanceof Map) {
    return (
      probeBuiltin(() => {
        const result = new Map<unknown, unknown>();
        for (const [key, value] of obj) {
          result.set(redactWalk(key, seen), redactWalk(value, seen));
        }
        return result;
      }) ?? UNREADABLE
    );
  }

  if (obj instanceof Set) {
    return (
      probeBuiltin(() => {
        const result = new Set<unknown>();
        for (const value of obj) {
          result.add(redactWalk(value, seen));
        }
        return result;
      }) ?? UNREADABLE
    );
  }

  // Objects that define their own JSON form (URL, Buffer, user classes, and a
  // plain object carrying its own toJSON): redact that form. It has to come
  // before the plain-object copy, because a copy that keeps the function hands
  // JSON.stringify an unredacted form to call later. A toJSON() that returns
  // the object itself is walked like any other object.
  //
  // Both the lookup and the call are guarded. `'toJSON' in obj` goes through a
  // `has` trap, and the method itself is caller code that may throw. A refusal
  // from either falls through to the own-property walk, which is the same path
  // an object with no toJSON takes and still redacts everything it holds.
  const toJson = probeMethod(obj, 'toJSON');
  if (toJson !== undefined) {
    // With the redaction mark set: a toJSON() that calls reveal() would hand
    // the walk a plain string it cannot tell from one that was always plain,
    // so the gate refuses the reveal for the duration of the call. The refusal
    // is a throw, which lands in the fallback below like any other refusal,
    // and the instance is redacted as an instance there. See `redaction-scope`.
    const called = runInsideRedaction(() => probeCall(toJson, obj));

    if (called.ok) {
      return called.value === obj ? redactOwnProperties(obj, seen) : redactWalk(called.value, seen);
    }

    // The method refused, so the walk falls through to own properties. It also
    // drops the method itself: an own enumerable `toJSON` would otherwise be
    // copied into the result, and the next serializer to touch that result
    // would call it and get the same throw. The output of this function is
    // supposed to be inert.
    return redactOwnProperties(obj, seen, 'toJSON');
  }

  // Handle plain objects
  if (prototype === Object.prototype) {
    return redactOwnProperties(obj, seen);
  }

  // Class instances (entities, DTOs, view models) and null-prototype objects:
  // walk own enumerable properties. Stringifying these would hide any
  // SensitiveString they hold behind "[object Object]".
  if (isOrdinaryObject(obj)) {
    return redactOwnProperties(obj, seen);
  }

  // Exotic objects (typed arrays, promises, boxed primitives, RegExp, ...):
  // fall back to the string representation.
  //
  // Guarded, because an object that reaches here has its own toString by
  // definition, and its own toString is caller code. A refusal leaves nothing
  // to keep, so the marker stands in for it.
  return probeString(obj) ?? UNREADABLE;
}

/**
 * Prepare a value for safe logging.
 * Wrapper around redactInStructure with a clearer name for log contexts.
 *
 * @param obj - The value to make safe for logging
 * @returns A new structure with all SensitiveString instances redacted
 *
 * @example
 * ```ts
 * console.log('Processing request:', safeLog(payload));
 * ```
 */
export function safeLog<T>(obj: T): unknown {
  return redactInStructure(obj);
}

/**
 * Options for safe JSON stringify.
 */
export interface SafeStringifyOptions {
  /** Pretty print with indentation */
  pretty?: boolean;
  /** Custom replacer function (runs after redaction) */
  replacer?: (key: string, value: unknown) => unknown;
}

/**
 * Convert the values JSON.stringify rejects outright.
 *
 * A BigInt is the one primitive it throws a TypeError on rather than skipping,
 * so a single `id: 1n` anywhere in a payload takes down the logging call that
 * was meant to be the safe one. The decimal string is the conventional
 * substitute and is lossless, unlike Number(), which silently rounds anything
 * past 2^53. A BigInt has no source text to leak the way a function does.
 */
function toJsonSafe(value: unknown): unknown {
  return typeof value === 'bigint' ? value.toString() : value;
}

/**
 * Wrap the caller's replacer, if any, so the conversion runs on whatever that
 * replacer returned.
 *
 * Order matters: a caller's replacer is free to hand back a BigInt of its own,
 * so the conversion has to come last to hold. Running it first would also hide
 * the real value from a replacer that wanted to inspect it.
 *
 * Installing a replacer unconditionally is safe: an identity replacer produces
 * byte-identical output to passing null, and JSON.stringify applies it to the
 * root value too, so a bare BigInt is covered as well as a nested one. The
 * `function` expression, rather than an arrow, preserves the holder object as
 * `this`, which is what a replacer passed straight to JSON.stringify receives.
 */
function jsonSafeReplacer(
  replacer: SafeStringifyOptions['replacer']
): (this: unknown, key: string, value: unknown) => unknown {
  if (!replacer) {
    return (_key, value) => toJsonSafe(value);
  }

  return function (this: unknown, key: string, value: unknown): unknown {
    return toJsonSafe(replacer.call(this, key, value));
  };
}

/**
 * Safely stringify a value to JSON with all sensitive data redacted.
 *
 * Always returns a string and never throws on the input's shape: a BigInt
 * becomes its decimal string, and a value JSON cannot represent at all becomes
 * 'null'. Both are cases where JSON.stringify alone would take a logging call
 * down or hand back an undefined that its own type declaration denies.
 *
 * @param obj - The value to stringify
 * @param options - Stringify options
 * @returns JSON string with redacted sensitive values, or the string 'null'
 *          for a value JSON cannot represent
 *
 * @example
 * ```ts
 * const json = safeStringify({
 *   user: 'alice',
 *   token: new SensitiveString('secret', 'credential', 'token')
 * });
 * // '{"user":"alice","token":"[REDACTED:credential]"}'
 * ```
 */
export function safeStringify(obj: unknown, options: SafeStringifyOptions = {}): string {
  const redacted = redactInStructure(obj);
  const space = options.pretty ? 2 : undefined;

  const json = JSON.stringify(redacted, jsonSafeReplacer(options.replacer), space);

  // JSON.stringify returns undefined, not a string, for the values JSON cannot
  // represent: undefined itself, functions (a class constructor among them),
  // and symbols. A replacer that drops the root does the same. TypeScript's
  // own lib declares the return as `string` and hides this, so a caller that
  // believed the declaration would fail on the result rather than at the call.
  //
  // 'null' is what JSON.stringify already substitutes for these same values in
  // array position, so the fallback keeps the return parseable as JSON and
  // leaks nothing. Deliberately not String(redacted): a function's string form
  // is its source text, which would put a static field's initializer, secret
  // literals and all, into output this function exists to keep safe.
  return json ?? 'null';
}

/**
 * Create a logger-compatible serializer that redacts sensitive values.
 * Can be used with pino, winston, or other logging libraries that support
 * custom serializers.
 *
 * @returns A serializer function compatible with most logging libraries
 *
 * @example
 * ```ts
 * // With pino
 * const logger = pino({
 *   serializers: {
 *     req: createSensitiveSerializer(),
 *     payload: createSensitiveSerializer(),
 *   }
 * });
 * ```
 */
export function createSensitiveSerializer(): (value: unknown) => unknown {
  return (value: unknown) => redactInStructure(value);
}

/**
 * Check if a value contains any sensitive value: a SensitiveString instance,
 * or a serialized one, which holds the raw value in the open.
 * Useful for validation or debugging.
 *
 * Walks arrays, Map and Set entries, plain objects, and the own enumerable
 * properties of class instances.
 *
 * @param obj - The value to check
 * @returns true if any SensitiveString or serialized sensitive value is found
 */
export function containsSensitive(obj: unknown): boolean {
  return containsWalk(obj, new WeakSet<object>());
}

/** The walk itself. Private for the reason `redactWalk` is. */
function containsWalk(obj: unknown, seen: WeakSet<object>): boolean {
  if (obj === null || typeof obj !== 'object') {
    return false;
  }

  // Before the first `instanceof`, which walks the prototype chain and throws
  // for an object that refuses to report it. Unwalkable, so unprovable: a leak
  // detector answers `true` for a value it could not read, for the reason given
  // at the ordinary-object branch below.
  if (isUnreadable(obj)) {
    return true;
  }

  if (obj instanceof SensitiveString || carriesSerializedMarker(obj)) {
    return true;
  }

  if (seen.has(obj)) {
    return false;
  }
  seen.add(obj);

  // Iteration is the collection's own code, and a collection that refuses it
  // answers `true`, for the reason given at the ordinary-object branch below.
  if (Array.isArray(obj)) {
    return probeBuiltin(() => obj.some((item) => containsWalk(item, seen))) ?? true;
  }

  if (obj instanceof Map) {
    return (
      probeBuiltin(() => {
        for (const [key, value] of obj) {
          if (containsWalk(key, seen) || containsWalk(value, seen)) {
            return true;
          }
        }
        return false;
      }) ?? true
    );
  }

  if (obj instanceof Set) {
    return (
      probeBuiltin(() => {
        for (const value of obj) {
          if (containsWalk(value, seen)) {
            return true;
          }
        }
        return false;
      }) ?? true
    );
  }

  if (isOrdinaryObject(obj)) {
    const entries = probeEntries(obj);

    // An object that cannot be enumerated answers `true`, not `false`. This is
    // a leak detector, and the two wrong answers are not symmetric: reporting a
    // value it could not read as clean is how a caller ships a payload
    // believing it was checked. `sensitiveClassesIn` deliberately answers the
    // other way and says why.
    if (entries === undefined) {
      return true;
    }

    return entries.some(([, value]) => containsWalk(value, seen));
  }

  return false;
}

/**
 * Collect the sensitivity classes present anywhere in a value.
 *
 * The traversal matches {@link containsSensitive} exactly: arrays, Map keys and
 * values, Set values, plain objects, and the own enumerable properties of class
 * instances. It answers "which classes are in here" where `containsSensitive`
 * answers "is anything in here", so a caller can act on `credential` without
 * acting on `sensitive`. A serialized value contributes the class it names when
 * that class is registered; one naming an unregistered class is counted by
 * `containsSensitive` but has no class to contribute here.
 *
 * @param obj - The value to inspect
 * @returns The set of sensitivity classes found, empty when there are none
 *
 * @example
 * ```ts
 * const classes = sensitiveClassesIn({ token: apiKey, email: userEmail });
 * classes.has('credential'); // true
 * ```
 */
export function sensitiveClassesIn(obj: unknown): Set<SensitivityClass> {
  return classesWalk(obj, new Set<SensitivityClass>(), new WeakSet<object>());
}

/**
 * The walk itself. Private for the reason `redactWalk` is, and with one more:
 * a caller who primes `found` gets back a set naming a class the payload does
 * not contain, which is a wrong answer that reads exactly like a right one.
 */
function classesWalk(
  obj: unknown,
  found: Set<SensitivityClass>,
  seen: WeakSet<object>
): Set<SensitivityClass> {
  if (obj === null || typeof obj !== 'object') {
    return found;
  }

  // Unwalkable, and there is no class to name for something that was never
  // read. `containsSensitive` answers `true` for the same object; see the note
  // at its ordinary-object branch for why the two differ here.
  if (isUnreadable(obj)) {
    return found;
  }

  if (obj instanceof SensitiveString) {
    // Through a guard: a Proxy around an instance forwards the read, and a
    // hostile one may refuse it. Nothing to name then, as for any other object
    // that was never read.
    const klass = probeProperty(obj, 'klass');

    if (typeof klass === 'string') {
      found.add(klass as SensitivityClass);
    }

    return found;
  }

  if (carriesSerializedMarker(obj)) {
    const klass = serializedClass(obj);

    if (klass !== undefined) {
      found.add(klass);
    }

    return found;
  }

  if (seen.has(obj)) {
    return found;
  }
  seen.add(obj);

  // Iteration is the collection's own code. A collection that refuses it
  // contributes nothing beyond what was read before the refusal, which is the
  // answer this walk gives for an object it cannot enumerate.
  if (Array.isArray(obj)) {
    probeBuiltin(() => {
      for (const item of obj) {
        classesWalk(item, found, seen);
      }
    });
    return found;
  }

  if (obj instanceof Map) {
    probeBuiltin(() => {
      for (const [key, value] of obj) {
        classesWalk(key, found, seen);
        classesWalk(value, found, seen);
      }
    });
    return found;
  }

  if (obj instanceof Set) {
    probeBuiltin(() => {
      for (const value of obj) {
        classesWalk(value, found, seen);
      }
    });
    return found;
  }

  if (isOrdinaryObject(obj)) {
    // An object that cannot be enumerated contributes no classes, because there
    // is no class to name. That is the one place this traversal and
    // `containsSensitive` disagree, and the disagreement is the honest one:
    // `containsSensitive` can say "there may be something in here" without
    // knowing what, and this function cannot.
    for (const [, value] of probeEntries(obj) ?? []) {
      classesWalk(value, found, seen);
    }
  }

  return found;
}
