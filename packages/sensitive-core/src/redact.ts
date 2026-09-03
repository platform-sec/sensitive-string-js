import { SensitiveString } from './sensitive-string.js';
import type { SensitivityClass } from './types.js';

/**
 * Identify ordinary objects: plain objects, null-prototype objects, and class
 * instances. Exotic objects such as typed arrays, promises, boxed primitives,
 * and anything with a custom Symbol.toStringTag report a different tag and are
 * handled by the string fallback instead.
 */
function isOrdinaryObject(obj: object): boolean {
  return Object.prototype.toString.call(obj) === '[object Object]';
}

/**
 * Copy own enumerable properties into a new plain object, redacting as we go.
 * Used for plain objects and class instances alike. The result is always a
 * plain object: methods, prototype getters, and private fields are not carried
 * over, which keeps the output inert for logging.
 */
function redactOwnProperties(obj: object, seen: WeakSet<object>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    result[key] = redactInStructure(value, seen);
  }
  return result;
}

/**
 * Recursively redact SensitiveString instances in a data structure.
 *
 * Handles:
 * - Primitive values (returned as-is)
 * - SensitiveString instances (redacted via toString())
 * - Arrays, Map, and Set (recursively processed)
 * - Date (preserved as-is)
 * - Error (name, message, and stack copied into a plain object)
 * - Plain objects and class instances (own enumerable properties recursively
 *   processed into a new plain object)
 * - Objects with a toJSON() method (their JSON form, recursively processed)
 * - Other exotic objects such as typed arrays or promises (string form)
 * - Circular references (replaced with '[Circular]')
 *
 * @param obj - The value to process
 * @param seen - WeakSet to track circular references (internal use)
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
export function redactInStructure(obj: unknown, seen = new WeakSet<object>()): unknown {
  // Handle primitives and null
  if (obj === null || typeof obj !== 'object') {
    return obj;
  }

  // Handle SensitiveString - redact to string
  if (obj instanceof SensitiveString) {
    return obj.toString();
  }

  // Circular reference protection
  if (seen.has(obj)) {
    return '[Circular]';
  }
  seen.add(obj);

  // Handle arrays
  if (Array.isArray(obj)) {
    return obj.map((item) => redactInStructure(item, seen));
  }

  // Handle Date - preserve as-is
  if (obj instanceof Date) {
    return obj;
  }

  // Handle Error - preserve message but redact any sensitive properties
  if (obj instanceof Error) {
    return {
      name: obj.name,
      message: obj.message,
      stack: obj.stack,
    };
  }

  // Handle Map
  if (obj instanceof Map) {
    const result = new Map<unknown, unknown>();
    for (const [key, value] of obj) {
      result.set(redactInStructure(key, seen), redactInStructure(value, seen));
    }
    return result;
  }

  // Handle Set
  if (obj instanceof Set) {
    const result = new Set<unknown>();
    for (const value of obj) {
      result.add(redactInStructure(value, seen));
    }
    return result;
  }

  // Handle plain objects
  if (Object.getPrototypeOf(obj) === Object.prototype) {
    return redactOwnProperties(obj, seen);
  }

  // Objects that define their own JSON form (URL, Buffer, user classes):
  // redact that form. A toJSON() that returns the object itself is walked
  // like any other class instance.
  if ('toJSON' in obj && typeof obj.toJSON === 'function') {
    const json: unknown = (obj as { toJSON: () => unknown }).toJSON();
    return json === obj ? redactOwnProperties(obj, seen) : redactInStructure(json, seen);
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
  // no-base-to-string reads this as the useless '[object Object]' case, but
  // isOrdinaryObject() returning false is exactly the guarantee that it is not:
  // anything still carrying Object's default tag went to redactOwnProperties
  // above, so what reaches here has its own toString or Symbol.toStringTag.
  // eslint-disable-next-line @typescript-eslint/no-base-to-string
  return String(obj);
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
 * Check if a value contains any SensitiveString instances.
 * Useful for validation or debugging.
 *
 * Walks arrays, Map and Set entries, plain objects, and the own enumerable
 * properties of class instances.
 *
 * @param obj - The value to check
 * @param seen - WeakSet to track circular references (internal use)
 * @returns true if any SensitiveString is found
 */
export function containsSensitive(obj: unknown, seen = new WeakSet<object>()): boolean {
  if (obj === null || typeof obj !== 'object') {
    return false;
  }

  if (obj instanceof SensitiveString) {
    return true;
  }

  if (seen.has(obj)) {
    return false;
  }
  seen.add(obj);

  if (Array.isArray(obj)) {
    return obj.some((item) => containsSensitive(item, seen));
  }

  if (obj instanceof Map) {
    for (const [key, value] of obj) {
      if (containsSensitive(key, seen) || containsSensitive(value, seen)) {
        return true;
      }
    }
    return false;
  }

  if (obj instanceof Set) {
    for (const value of obj) {
      if (containsSensitive(value, seen)) {
        return true;
      }
    }
    return false;
  }

  if (isOrdinaryObject(obj)) {
    return Object.values(obj).some((value) => containsSensitive(value, seen));
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
 * acting on `sensitive`.
 *
 * @param obj - The value to inspect
 * @param found - Accumulator for the classes seen so far (internal use)
 * @param seen - WeakSet to track circular references (internal use)
 * @returns The set of sensitivity classes found, empty when there are none
 *
 * @example
 * ```ts
 * const classes = sensitiveClassesIn({ token: apiKey, email: userEmail });
 * classes.has('credential'); // true
 * ```
 */
export function sensitiveClassesIn(
  obj: unknown,
  found = new Set<SensitivityClass>(),
  seen = new WeakSet<object>()
): Set<SensitivityClass> {
  if (obj === null || typeof obj !== 'object') {
    return found;
  }

  if (obj instanceof SensitiveString) {
    found.add((obj as SensitiveString<SensitivityClass>).klass);
    return found;
  }

  if (seen.has(obj)) {
    return found;
  }
  seen.add(obj);

  if (Array.isArray(obj)) {
    for (const item of obj) {
      sensitiveClassesIn(item, found, seen);
    }
    return found;
  }

  if (obj instanceof Map) {
    for (const [key, value] of obj) {
      sensitiveClassesIn(key, found, seen);
      sensitiveClassesIn(value, found, seen);
    }
    return found;
  }

  if (obj instanceof Set) {
    for (const value of obj) {
      sensitiveClassesIn(value, found, seen);
    }
    return found;
  }

  if (isOrdinaryObject(obj)) {
    for (const value of Object.values(obj)) {
      sensitiveClassesIn(value, found, seen);
    }
  }

  return found;
}
