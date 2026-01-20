import { SensitiveString } from './sensitive-string.js';

/**
 * Recursively redact SensitiveString instances in a data structure.
 *
 * Handles:
 * - Primitive values (returned as-is)
 * - SensitiveString instances (redacted via toString())
 * - Arrays (recursively processed)
 * - Plain objects (recursively processed)
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
      result.set(
        redactInStructure(key, seen),
        redactInStructure(value, seen)
      );
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
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      result[key] = redactInStructure(value, seen);
    }
    return result;
  }

  // Non-plain objects: check for toJSON method
  if ('toJSON' in obj && typeof (obj as { toJSON: unknown }).toJSON === 'function') {
    return (obj as { toJSON: () => unknown }).toJSON();
  }

  // Fallback: return string representation
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
 * Safely stringify a value to JSON with all sensitive data redacted.
 *
 * @param obj - The value to stringify
 * @param options - Stringify options
 * @returns JSON string with redacted sensitive values
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

  if (options.replacer) {
    return JSON.stringify(redacted, options.replacer, space);
  }

  return JSON.stringify(redacted, null, space);
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

  if (Object.getPrototypeOf(obj) === Object.prototype) {
    return Object.values(obj).some((value) => containsSensitive(value, seen));
  }

  return false;
}
