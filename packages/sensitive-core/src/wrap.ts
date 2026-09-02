import { SensitiveString } from './sensitive-string.js';
import type { SensitivityClass, RevealContext } from './types.js';
import { getCurrentRevealContext } from './context.js';

/** Class and optional audit label for one configured field path. */
export interface SensitiveFieldOptions {
  klass: SensitivityClass;
  label?: string;
}

/**
 * Configuration for path-based sensitive field wrapping.
 * Keys are dot-notation paths. Values are either sensitivity classes or an
 * object containing a class and optional label.
 *
 * @example
 * ```ts
 * const config: SensitiveFieldConfig = {
 *   'user.email': 'sensitive',
 *   'user.ssn': { klass: 'sensitive', label: 'ssn' },
 *   'credentials.apiKey': 'credential',
 *   'session.token': 'credential',
 * };
 * ```
 */
export type SensitiveFieldConfig = Record<string, SensitivityClass | SensitiveFieldOptions>;

/**
 * Result type after wrapping - transforms string fields at specified paths
 * to SensitiveString instances while preserving the rest of the structure.
 *
 * Note: Due to TypeScript limitations with dynamic path-based transformations,
 * the exact return type is complex. In practice, the wrapped object maintains
 * the same shape but with specified string fields converted to SensitiveString.
 */
export type WrappedResult<T> = T extends object ? { [K in keyof T]: WrappedResult<T[K]> } : T;

/**
 * Get a value from an object by dot-notation path.
 *
 * @param obj - The object to traverse
 * @param path - Dot-notation path (e.g., 'user.email' or 'additionalData.cardBin')
 * @returns The value at the path, or undefined if not found
 */
function getByPath(obj: unknown, path: string): unknown {
  const parts = path.split('.');
  let current: unknown = obj;

  for (const part of parts) {
    if (part === '__proto__' || part === 'constructor' || part === 'prototype') {
      return undefined;
    }
    if (current === null || current === undefined) {
      return undefined;
    }
    if (typeof current !== 'object') {
      return undefined;
    }
    current = (current as Record<string, unknown>)[part];
  }

  return current;
}

/**
 * Set a value in an object by dot-notation path.
 * Creates intermediate objects if they don't exist.
 *
 * @param obj - The object to modify (mutates in place)
 * @param path - Dot-notation path
 * @param value - The value to set
 */
function setByPath(obj: Record<string, unknown>, path: string, value: unknown): void {
  const parts = path.split('.');
  let current: Record<string, unknown> = obj;

  for (let i = 0; i < parts.length - 1; i++) {
    const part = parts[i];
    if (part === undefined) continue;
    if (part === '__proto__' || part === 'constructor' || part === 'prototype') {
      return;
    }
    if (!(part in current) || typeof current[part] !== 'object' || current[part] === null) {
      current[part] = {};
    }
    current = current[part] as Record<string, unknown>;
  }

  const lastPart = parts[parts.length - 1];
  if (lastPart !== undefined) {
    if (lastPart === '__proto__' || lastPart === 'constructor' || lastPart === 'prototype') {
      return;
    }
    current[lastPart] = value;
  }
}

/**
 * Deep clone an object, preserving most types.
 * Does not clone functions, symbols, or class instances (except Date).
 */
function deepClone<T>(obj: T): T {
  if (obj === null || typeof obj !== 'object') {
    return obj;
  }

  if (obj instanceof Date) {
    return new Date(obj.getTime()) as unknown as T;
  }

  if (obj instanceof SensitiveString) {
    return obj; // Don't clone SensitiveString instances
  }

  if (Array.isArray(obj)) {
    return obj.map((item: unknown) => deepClone(item)) as T;
  }

  const cloned: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    cloned[key] = deepClone(value);
  }

  return cloned as T;
}

/**
 * Wrap sensitive fields in an object by path, converting string values
 * to SensitiveString instances.
 *
 * This is the primary utility for protecting sensitive data at boundary layers
 * (e.g., when receiving webhook payloads from payment providers).
 *
 * @typeParam T - The type of the input object
 * @param obj - The object containing sensitive data
 * @param config - Mapping of dot-notation paths to class or class-and-label configuration
 * @returns A deep clone of the object with specified fields wrapped as SensitiveString
 *
 * @remarks
 * - Only wraps fields that exist and are strings
 * - Non-existent paths are silently ignored
 * - Already-wrapped SensitiveString values are preserved
 * - The original object is not mutated
 *
 * @example
 * ```ts
 * const PSP_SENSITIVE_FIELDS = {
 *   'additionalData.hmacSignature': 'credential',
 *   'additionalData.cardSummary': 'sensitive',
 *   'additionalData.cardBin': 'sensitive',
 *   'additionalData.shopperIP': 'sensitive',
 *   'reason': 'sensitive',
 * } as const;
 *
 * const rawWebhook = JSON.parse(body);
 * const safeWebhook = wrapSensitiveByPath(rawWebhook, PSP_SENSITIVE_FIELDS);
 *
 * console.log(safeWebhook.additionalData.cardSummary);
 * // SensitiveString<sensitive> { [REDACTED:sensitive] }
 * ```
 */
export function wrapSensitiveByPath<T extends object>(obj: T, config: SensitiveFieldConfig): T {
  // Deep clone to avoid mutating the original
  const result = deepClone(obj) as Record<string, unknown>;

  for (const [path, fieldConfig] of Object.entries(config)) {
    const value = getByPath(result, path);

    // Only wrap if value exists and is a string
    if (typeof value === 'string') {
      const { klass, label } =
        typeof fieldConfig === 'string' ? { klass: fieldConfig, label: undefined } : fieldConfig;
      const wrapped = new SensitiveString(value, klass, label);
      setByPath(result, path, wrapped);
    }
    // If already a SensitiveString, leave it alone
    // If undefined/null/other type, skip
  }

  return result as T;
}

/**
 * Unwrap sensitive fields in an object by path, converting SensitiveString
 * instances back to raw strings.
 *
 * This is useful when you need to serialize data for external transmission
 * or when interfacing with APIs that don't understand SensitiveString.
 *
 * @typeParam T - The type of the input object
 * @param obj - The object containing SensitiveString instances
 * @param config - Mapping of dot-notation paths (same as used for wrapping)
 * @param ctx - Optional reveal context for auditing
 * @returns A deep clone of the object with specified SensitiveString fields unwrapped
 *
 * @remarks
 * - Audits each unwrap operation if a RevealContext is active
 * - Non-existent paths are silently ignored
 * - Regular string values are preserved as-is
 * - The original object is not mutated
 *
 * @example
 * ```ts
 * // When you need to forward data to another service
 * const rawPayload = unwrapSensitiveByPath(
 *   safeWebhook,
 *   PSP_SENSITIVE_FIELDS,
 *   { name: 'forward-to-processor', reason: 'payment processing' }
 * );
 * ```
 */
export function unwrapSensitiveByPath<T extends object>(
  obj: T,
  config: SensitiveFieldConfig,
  ctx?: RevealContext
): T {
  const effectiveCtx = ctx ?? getCurrentRevealContext() ?? undefined;

  // Deep clone to avoid mutating the original
  const result = deepClone(obj) as Record<string, unknown>;

  for (const path of Object.keys(config)) {
    const value = getByPath(result, path);

    // Only unwrap if value is a SensitiveString
    if (value instanceof SensitiveString) {
      const raw = value.reveal(effectiveCtx);
      setByPath(result, path, raw);
    }
    // If already a plain string or other type, leave it alone
  }

  return result as T;
}

/**
 * Validate that all paths in a config exist in a sample object.
 * Useful for catching typos in path configurations during testing.
 *
 * @param sampleObj - A sample object to validate against
 * @param config - The sensitive field configuration to validate
 * @returns An object with `valid` boolean and `missingPaths` array
 *
 * @example
 * ```ts
 * // In your test file
 * const validation = validateSensitiveFieldConfig(samplePSPWebhook, PSP_SENSITIVE_FIELDS);
 * expect(validation.valid).toBe(true);
 * expect(validation.missingPaths).toEqual([]);
 * ```
 */
export function validateSensitiveFieldConfig(
  sampleObj: unknown,
  config: SensitiveFieldConfig
): { valid: boolean; missingPaths: string[] } {
  const missingPaths: string[] = [];

  for (const path of Object.keys(config)) {
    const value = getByPath(sampleObj, path);
    if (value === undefined) {
      missingPaths.push(path);
    }
  }

  return {
    valid: missingPaths.length === 0,
    missingPaths,
  };
}

/**
 * Check if an object contains any unwrapped sensitive fields
 * based on the provided configuration.
 *
 * Useful for validation to ensure all sensitive fields have been wrapped.
 *
 * @param obj - The object to check
 * @param config - The sensitive field configuration
 * @returns An object with `allWrapped` boolean and `unwrappedPaths` array
 *
 * @example
 * ```ts
 * const check = checkSensitiveFieldsWrapped(webhook, PSP_SENSITIVE_FIELDS);
 * if (!check.allWrapped) {
 *   throw new Error(`Unwrapped sensitive fields: ${check.unwrappedPaths.join(', ')}`);
 * }
 * ```
 */
export function checkSensitiveFieldsWrapped(
  obj: unknown,
  config: SensitiveFieldConfig
): { allWrapped: boolean; unwrappedPaths: string[] } {
  const unwrappedPaths: string[] = [];

  for (const path of Object.keys(config)) {
    const value = getByPath(obj, path);

    // If the field exists and is a plain string (not SensitiveString), it's unwrapped
    if (typeof value === 'string') {
      unwrappedPaths.push(path);
    }
  }

  return {
    allWrapped: unwrappedPaths.length === 0,
    unwrappedPaths,
  };
}
