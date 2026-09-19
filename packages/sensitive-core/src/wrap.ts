import { SensitiveString } from './sensitive-string.js';
import type { SensitivityClass, RevealContext, SensitiveStringOptions } from './types.js';
import { getCurrentRevealContext } from './context.js';
import { assignOwn } from './own-property.js';
import { compileClassification } from './classification.js';
import type { ClassificationSpec, CompiledClassification, FieldClass } from './classification.js';

/** Class, optional audit label, and optional lifetime for one configured field path. */
export interface SensitiveFieldOptions {
  klass: SensitivityClass;
  label?: string;
  /**
   * Construction options for the wrapped value, most usefully a deadline.
   *
   * A secrets manager that reports when a secret expires has to bind that
   * deadline to every field it wrapped, and a wrapper that could only carry a
   * class and a label would leave the deadline in provider metadata that
   * nothing enforces.
   */
  options?: SensitiveStringOptions;
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
 *   'session.refresh': { klass: 'credential', options: { ttl: 60_000 } },
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
 * Refuse a protected value handed in as the whole object to wrap.
 *
 * `deepClone` returns an instance by reference, and a walk over it would see
 * its own public `klass` and `label` and write wrapped values over them in
 * place, on the caller's object, leaving an instance that cannot render or
 * reveal. A value that is already protected has nothing here to do.
 */
function refuseInstanceRoot(obj: unknown, where: string): void {
  if (obj instanceof SensitiveString) {
    throw new TypeError(
      `${where}: expected a parsed object, received a SensitiveString. The value is already ` +
        'protected; wrap the object that holds it.'
    );
  }
}

/**
 * Deep clone an object, preserving most types.
 * Does not clone functions, symbols, or class instances (except Date).
 *
 * A key named `__proto__` is copied as the own data property it was, never
 * assigned: see `assignOwn`. A webhook body is the input this function was
 * written for, and an attacker chooses its keys.
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
    assignOwn(cloned, key, deepClone(value));
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
 * - Wraps a string at a declared path, and every string element of an array
 *   at one, through nested arrays; a list of connection strings declared once
 *   becomes a list of wrapped connection strings. Until 2026-09-19 an array
 *   was skipped, silently, and the corpus study found the two report
 *   functions vouching for the config that skipped it.
 * - Any other value at a declared path, an object, a number, `null`, is left
 *   as it is, and `validateSensitiveFieldConfig` reports it as unwrappable
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
  refuseInstanceRoot(obj, 'wrapSensitiveByPath');

  // Deep clone to avoid mutating the original
  const result = deepClone(obj) as Record<string, unknown>;

  for (const [path, fieldConfig] of Object.entries(config)) {
    const value = getByPath(result, path);

    const resolved: SensitiveFieldOptions =
      typeof fieldConfig === 'string' ? { klass: fieldConfig } : fieldConfig;

    if (typeof value === 'string') {
      const wrapped = new SensitiveString(value, resolved.klass, resolved.label, resolved.options);
      setByPath(result, path, wrapped);
    } else if (Array.isArray(value)) {
      // The clone's own array, so wrapping in place mutates nothing the caller
      // holds. Each element gets the class, the label and the options the path
      // declared: one declaration is one classification, however many values
      // stand at it.
      wrapElements(value, resolved);
    }
    // If already a SensitiveString, leave it alone
    // If undefined/null/other type, skip
  }

  return result as T;
}

/**
 * Wrap every string element of an array a declared path holds, through nested
 * arrays. Anything else, an object or a number, stays as it is, for the reason
 * the leaf walk leaves them: a path names values of one class, and an object
 * inside the list is addressed by a deeper path or left alone.
 */
function wrapElements(list: unknown[], resolved: SensitiveFieldOptions): void {
  list.forEach((item, index) => {
    if (typeof item === 'string') {
      list[index] = new SensitiveString(item, resolved.klass, resolved.label, resolved.options);
    } else if (Array.isArray(item)) {
      wrapElements(item, resolved);
    }
  });
}

/** The reverse, for `unwrapSensitiveByPath`: every instance in the list is revealed. */
function unwrapElements(list: unknown[], ctx: RevealContext | undefined): void {
  list.forEach((item, index) => {
    if (item instanceof SensitiveString) {
      list[index] = item.reveal(ctx);
    } else if (Array.isArray(item)) {
      unwrapElements(item, ctx);
    }
  });
}

/**
 * Whether `wrapSensitiveByPath` would act on everything in this array: each
 * element is a string, an instance, or such an array. An empty array passes,
 * since nothing in it is left unprotected.
 */
function isWrappableArray(list: unknown[]): boolean {
  return list.every(
    (item) =>
      typeof item === 'string' ||
      item instanceof SensitiveString ||
      (Array.isArray(item) && isWrappableArray(item))
  );
}

/**
 * Whether every element of this array is an instance, through nested arrays.
 * A plain string is unwrapped, and so is anything else that is not an
 * instance, on the rule `checkSensitiveFieldsWrapped` applies at the path.
 */
function isWrappedArray(list: unknown[]): boolean {
  return list.every(
    (item) => item instanceof SensitiveString || (Array.isArray(item) && isWrappedArray(item))
  );
}

/**
 * How `wrapSensitiveByClassification` labels and constructs what it wraps.
 */
export interface ClassifiedWrapOptions {
  /**
   * The audit label for every wrapped leaf: a fixed string, or a function of
   * the leaf's dot path and its nearest key that returns one, or `undefined`
   * for no label. Paths and keys are field names, never values.
   */
  label?: string | ((path: string, key: string) => string | undefined);
  /** Construction options for every wrapped leaf, most usefully a deadline or a destination. */
  options?: SensitiveStringOptions;
}

/**
 * The classification a leaf gets under a spec.
 *
 * The authoritative name is the dot path with array indices, so a spec can
 * name one element. The aliases are the same path with its trailing indices
 * stripped, so `fields: { 'db.replicaUrls': 'credential' }` classifies every
 * element of that array, and the nearest key name, so a rule written as
 * `/password/` matches `db.password` without the caller anticipating the
 * nesting. The secrets layer classifies with the same three names.
 */
function classifyLeaf(
  spec: CompiledClassification,
  path: string,
  keyPath: string,
  key: string
): FieldClass | undefined {
  return spec.classify(path, path === keyPath ? [key] : [keyPath, key]);
}

/** A container the classification walk descends into: a plain object or an array. */
function isContainer(value: unknown): value is Record<string, unknown> | unknown[] {
  return (
    value !== null &&
    typeof value === 'object' &&
    !(value instanceof SensitiveString) &&
    !(value instanceof Date)
  );
}

/**
 * Visit every string leaf of a JSON-shaped object with its classification.
 *
 * `path` carries array indices and `keyPath` does not, so a leaf inside an
 * array is classified under the array's own name as well as its own. `key` is
 * the nearest object key, which an index never replaces.
 */
function walkLeaves(
  node: Record<string, unknown> | unknown[],
  spec: CompiledClassification,
  path: string,
  keyPath: string,
  key: string,
  visit: (
    container: Record<string, unknown> | unknown[],
    entry: string,
    value: unknown,
    klass: FieldClass | undefined,
    path: string,
    key: string
  ) => void
): void {
  if (Array.isArray(node)) {
    node.forEach((value, index) => {
      const childPath = path === '' ? String(index) : `${path}.${index}`;

      if (isContainer(value)) {
        walkLeaves(value, spec, childPath, keyPath, key, visit);
        return;
      }

      visit(
        node,
        String(index),
        value,
        classifyLeaf(spec, childPath, keyPath, key),
        childPath,
        key
      );
    });
    return;
  }

  for (const [entry, value] of Object.entries(node)) {
    // `constructor`, `prototype` and an own `__proto__` are visited like any
    // other key. The path helpers refuse to traverse those names because a
    // dot path is a route into the object, and the route is the hazard; here
    // the key is data the payload chose, `constructor` is a legal header
    // name, and a string under it is exactly what a fallback means to wrap
    // and a check means to report. The write goes through `assignOwn`, so an
    // own `__proto__` stays the inert data property the clone gave it.
    const childPath = path === '' ? entry : `${path}.${entry}`;
    const childKeyPath = keyPath === '' ? entry : `${keyPath}.${entry}`;

    if (isContainer(value)) {
      walkLeaves(value, spec, childPath, childKeyPath, entry, visit);
      continue;
    }

    visit(node, entry, value, classifyLeaf(spec, childPath, childKeyPath, entry), childPath, entry);
  }
}

/**
 * Wrap every string leaf of an object that a classification spec says is
 * sensitive, including the ones whose keys nobody could enumerate in advance.
 *
 * `wrapSensitiveByPath` takes a list of the paths that are sensitive, which is
 * the right entry when the payload's shape is known: a webhook from a named
 * provider. It is the wrong entry for a bag whose keys the caller does not
 * choose, which is a header bag, a `.env` file, the return value of a plugin
 * loaded at run time, or a per-provider credential object whose keys are data.
 * A path list over such a bag is a denylist turned inside out, and it fails
 * the way every denylist in this library's adoption corpus failed: a key the
 * list does not name arrives unwrapped, silently, in the unsafe direction.
 *
 * This entry inverts the default. A spec with a `fallback` wraps every string
 * leaf the spec does not classify `'plain'`, so the list the caller maintains
 * is the short one, of what may stay readable, and a key nobody anticipated is
 * wrapped rather than missed. A spec with no `fallback` classifies by name
 * pattern alone, which is what a credential object with sixty provider shapes
 * needs: one rule set instead of sixty lists. Precedence is `fields`, then
 * `rules` in order, then `fallback`, as `compileClassification` documents.
 *
 * What it wraps and what it leaves:
 *
 * - Strings only. A number, a boolean and `null` keep their type whatever the
 *   spec says, because `port: 5432` is not a secret and a wrapped one would
 *   break `config.port === 5432` in a way that reads as a configuration bug.
 *   `checkClassifiedFieldsWrapped` reports nothing about them either.
 * - Every element of an array of strings, each classified under the array's
 *   own name, so a list of connection strings is a list of wrapped
 *   connection strings, as `wrapSensitiveByPath` does at a declared path.
 * - An already wrapped value is kept as it is, and not descended into.
 * - A `Date` is copied, not descended into.
 * - The input is deep-cloned first, as `wrapSensitiveByPath` does, and the
 *   clone keeps an own `__proto__` key as the inert data property it was.
 * - A `fields` entry written as a bare key matches that key at any depth,
 *   which is the alias rule `compileClassification` documents, so under a
 *   `fallback` a bare `password: 'plain'` leaves every `password` readable.
 *   Write the dot path to mean one of them.
 *
 * Reveal on the way out with `unwrapSensitiveByPath` and a list of the paths
 * that may leave, which is the allowlist this entry pairs with, or with each
 * value's own `reveal()`.
 *
 * @typeParam T - The type of the input object
 * @param obj - A parsed, JSON-shaped object. Not a string, and not a `Map`.
 * @param spec - Which keys become which class
 * @param options - A label and construction options for every wrapped leaf
 * @returns A deep clone with every classified string leaf wrapped
 *
 * @example
 * ```ts
 * // A header bag: keep one header readable, wrap the rest.
 * const headers = wrapSensitiveByClassification(req.headers, {
 *   fields: { referer: 'plain', host: 'plain' },
 *   fallback: 'sensitive',
 * });
 *
 * // A plugin's return value: every string it hands back is a credential.
 * const creds = wrapSensitiveByClassification(await plugin.getCredentials(), {
 *   fallback: 'credential',
 * });
 *
 * // A provider credential object with keys nobody enumerates: classify by name.
 * const provider = wrapSensitiveByClassification(config, {
 *   rules: [
 *     { pattern: /secret|token|password|key$/i, klass: 'credential' },
 *     { pattern: /email|phone/i, klass: 'sensitive' },
 *   ],
 * });
 * ```
 */
export function wrapSensitiveByClassification<T extends object>(
  obj: T,
  spec: ClassificationSpec,
  options: ClassifiedWrapOptions = {}
): T {
  if (obj === null || typeof obj !== 'object') {
    throw new TypeError(
      `wrapSensitiveByClassification: expected a parsed object, received ${obj === null ? 'null' : typeof obj}`
    );
  }

  refuseInstanceRoot(obj, 'wrapSensitiveByClassification');

  const compiled = compileClassification(spec);
  const result = deepClone(obj) as Record<string, unknown> | unknown[];
  const { label, options: construction } = options;

  walkLeaves(result, compiled, '', '', '', (container, entry, value, klass, path, key) => {
    if (typeof value !== 'string' || klass === undefined || klass === 'plain') {
      return;
    }

    const resolvedLabel = typeof label === 'function' ? label(path, key) : label;
    const wrapped = new SensitiveString(value, klass, resolvedLabel, construction);

    if (Array.isArray(container)) {
      container[Number(entry)] = wrapped;
    } else {
      assignOwn(container, entry, wrapped);
    }
  });

  return result as T;
}

/**
 * Report every string leaf a classification spec says is sensitive and that
 * is still a plain string.
 *
 * The inverse of `checkSensitiveFieldsWrapped`: that one walks the config and
 * asks the object, so a key the object carries and the config does not name
 * is invisible to it, which is exactly the key an untrusted payload adds.
 * This one walks the object and asks the spec, so the key it reports is the
 * one nobody declared.
 *
 * Used the way the path helper's checks are used: in a test over a sample
 * payload, or as a guard at a boundary before the object is logged or sent.
 * Non-string leaves are not reported, since the wrapper would not have
 * wrapped them.
 *
 * @param obj - The object to check
 * @param spec - The classification the object should satisfy
 * @returns `allWrapped`, and the dot paths of the string leaves that are not
 *
 * @example
 * ```ts
 * const check = checkClassifiedFieldsWrapped(payload, { fallback: 'credential' });
 * if (!check.allWrapped) {
 *   throw new Error(`Unwrapped sensitive fields: ${check.unwrappedPaths.join(', ')}`);
 * }
 * ```
 */
export function checkClassifiedFieldsWrapped(
  obj: unknown,
  spec: ClassificationSpec
): { allWrapped: boolean; unwrappedPaths: string[] } {
  const unwrappedPaths: string[] = [];

  if (isContainer(obj)) {
    walkLeaves(
      obj,
      compileClassification(spec),
      '',
      '',
      '',
      (_container, _entry, value, klass, path) => {
        if (typeof value === 'string' && klass !== undefined && klass !== 'plain') {
          unwrappedPaths.push(path);
        }
      }
    );
  }

  return {
    allWrapped: unwrappedPaths.length === 0,
    unwrappedPaths,
  };
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
 * - Audits each unwrap operation if a RevealContext is active, once per
 *   instance, so an array of five reveals five times
 * - An array at a declared path has every instance in it unwrapped
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

    if (value instanceof SensitiveString) {
      const raw = value.reveal(effectiveCtx);
      setByPath(result, path, raw);
    } else if (Array.isArray(value)) {
      // The wrap side's counterpart: every instance in the clone's array is
      // revealed under the same context, and a plain element stays as it is.
      unwrapElements(value, effectiveCtx);
    }
    // If already a plain string or other type, leave it alone
  }

  return result as T;
}

/**
 * Validate that all paths in a config exist in a sample object.
 * Useful for catching typos in path configurations during testing.
 *
 * `missingPaths` holds a declared path that is not in the object at all, which
 * is usually a typo. `unwrappablePaths` holds one that is there and holds
 * something `wrapSensitiveByPath` will not act on: an object, a number, `null`,
 * or an array with any of those in it. That case used to pass silently and is
 * the one worth failing a test over, since the config reads as though the field
 * is protected and nothing protects it. An array of strings is not such a case
 * since 2026-09-19: the helper wraps every element of it.
 *
 * @param sampleObj - A sample object to validate against
 * @param config - The sensitive field configuration to validate
 * @returns `valid`, plus `missingPaths` and `unwrappablePaths`
 *
 * @example
 * ```ts
 * // In your test file
 * const validation = validateSensitiveFieldConfig(samplePSPWebhook, PSP_SENSITIVE_FIELDS);
 * expect(validation.valid).toBe(true);
 * expect(validation.missingPaths).toEqual([]);
 * expect(validation.unwrappablePaths).toEqual([]);
 * ```
 */
export function validateSensitiveFieldConfig(
  sampleObj: unknown,
  config: SensitiveFieldConfig
): { valid: boolean; missingPaths: string[]; unwrappablePaths: string[] } {
  const missingPaths: string[] = [];
  const unwrappablePaths: string[] = [];

  for (const path of Object.keys(config)) {
    const value = getByPath(sampleObj, path);
    if (value === undefined || value === null) {
      missingPaths.push(path);
      continue;
    }
    // Declared, present, and something `wrapSensitiveByPath` will not act on
    // in full. Reported separately from a missing path: the path is right and
    // the value is the wrong shape, which is a different mistake and has a
    // different fix. An array is the wrong shape only when something in it is.
    if (
      typeof value !== 'string' &&
      !(value instanceof SensitiveString) &&
      !(Array.isArray(value) && isWrappableArray(value))
    ) {
      unwrappablePaths.push(path);
    }
  }

  return {
    valid: missingPaths.length === 0 && unwrappablePaths.length === 0,
    missingPaths,
    unwrappablePaths,
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

    // Absent is not unwrapped. An optional field that is not there carries no
    // secret, and `validateSensitiveFieldConfig` is what reports a path that
    // should be there and is not.
    if (value === undefined || value === null) continue;

    // Anything else that is not a `SensitiveString`, or an array of them, is
    // unwrapped, whatever its type. Until 2026-09-19 this tested
    // `typeof value === 'string'`, so a declared path holding an array of
    // secrets, or an object, answered `allWrapped: true`: the guard this
    // function's own documentation puts in a caller's path passed, and the
    // values went out in the clear. A config that wrapped nothing was affirmed
    // by both of this module's report functions. An array is reported once,
    // under the declared path, if anything in it is not an instance.
    if (!(value instanceof SensitiveString) && !(Array.isArray(value) && isWrappedArray(value))) {
      unwrappedPaths.push(path);
    }
  }

  return {
    allWrapped: unwrappedPaths.length === 0,
    unwrappedPaths,
  };
}
