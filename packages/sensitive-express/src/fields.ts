import type {
  SensitiveFieldConfig,
  SensitiveFieldOptions,
  SensitivityClass,
} from '@platform-sec/sensitive-string-core';

/**
 * Path segments that core's `getByPath` and `setByPath` refuse to walk.
 *
 * Core already returns `undefined` for them, so a configured path containing
 * one silently wraps nothing. Rejecting it here turns a typo, or an attempt to
 * reach `Object.prototype`, into an error at wire-up instead of a field that
 * quietly stays a plain string for the life of the process.
 */
const FORBIDDEN_SEGMENTS = new Set(['__proto__', 'constructor', 'prototype']);

/** The classes core ships policies for. */
const KNOWN_CLASSES: readonly string[] = ['credential', 'sensitive'];

/** One validated entry: where to look, what class to give it, what to call it. */
export interface CompiledField extends SensitiveFieldOptions {
  klass: SensitivityClass;
  label: string;
}

/**
 * Validate a map of dot-notation paths and give every entry a label.
 *
 * The label defaults to the path's last segment, so `'creditCard.number'`
 * labels as `number`, which is what an audit record wants far more often than
 * the whole path.
 *
 * @param fields - The user's field map
 * @param option - Name of the middleware, for the error message
 * @returns A new map, keyed by path, with every entry as `{ klass, label }`
 * @throws TypeError If the map, a path, or an entry is malformed
 */
export function compilePathFields(
  fields: SensitiveFieldConfig,
  option: string
): Record<string, CompiledField> {
  return compile(fields, option, {
    normalize: (path) => path,
    validate: (path) => validatePath(path, option),
    label: labelFromPath,
  });
}

/**
 * Validate a map of header names and give every entry a label.
 *
 * Names are lower-cased, which is how Node stores them, and the label defaults
 * to the lower-cased name. Nothing walks a dot here, so a name is checked only
 * for being a non-empty string; a header genuinely called `constructor` is an
 * ordinary key rather than a reserved one.
 *
 * @param fields - The user's field map
 * @param option - Name of the middleware, for the error message
 * @returns A new map, keyed by lower-cased name, with every entry as `{ klass, label }`
 * @throws TypeError If the map or an entry is malformed
 */
export function compileNameFields(
  fields: SensitiveFieldConfig,
  option: string
): Record<string, CompiledField> {
  return compile(fields, option, {
    normalize: (name) => name.toLowerCase(),
    validate: (name) => {
      if (name.length === 0) {
        throw new TypeError(`${option}.fields has an empty header name`);
      }
    },
    label: (name) => name,
  });
}

interface KeyHandling {
  normalize(key: string): string;
  validate(key: string): void;
  /** Called with the normalized key. */
  label(key: string): string;
}

function compile(
  fields: SensitiveFieldConfig,
  option: string,
  keys: KeyHandling
): Record<string, CompiledField> {
  if (fields === null || typeof fields !== 'object') {
    throw new TypeError(`${option}.fields must be an object mapping keys to sensitivity classes`);
  }

  // Null prototype: the duplicate check below asks whether a key is already
  // present, and on a plain object `'constructor' in compiled` is true before
  // anything has been added to it.
  const compiled: Record<string, CompiledField> = Object.create(null) as Record<
    string,
    CompiledField
  >;

  for (const [rawKey, entry] of Object.entries(fields)) {
    keys.validate(rawKey);

    const key = keys.normalize(rawKey);
    const klass = typeof entry === 'string' ? entry : entry?.klass;
    const label = typeof entry === 'string' ? undefined : entry?.label;

    if (typeof klass !== 'string' || !KNOWN_CLASSES.includes(klass)) {
      throw new TypeError(
        `${option}.fields['${rawKey}'] must be a sensitivity class ` +
          `(${KNOWN_CLASSES.join(' or ')}) or { klass, label }; received ${describe(entry)}`
      );
    }

    if (label !== undefined && typeof label !== 'string') {
      throw new TypeError(`${option}.fields['${rawKey}'].label must be a string when given`);
    }

    // Two source keys can normalize to one, which an object literal cannot
    // catch on its own: `X-Api-Key` and `x-api-key` are distinct keys that name
    // the same header. Letting the later one win would silently discard the
    // class the earlier one declared.
    if (key in compiled) {
      throw new TypeError(
        `${option}.fields declares '${rawKey}' more than once; it matches the same key as an ` +
          `earlier entry ('${key}')`
      );
    }

    compiled[key] = { klass, label: label ?? keys.label(key) };
  }

  return compiled;
}

/**
 * The default label for a dot-notation path: its last segment.
 *
 * A path pointing into an array (`'items.0.secret'`) still ends in a name,
 * because an index alone would be a useless label.
 */
function labelFromPath(path: string): string {
  const segments = path.split('.');

  return segments[segments.length - 1] ?? path;
}

function validatePath(path: string, option: string): void {
  if (path.length === 0) {
    throw new TypeError(`${option}.fields has an empty path key`);
  }

  for (const segment of path.split('.')) {
    if (segment.length === 0) {
      throw new TypeError(`${option}.fields['${path}'] has an empty path segment`);
    }

    if (FORBIDDEN_SEGMENTS.has(segment)) {
      throw new TypeError(
        `${option}.fields['${path}'] contains the reserved segment '${segment}', ` +
          'which the path walker refuses to follow'
      );
    }
  }
}

function describe(value: unknown): string {
  if (value === null) {
    return 'null';
  }

  return typeof value === 'object' ? JSON.stringify(value) : typeof value;
}
