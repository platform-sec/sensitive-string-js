import type { SensitivityClass } from './types.js';

/**
 * A field's classification, or `'plain'` to leave it an ordinary string.
 *
 * `'plain'` is not an absence of a decision. It is the decision that a key
 * carries configuration rather than a secret, and it is what keeps a wrapped
 * `PORT` or `LOG_LEVEL` out of a config tree: an instance is an object, so
 * `config.LOG_LEVEL === 'debug'` is permanently false once the value is
 * wrapped, and the application misbehaves in a way that looks like a
 * configuration bug rather than a security control.
 */
export type FieldClass = SensitivityClass | 'plain';

/** One pattern-to-class rule, tried in order for keys `fields` did not match. */
export interface ClassificationRule {
  /** Matched against key names, never against values. */
  readonly pattern: RegExp;
  readonly klass: FieldClass;
}

/**
 * Which keys of a decoded payload become which class.
 *
 * Precedence is `fields`, then `rules` in order, then `fallback`. The first
 * match wins at every level, so a key named in `fields` is never reconsidered
 * by a rule.
 *
 * Patterns run on key names. A key is a field name, not the secret, which is
 * the same reasoning that keeps record keys in the clear in the Zod
 * integration. Matching on values would mean reading them to decide whether to
 * protect them.
 */
export interface ClassificationSpec {
  /** Exact key or dot path matches. Highest precedence. */
  readonly fields?: Readonly<Record<string, FieldClass>>;
  /** Tried in order for keys `fields` did not match. */
  readonly rules?: readonly ClassificationRule[];
  /** Everything unmatched. Optional here, and each caller decides whether to require it. */
  readonly fallback?: FieldClass;
}

/**
 * A spec with its patterns compiled, so a rule list is prepared once per source
 * rather than once per key of every load.
 */
export interface CompiledClassification {
  /** The exact matches, in a map rather than an object so no key inherits one. */
  readonly fields: ReadonlyMap<string, FieldClass>;
  readonly rules: readonly ClassificationRule[];
  readonly fallback: FieldClass | undefined;

  /**
   * The class for one key, or `undefined` when nothing matched and the spec has
   * no fallback.
   *
   * @param key - The authoritative name, which for a nested payload is the dot
   *   path from the root of the decoded object.
   * @param aliases - Further names for the same field, tried after `key` at
   *   each precedence level. A nested field passes its leaf key here, so a rule
   *   written as `/password/` matches `db.password` without the caller having
   *   to anticipate the nesting.
   */
  classify(key: string, aliases?: readonly string[]): FieldClass | undefined;
}

const FIELD_CLASSES: readonly FieldClass[] = ['credential', 'sensitive', 'plain'];

function assertFieldClass(value: unknown, where: string): asserts value is FieldClass {
  if (typeof value !== 'string' || !FIELD_CLASSES.includes(value as FieldClass)) {
    throw new Error(
      `Invalid classification for ${where}: expected one of ${FIELD_CLASSES.join(', ')}.`
    );
  }
}

/**
 * The same pattern without `g` or `y`.
 *
 * Both flags make a `RegExp` stateful through `lastIndex`, and a compiled spec
 * is reused across every key of every load. A global pattern tested twice
 * answers `true` then `false` for the same key, so the second secret of a
 * payload would be classified differently from the first. Dropping the flags is
 * the fix rather than resetting `lastIndex` at each call, because it also
 * removes the shared mutable state a caller could observe on their own object.
 */
function stateless(pattern: RegExp): RegExp {
  const flags = pattern.flags.replace(/[gy]/g, '');

  return flags === pattern.flags ? pattern : new RegExp(pattern.source, flags);
}

/**
 * Prepare a spec for repeated matching.
 *
 * @throws Error if a class is not a `FieldClass`, or a rule has no `RegExp`.
 */
/**
 * Compiled forms, memoized per spec object.
 *
 * `classifyField` compiles the spec it is handed on every call, which made it
 * an order of magnitude slower than a hoisted compiled classification over a
 * payload of keys. A spec is `readonly` throughout its type, so reusing the
 * compiled form for the same object is sound; a caller that mutates one after
 * classifying with it gets the earlier compile.
 */
const compiledSpecs = new WeakMap<ClassificationSpec, CompiledClassification>();

export function compileClassification(spec: ClassificationSpec): CompiledClassification {
  // Checked before the memo, because `WeakMap.set` refuses a primitive key and
  // would report this as "Invalid value used as weak map key", which names an
  // implementation detail and not the caller's mistake. A primitive used to
  // compile to a classification that matched nothing and said so to no one.
  if (spec === null || typeof spec !== 'object') {
    throw new TypeError(
      `Invalid classification specification: expected an object, received ${
        spec === null ? 'null' : typeof spec
      }.`
    );
  }

  const memoized = compiledSpecs.get(spec);

  if (memoized !== undefined) {
    return memoized;
  }

  const compiled = compileSpec(spec);
  compiledSpecs.set(spec, compiled);
  return compiled;
}

function compileSpec(spec: ClassificationSpec): CompiledClassification {
  const fields = new Map<string, FieldClass>();

  for (const [key, klass] of Object.entries(spec.fields ?? {})) {
    assertFieldClass(klass, `field '${key}'`);
    fields.set(key, klass);
  }

  const rules = (spec.rules ?? []).map((rule, index) => {
    if (!(rule.pattern instanceof RegExp)) {
      throw new Error(`Invalid classification rule at index ${index}: pattern must be a RegExp.`);
    }
    assertFieldClass(rule.klass, `rule at index ${index}`);

    return { pattern: stateless(rule.pattern), klass: rule.klass };
  });

  if (spec.fallback !== undefined) {
    assertFieldClass(spec.fallback, 'fallback');
  }

  return {
    fields,
    rules,
    fallback: spec.fallback,
    classify(key: string, aliases?: readonly string[]): FieldClass | undefined {
      const names = aliases === undefined ? [key] : [key, ...aliases];

      for (const name of names) {
        const declared = fields.get(name);
        if (declared !== undefined) {
          return declared;
        }
      }

      for (const rule of rules) {
        for (const name of names) {
          if (rule.pattern.test(name)) {
            return rule.klass;
          }
        }
      }

      return spec.fallback;
    },
  };
}

/**
 * The class for one key under a spec, compiling the spec for this call.
 *
 * Convenient for a one-off decision. Anything classifying more than a handful
 * of keys compiles once with `compileClassification` instead.
 */
export function classifyField(
  key: string,
  spec: ClassificationSpec,
  aliases?: readonly string[]
): FieldClass | undefined {
  return compileClassification(spec).classify(key, aliases);
}
