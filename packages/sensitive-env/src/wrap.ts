import {
  SensitiveString,
  validateSensitiveFieldConfig,
  wrapSensitiveByPath,
} from '@platform-sec/sensitive-string-core';
import type {
  CompiledClassification,
  FieldClass,
  SensitiveFieldConfig,
  SensitivityClass,
} from '@platform-sec/sensitive-string-core';

import { compileEnvSpec, emptyCounts, envLabel } from './classify.js';
import { probeKeys, probeProperty } from './probe.js';
import type { EnvSpec } from './types.js';

/** One flat source, split into what was wrapped and what was left alone. */
export interface FlatWrapResult {
  readonly fields: Map<string, SensitiveString<SensitivityClass>>;
  readonly plain: Map<string, string>;
  /** Every name the source offered, wrapped or not, in insertion order. */
  readonly names: string[];
  /** The class each name received. */
  readonly classes: Map<string, FieldClass>;
  readonly counts: Record<FieldClass, number>;
}

/**
 * Wrap a flat record by **exact key**.
 *
 * Not `wrapSensitiveByPath`. That helper splits keys on `.`, so a variable
 * literally named `A.B` is read as a nested path, matches nothing, and is
 * silently left a raw string. Measured. Environment names with dots are legal,
 * are produced by some container platforms and by `.env` files, and would
 * therefore be a silent hole in exactly the tool an integration is told to
 * reach for. The flat case involves no walking at all, so it does none.
 *
 * A name whose value is not a string, which for `process.env` means
 * `undefined`, lands in neither map. It is still reported in `names`, because
 * the caller asked about it and "absent" is an answer.
 *
 * @param source - The variables, by name.
 * @param spec - Which names become which class.
 */
export function wrapFlat(
  source: Readonly<Record<string, string | undefined>>,
  spec: EnvSpec
): FlatWrapResult {
  return wrapFlatCompiled(source, spec, compileEnvSpec(spec));
}

/**
 * The same walk with the spec already compiled.
 *
 * `loadEnv` merges several sources and must not recompile a rule list per
 * source, let alone per name.
 *
 * @internal
 */
export function wrapFlatCompiled(
  source: Readonly<Record<string, string | undefined>>,
  spec: EnvSpec,
  compiled: CompiledClassification
): FlatWrapResult {
  const fields = new Map<string, SensitiveString<SensitivityClass>>();
  const plain = new Map<string, string>();
  const classes = new Map<string, FieldClass>();
  const counts = emptyCounts();
  const names: string[] = [];

  // Guarded reads, not `Object.keys` and a plain index. The source is whatever
  // the caller passed, and envalid's `cleanEnv` result is a real object that
  // throws for a name it was not given. An object that refuses to answer is
  // walked as far as it will go rather than taking the whole load down.
  for (const name of probeKeys(source)) {
    names.push(name);

    const klass = compiled.classify(name) ?? spec.fallback;
    classes.set(name, klass);
    counts[klass]++;

    const value = probeProperty(source, name);
    if (typeof value !== 'string') {
      continue;
    }

    if (klass === 'plain') {
      plain.set(name, value);
    } else {
      fields.set(name, new SensitiveString(value, klass, envLabel(spec, name)));
    }
  }

  return { fields, plain, names, classes, counts };
}

/** How `wrapTree` treats a configured path the document does not have. */
export interface WrapTreeOptions {
  /**
   * Throw when a configured path is absent from the document. Defaults to
   * `true`.
   *
   * On by default because the case this form was added for is a configuration
   * document, where an absent path is a typo in the field list rather than an
   * optional value, and a typo means a secret was silently left unwrapped while
   * the caller believes it was protected. Set it to `false` for a document
   * whose fields really are optional.
   */
  readonly requireAllPaths?: boolean;
}

/**
 * Wrap a nested configuration document by dot path.
 *
 * This is `wrapSensitiveByPath` from `core`, plus the `validateSensitiveFieldConfig`
 * check that catches a path typo. There is no second path walker in this
 * package. Dots are real separators here, unlike in `wrapFlat`, because a
 * config tree is nested and an environment variable name is not.
 *
 * Use it on the plain tree a config library hands out, never on the library's
 * own instance:
 *
 * @example
 * ```ts
 * config.validate({ allowed: 'strict' });
 * const settings = wrapTree(config.getProperties(), CONFIG_FIELDS);
 * ```
 *
 * @throws Error when a configured path is absent and `requireAllPaths` is on.
 *   The message lists paths and never values.
 */
export function wrapTree<T extends object>(
  tree: T,
  config: SensitiveFieldConfig,
  options: WrapTreeOptions = {}
): T {
  if (options.requireAllPaths !== false) {
    const validation = validateSensitiveFieldConfig(tree, config);
    if (!validation.valid) {
      throw new Error(
        `Configured sensitive paths are absent from the document: ` +
          `${validation.missingPaths.join(', ')}. Fix the path, or pass ` +
          `{ requireAllPaths: false } if the field is genuinely optional.`
      );
    }
  }

  return wrapSensitiveByPath(tree, config);
}
