import { SensitiveString, wrapSensitiveByPath } from '@platform-sec/sensitive-string-core';
import type {
  CompiledClassification,
  FieldClass,
  SensitiveFieldConfig,
  SensitiveStringOptions,
  SensitivityClass,
} from '@platform-sec/sensitive-string-core';

import { SecretPayloadError } from './errors.js';
import { fieldLabel } from './label.js';
import type { FieldSets, ResolvedSecretRef, SecretLifetime } from './types.js';

/** A value a field declared `'plain'` may hold. */
export type PlainFieldValue = string | number | boolean | null;

/** One leaf of a decoded payload, addressed by dot path. */
interface Leaf {
  /** Dot path from the root of the payload. */
  readonly path: string;
  /** The last segment, which is what a rule written without nesting in mind matches. */
  readonly key: string;
  readonly value: unknown;
}

/**
 * Every leaf of a decoded payload, in encounter order.
 *
 * A leaf is anything that is not a plain object: strings, numbers, booleans,
 * null, and arrays. Arrays are leaves rather than containers because indexing
 * into one produces field names like `0` and `1`, which classify against
 * nothing and read as noise in an audit record. An already-wrapped value is a
 * leaf too, which is what makes it safe to walk the wrapped clone: descending
 * into a `SensitiveString` would enumerate its own class and label fields as if
 * they were payload.
 */
function leaves(payload: Readonly<Record<string, unknown>>, prefix = ''): Leaf[] {
  const found: Leaf[] = [];

  for (const [key, value] of Object.entries(payload)) {
    const path = prefix === '' ? key : `${prefix}.${key}`;

    if (
      value !== null &&
      typeof value === 'object' &&
      !Array.isArray(value) &&
      !(value instanceof SensitiveString)
    ) {
      found.push(...leaves(value as Record<string, unknown>, path));
      continue;
    }

    found.push({ path, key, value });
  }

  return found;
}

/** A provider lifetime in the terms core's constructor takes. */
export function lifetimeOptions(
  lifetime: SecretLifetime | undefined
): SensitiveStringOptions | undefined {
  if (lifetime === undefined) {
    return undefined;
  }

  const options: SensitiveStringOptions = {};

  if (lifetime.ttl !== undefined) {
    options.ttl = lifetime.ttl;
  }
  if (lifetime.expiresAt !== undefined) {
    options.expiresAt = lifetime.expiresAt;
  }
  if (lifetime.allowRenewal !== undefined) {
    options.allowRenewal = lifetime.allowRenewal;
  }
  if (lifetime.maxRenewals !== undefined) {
    options.maxRenewals = lifetime.maxRenewals;
  }

  return Object.keys(options).length === 0 ? undefined : options;
}

export interface MaterializeOptions {
  readonly payload: Readonly<Record<string, unknown>>;
  readonly ref: ResolvedSecretRef;
  readonly spec: CompiledClassification;
  /** Label prefix. The field half is appended as `#<dot path>`. */
  readonly label: string;
  readonly lifetime?: SecretLifetime | undefined;
  /**
   * Field paths the caller declared by name, so a divergence between the spec
   * and the payload is an error rather than an `undefined` in a typed result.
   */
  readonly declared?: readonly string[];
}

export interface Materialized extends FieldSets {
  /** Every leaf path the payload carried, declared or not. Key names are not secret. */
  readonly keys: readonly string[];
  readonly counts: Readonly<Record<FieldClass, number>>;
  /** The classification each leaf received, for a caller assembling a typed result. */
  readonly classes: ReadonlyMap<string, FieldClass>;
  /** Values of leaves that were left unwrapped, including the non-string ones. */
  readonly raw: ReadonlyMap<string, unknown>;
}

function isPlainScalar(value: unknown): value is PlainFieldValue {
  return (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  );
}

/**
 * Classify, then wrap.
 *
 * The path walker is core's. This function decides which paths get wrapped and
 * with what, hands `wrapSensitiveByPath` a `{ klass, label, options }` config,
 * and reads the result back into the two maps a caller sees. Wrapping in one
 * pass rather than per field is what keeps a nested payload's structure intact.
 *
 * What this cannot fix: the decoder materialized the payload as plain strings
 * before anything was wrapped, and `wrapSensitiveByPath` deep-clones. Both
 * copies exist until collection. JavaScript has no primitive that would let it
 * do better.
 */
export function materialize(options: MaterializeOptions): Materialized {
  const { payload, ref, spec, label, lifetime, declared = [] } = options;

  const found = leaves(payload);
  const byPath = new Map(found.map((leaf) => [leaf.path, leaf]));
  const classes = new Map<string, FieldClass>();
  const config: SensitiveFieldConfig = {};
  const constructionOptions = lifetimeOptions(lifetime);

  for (const name of declared) {
    const leaf = byPath.get(name);

    if (leaf === undefined) {
      // A declared name that is not a leaf but is the prefix of one names a
      // container rather than a value. That is a different mistake from a
      // field the payload no longer carries, and the fix is different too.
      const container = found.some((candidate) => candidate.path.startsWith(`${name}.`));

      throw new SecretPayloadError(
        container
          ? `Secret '${ref.path}' version '${ref.version}' field '${name}' holds an object ` +
              `or an array. Declare its leaves instead, such as '${name}.<field>'.`
          : `Secret '${ref.path}' version '${ref.version}' has no field '${name}'. ` +
              `The declared fields and the payload have diverged.`,
        ref.path,
        ref.version
      );
    }

    const klass = spec.classify(leaf.path, [leaf.key]);

    if (klass !== 'plain' && typeof leaf.value !== 'string') {
      throw new SecretPayloadError(
        `Secret '${ref.path}' version '${ref.version}' field '${name}' was declared ` +
          `'${String(klass)}' but is not a string, so it cannot be wrapped.`,
        ref.path,
        ref.version
      );
    }

    if (klass === 'plain' && !isPlainScalar(leaf.value)) {
      throw new SecretPayloadError(
        `Secret '${ref.path}' version '${ref.version}' field '${name}' holds an object ` +
          `or an array. Declare its leaves instead, such as '${name}.<field>'.`,
        ref.path,
        ref.version
      );
    }
  }

  for (const leaf of found) {
    const matched = spec.classify(leaf.path, [leaf.key]) ?? 'plain';

    // Non-string leaves stay as they are. `port: 5432` is not a secret and
    // wrapping a number would change its type for no benefit. The class
    // recorded is the effective one, so a caller reading `classes` sees what
    // happened rather than what a rule asked for.
    const klass: FieldClass =
      matched === 'plain' || typeof leaf.value !== 'string' ? 'plain' : matched;
    classes.set(leaf.path, klass);

    if (klass === 'plain') {
      continue;
    }

    config[leaf.path] = {
      klass,
      label: fieldLabel(label, leaf.path),
      ...(constructionOptions === undefined ? {} : { options: constructionOptions }),
    };
  }

  const wrapped = wrapSensitiveByPath(payload as Record<string, unknown>, config);
  const wrappedLeaves = new Map(leaves(wrapped).map((leaf) => [leaf.path, leaf.value]));

  const fields = new Map<string, SensitiveString<SensitivityClass>>();
  const plain = new Map<string, string>();
  const raw = new Map<string, unknown>();
  const counts: Record<FieldClass, number> = { credential: 0, sensitive: 0, plain: 0 };

  for (const leaf of found) {
    const klass = classes.get(leaf.path) ?? 'plain';
    const value = wrappedLeaves.get(leaf.path);

    if (value instanceof SensitiveString) {
      fields.set(leaf.path, value as SensitiveString<SensitivityClass>);
      counts[klass] += 1;
      continue;
    }

    // Either the classification said `plain`, or the leaf was not a string and
    // so was never a candidate for wrapping.
    counts.plain += 1;
    raw.set(leaf.path, leaf.value);

    if (typeof leaf.value === 'string') {
      plain.set(leaf.path, leaf.value);
    }
  }

  return {
    fields,
    plain,
    raw,
    keys: found.map((leaf) => leaf.path),
    counts,
    classes,
  };
}
