import { SensitiveString } from '@platform-sec/sensitive-string-core';
import type {
  CompiledClassification,
  FieldClass,
  SensitiveStringOptions,
  SensitivityClass,
} from '@platform-sec/sensitive-string-core';

import { SecretPayloadError } from './errors.js';
import { fieldLabel } from './label.js';
import type { FieldSets, ResolvedSecretRef, SecretLifetime } from './types.js';

/** A value a field declared `'plain'` may hold. */
export type PlainFieldValue = string | number | boolean | null;

/** One leaf of a decoded payload. */
interface Leaf {
  /** Dot path from the root, which is how a caller names the field. */
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
 * leaf too: descending into a `SensitiveString` would enumerate its own class
 * and label fields as if they were payload.
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
 * Reject a payload whose dot paths are ambiguous.
 *
 * `{ "a.b": x }` and `{ a: { b: x } }` produce the same path, and a caller
 * naming `a.b` in a spec would be naming both. Two leaves under one name would
 * mean one of them silently wins the classification the other was meant to get,
 * so the payload is refused instead. This is rare enough to be worth being loud
 * about and dangerous enough to be worth refusing.
 */
function assertDistinctPaths(found: readonly Leaf[], ref: ResolvedSecretRef): void {
  const seen = new Set<string>();

  for (const leaf of found) {
    if (seen.has(leaf.path)) {
      throw new SecretPayloadError(
        `Secret '${ref.path}' version '${ref.version}' has two fields that both address ` +
          `'${leaf.path}', one as a key containing a dot and one through nesting. ` +
          `Classification cannot tell them apart.`,
        ref.path,
        ref.version
      );
    }

    seen.add(leaf.path);
  }
}

/**
 * Classify, then wrap.
 *
 * Wrapping happens at the leaf, not by dot path. An earlier version of this
 * function handed a `SensitiveFieldConfig` to core's `wrapSensitiveByPath`,
 * which is the obvious way to reuse a walker the library already has, and it
 * silently failed to wrap any key containing a dot: that helper reads `a.b` as
 * a path into a nested object, so a flat `{ "tls.key": ... }` matched nothing
 * and the secret came back in the plain map as an ordinary string. Kubernetes
 * Secret keys are routinely `tls.key`, `ca.crt` and `.dockerconfigjson`, so
 * that was the common case rather than an edge one, and under-wrapping is the
 * failure this whole layer exists to prevent.
 *
 * Wrapping at the leaf also removes a copy. The dot-path helper deep-clones its
 * input, so the payload existed twice; now only the decoder's own copy exists
 * until collection. JavaScript still has no primitive that would let this
 * function do better than that one.
 */
export function materialize(options: MaterializeOptions): Materialized {
  const { payload, ref, spec, label, lifetime, declared = [] } = options;

  const found = leaves(payload);
  assertDistinctPaths(found, ref);

  const byPath = new Map(found.map((leaf) => [leaf.path, leaf]));
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

  const classes = new Map<string, FieldClass>();
  const fields = new Map<string, SensitiveString<SensitivityClass>>();
  const plain = new Map<string, string>();
  const raw = new Map<string, unknown>();
  const counts: Record<FieldClass, number> = { credential: 0, sensitive: 0, plain: 0 };

  for (const leaf of found) {
    // A value the provider already wrapped stays as it is. Re-wrapping would
    // derive a second instance from the first and lose whichever deadline the
    // provider bound to it.
    if (leaf.value instanceof SensitiveString) {
      const existing = leaf.value as SensitiveString<SensitivityClass>;
      classes.set(leaf.path, existing.klass);
      fields.set(leaf.path, existing);
      counts[existing.klass] += 1;
      continue;
    }

    const matched = spec.classify(leaf.path, [leaf.key]) ?? 'plain';
    const value = leaf.value;

    // Non-string leaves stay as they are. `port: 5432` is not a secret and
    // wrapping a number would change its type for no benefit. The class
    // recorded is the effective one, so a caller reading `classes` sees what
    // happened rather than what a rule asked for.
    if (matched === 'plain' || typeof value !== 'string') {
      classes.set(leaf.path, 'plain');
      counts.plain += 1;
      raw.set(leaf.path, value);

      if (typeof value === 'string') {
        plain.set(leaf.path, value);
      }

      continue;
    }

    classes.set(leaf.path, matched);
    fields.set(
      leaf.path,
      new SensitiveString<SensitivityClass>(
        value,
        matched,
        fieldLabel(label, leaf.path),
        constructionOptions
      )
    );
    counts[matched] += 1;
  }

  // Nothing the classification asked to protect may end up in the plain map.
  // The bug this replaced was exactly that, and it was silent, so the
  // post-condition stays even though the loop above now makes it unreachable.
  for (const [path, klass] of classes) {
    if (klass !== 'plain' && !fields.has(path)) {
      throw new SecretPayloadError(
        `Secret '${ref.path}' version '${ref.version}' field '${path}' was classified ` +
          `'${klass}' but was not wrapped.`,
        ref.path,
        ref.version
      );
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
