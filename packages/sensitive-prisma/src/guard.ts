import { SensitiveString, hasPolicy } from '@platform-sec/sensitive-string-core';
import type { SensitivityClass } from '@platform-sec/sensitive-string-core';
import { PrismaUnwrappedValueError } from './errors.js';

/**
 * Whether a value is a live `SensitiveString`.
 *
 * A plain `instanceof` narrows to `SensitiveString<any>`, because the class
 * declares a default type parameter, and `any` then spreads through everything
 * the narrowed value touches. This pins the class parameter to the union
 * instead, which is what the walk and the computed fields actually want.
 *
 * The counterpart to `isUnwrappedResidue`: this recognises an instance that
 * still holds its value, that one recognises what is left after Prisma's
 * argument copy has taken it away.
 */
export function isSensitiveString(value: unknown): value is SensitiveString<SensitivityClass> {
  return value instanceof SensitiveString;
}

/**
 * What is left of a `SensitiveString` after Prisma copies query arguments.
 *
 * Measured on Prisma 6.19.3 and 7.10.0. `applyQueryExtensions` calls
 * `deepCloneArgs(params.args)` before it hands the arguments to any query
 * extension hook, and `deepCloneValue` keeps only the types it knows: object
 * enum values, field references, `Decimal`, `Date` and typed arrays. Every
 * other class instance becomes a plain object built from a `for...in` copy,
 * which keeps the enumerable own properties and drops the prototype.
 *
 * A `SensitiveString` has exactly two enumerable own properties, `klass` and
 * `label`, on every construction path: a plain instance, a labelled one, one
 * built with options, one derived through `concat`, `substring` or `map`, and
 * one from `deserialize`. Its prototype carries no enumerable property, and the
 * raw value lives in an ES `#private` field, which a copy cannot reach.
 *
 * So the residue is precise, and it is also all that is left: the value is
 * already gone by the time the hook runs, which is why no query extension can
 * unwrap a model argument, and why this recognises the wreckage instead.
 */
export interface UnwrappedResidue {
  readonly klass: SensitivityClass;
  readonly label: string | undefined;
}

const RESIDUE_KEYS = ['klass', 'label'];

/**
 * Whether a value is the flattened remains of a `SensitiveString`.
 *
 * Deliberately exact rather than generous: the keys must be `klass` and `label`
 * and nothing else, the class must be one the policy registry knows, and the
 * label must be a string or absent. A `where` clause filtering two columns
 * named `klass` and `label`, on a value that is also a registered sensitivity
 * class, is the only false positive available, and `detectUnwrapped: false`
 * turns the check off for a schema unlucky enough to have one.
 */
export function isUnwrappedResidue(value: unknown): value is UnwrappedResidue {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  if (Object.getPrototypeOf(value) !== Object.prototype) return false;

  const keys = Object.keys(value);
  if (keys.length !== RESIDUE_KEYS.length) return false;
  if (!RESIDUE_KEYS.every((key) => keys.includes(key))) return false;

  const { klass, label } = value as { klass: unknown; label: unknown };
  if (typeof klass !== 'string' || !hasPolicy(klass as SensitivityClass)) return false;
  return label === undefined || typeof label === 'string';
}

function join(path: string, segment: string): string {
  return path === '' ? segment : `${path}.${segment}`;
}

/**
 * Find the first flattened `SensitiveString` in an argument tree.
 *
 * @returns The residue and the argument path it sat at, or `undefined`.
 */
export function findUnwrapped(
  args: unknown,
  path = '',
  seen: WeakSet<object> = new WeakSet()
): { path: string; residue: UnwrappedResidue } | undefined {
  if (typeof args !== 'object' || args === null) return undefined;
  if (seen.has(args)) return undefined;
  seen.add(args);

  if (isUnwrappedResidue(args)) {
    return { path, residue: args };
  }

  if (Array.isArray(args)) {
    for (const [index, item] of args.entries()) {
      const found = findUnwrapped(item, join(path, String(index)), seen);
      if (found !== undefined) return found;
    }
    return undefined;
  }

  const prototype: unknown = Object.getPrototypeOf(args);
  if (prototype !== Object.prototype && prototype !== null) {
    // A class instance Prisma's copy preserved, or a `Prisma.Sql`. Its `values`
    // are copied by reference and so still hold live instances, which the
    // extension unwraps rather than refuses.
    return undefined;
  }

  for (const [key, value] of Object.entries(args as Record<string, unknown>)) {
    const found = findUnwrapped(value, join(path, key), seen);
    if (found !== undefined) return found;
  }
  return undefined;
}

/**
 * Refuse an operation carrying a `SensitiveString` that was never unwrapped.
 *
 * Without this the write does not fail cleanly. Prisma reports
 * `Invalid value provided. Expected String, provided Object`, which names
 * neither the cause nor the fix; and on a client with no query extension at all
 * there is no error, because Prisma serialises the instance through `toJSON()`
 * and the column ends up holding the redaction marker.
 *
 * @throws PrismaUnwrappedValueError If any argument is a flattened instance.
 */
export function assertNoUnwrapped(
  args: unknown,
  context: { model?: string | undefined; operation: string }
): void {
  const found = findUnwrapped(args);
  if (found === undefined) return;

  throw new PrismaUnwrappedValueError(
    context.model,
    context.operation,
    found.path,
    found.residue.klass
  );
}
