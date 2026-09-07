import {
  createChildContext,
  getCurrentRevealContext,
  withRevealContext,
} from '@platform-sec/sensitive-string-core';
import type {
  RevealContext,
  SensitiveString,
  SensitivityClass,
} from '@platform-sec/sensitive-string-core';
import { PrismaUnsafeStatementError } from './errors.js';
import { isSensitiveString } from './guard.js';

/**
 * What a reveal should be attributed to.
 *
 * Every field is optional because the two callers know different amounts. The
 * extension's raw hook knows the Prisma operation; `sensitiveInput()` runs in
 * the caller's own code and knows only what the caller tells it.
 */
export interface RevealAttribution {
  /** Schema model name, when there is one. */
  readonly model?: string | undefined;
  /** Prisma operation name: `create`, `$executeRaw`, and so on. */
  readonly operation?: string | undefined;
  /** Context name, used only if no ambient context supplies one. */
  readonly name?: string | undefined;
  /** Context reason, used only if no ambient context supplies one. */
  readonly reason?: string | undefined;
}

/**
 * A tagged-template SQL object, recognised by shape rather than by class.
 *
 * Two shapes reach here. `Prisma.Sql` carries `strings` and `values`;
 * `TypedSql`, which `$queryRawTyped` uses, carries `sql` and `values`. Both are
 * bundled into the client runtime where the class name is minified: it reads as
 * `_Sql` on Prisma 7 and as a single letter on Prisma 6, so the class is not
 * something to match on. The own properties are stable across both, and the
 * rest of each class is getters derived from them.
 */
interface SqlLike {
  readonly values: unknown[];
}

function isSqlLike(value: unknown): value is SqlLike {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const candidate = value as { values?: unknown; strings?: unknown; sql?: unknown };
  if (!Array.isArray(candidate.values)) return false;
  return Array.isArray(candidate.strings) || typeof candidate.sql === 'string';
}

/**
 * Build the context every unwrap in one operation starts from.
 *
 * Precedence, and why: an ambient context established with
 * `withRevealContext()` names the unit of work the caller cares about, so
 * replacing its `name` with a constant would flatten a request-scoped audit
 * trail into one bucket. The model, the operation and the argument path are not
 * lost by deferring to it, because they always travel in the tags.
 *
 * Layering goes through `createChildContext` so the ambient `auditReveal` hook
 * and the caller's tags survive; a freshly built context would silently drop
 * both.
 */
export function buildRevealContext(attribution: RevealAttribution): RevealContext {
  const { model, operation } = attribution;
  const ambient = getCurrentRevealContext();

  const name = ambient?.name ?? attribution.name ?? 'prisma';
  const reason =
    ambient?.reason ??
    attribution.reason ??
    describeOperation(model, operation) ??
    'database argument';

  return createChildContext({
    name,
    reason,
    tags: {
      ...(model === undefined ? {} : { model }),
      ...(operation === undefined ? {} : { operation }),
    },
  });
}

function describeOperation(model: string | undefined, operation: string | undefined) {
  if (operation === undefined) return model === undefined ? undefined : `write to ${model}`;
  return model === undefined ? operation : `${operation} on ${model}`;
}

function withPath(base: RevealContext, path: string): RevealContext {
  return { ...base, tags: { ...base.tags, path } };
}

/**
 * Reveal one value under a context that names where in the arguments it sat.
 *
 * The context is passed to `reveal()` and installed as the ambient one for the
 * duration of the call, which is not redundant. Core hands the explicit context
 * to a policy's `checkRevealAllowed`, but it calls `auditReveal(value, details)`
 * with no context at all, and `details` for a reveal is only
 * `{ operation: 'reveal' }`. Installing the context is therefore the one way an
 * audit sink can read the model, the operation and the argument path: from
 * `getCurrentRevealContext()` inside its own hook.
 *
 * The cost is one AsyncLocalStorage entry per sensitive value, paid only for
 * values that are actually wrapped.
 */
function revealAt(value: SensitiveString<SensitivityClass>, ctx: RevealContext): string {
  return withRevealContext(ctx, () => value.reveal(ctx));
}

function rebuildObject(
  source: Readonly<Record<string, unknown>>,
  entries: [string, unknown][]
): Record<string, unknown> {
  const target: Record<string, unknown> =
    Object.getPrototypeOf(source) === null ? (Object.create(null) as Record<string, unknown>) : {};
  for (const [key, value] of entries) {
    target[key] = value;
  }
  return target;
}

/**
 * Replace every `SensitiveString` in a value with its revealed string.
 *
 * A pure map: it descends into arrays and plain objects only, and returns the
 * original reference for any subtree it did not change. Class instances are
 * returned by identity, which is what keeps `Date`, `Decimal`, `Uint8Array` and
 * `Prisma.Sql` intact, and it is also what leaves `include` and `select`
 * untouched, since Prisma rejects a mutated one.
 *
 * Every replacement is one `reveal()` and therefore one audit entry, tagged
 * with the argument path that produced it.
 */
function walk(value: unknown, path: string, base: RevealContext, seen: WeakSet<object>): unknown {
  if (isSensitiveString(value)) {
    return revealAt(value, withPath(base, path));
  }

  if (typeof value !== 'object' || value === null) {
    return value;
  }

  // A cycle cannot be rebuilt, and Prisma could not serialise one either.
  // Returning the reference terminates the walk and changes nothing.
  if (seen.has(value)) {
    return value;
  }

  if (Array.isArray(value)) {
    seen.add(value);
    let changed = false;
    const mapped = value.map((item, index) => {
      const next = walk(item, join(path, String(index)), base, seen);
      if (next !== item) changed = true;
      return next;
    });
    return changed ? mapped : value;
  }

  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    // Any other class instance, `Prisma.Sql` included when it is nested rather
    // than the whole argument. Returned untouched.
    return value;
  }

  seen.add(value);
  const source = value as Record<string, unknown>;
  let changed = false;
  const entries = Object.entries(source).map<[string, unknown]>(([key, item]) => {
    const next = walk(item, join(path, key), base, seen);
    if (next !== item) changed = true;
    return [key, next];
  });

  return changed ? rebuildObject(source, entries) : value;
}

function join(path: string, segment: string): string {
  return path === '' ? segment : `${path}.${segment}`;
}

/**
 * Unwrap every `SensitiveString` anywhere in a value, through an audited reveal.
 *
 * This is the whole of `sensitiveInput()`, and it is also what the extension
 * applies to the bound parameters of a tagged-template raw query.
 */
export function revealArgs(args: unknown, attribution: RevealAttribution = {}): unknown {
  return walk(args, '', buildRevealContext(attribution), new WeakSet());
}

/**
 * Unwrap the bound parameters of a raw operation.
 *
 * Only the tagged-template forms can be served here. `Prisma.sql`, `$queryRaw`,
 * `$executeRaw` and `$queryRawTyped` reach the hook as an object whose `values`
 * array Prisma copies by reference, so the instances in it are still intact.
 * The `Unsafe` variants and `$runCommandRaw` are copied value by value before
 * the hook runs and arrive already flattened; `assertNoUnwrapped` is what
 * catches those.
 *
 * @throws PrismaUnsafeStatementError If the statement text itself is a
 * `SensitiveString`. That argument is interpolated rather than bound, so
 * revealing it would write the value into SQL.
 */
export function revealRawArgs(args: unknown, attribution: RevealAttribution): unknown {
  if (Array.isArray(args) && isSensitiveString(args[0])) {
    throw new PrismaUnsafeStatementError(attribution.operation ?? 'A raw query');
  }

  if (!isSqlLike(args)) {
    return args;
  }

  const base = buildRevealContext(attribution);
  let changed = false;
  const values = args.values.map((value, index) => {
    const next = walk(value, `values.${index}`, base, new WeakSet());
    if (next !== value) changed = true;
    return next;
  });
  if (!changed) return args;

  // Rebuilt on the original prototype: `sql`, `text` and `inspect` are getters
  // over `strings` and `values`, so a plain object would lose them.
  return Object.assign(Object.create(Object.getPrototypeOf(args) as object) as object, args, {
    values,
  });
}
