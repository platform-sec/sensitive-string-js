import { createChildContext, getCurrentRevealContext } from '@platform-sec/sensitive-string-core';
import type {
  RevealContext,
  SensitiveString,
  SensitivityClass,
} from '@platform-sec/sensitive-string-core';
import { PrismaCyclicArgumentError, PrismaUnsafeStatementError } from './errors.js';
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
 *
 * This does not use `buildWriteContext` from `sensitive-data`, and that is a
 * deliberate divergence rather than an oversight. The shared builder is per
 * column: it carries a `table`, a `column`, and one of six `WriteOperation`
 * members. This one is per operation, built once for a whole `create` call, and
 * its `path` is a position in a nested argument object rather than a column,
 * while its `operation` is Prisma's own free-form name. Filling the shared
 * shape would mean reporting `'unknown'` for an operation this hook actually
 * knows. What is shared is the precedence rule above and the `sink` tag, so an
 * audit sink can still tell which package produced a record.
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
      sink: 'prisma',
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
 * Passing the context is all of it. Core hands the same context to the policy's
 * `checkRevealAllowed` and to `auditReveal` as its third argument, so a sink
 * reads the model, the operation and the argument path from what it is given.
 *
 * This used to install the context ambiently as well, one AsyncLocalStorage
 * entry per sensitive value, because the hook was called with the value and the
 * operation and nothing else: without the install, the tags reached no sink.
 * Core's hook now carries the context, and the entry went with the workaround.
 */
function revealAt(value: SensitiveString<SensitivityClass>, ctx: RevealContext): string {
  return value.reveal(ctx);
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
function walk(value: unknown, path: string, base: RevealContext, done: Memo): unknown {
  if (isSensitiveString(value)) {
    return revealAt(value, withPath(base, path));
  }

  if (typeof value !== 'object' || value === null) {
    return value;
  }

  // A container reached twice must produce the same result both times. The memo
  // is what makes that true: a `data` object that names one nested record under
  // two keys used to be rebuilt on the first visit and returned by identity on
  // the second, which left half the input still wrapped.
  const memoized = done.get(value);
  if (memoized !== undefined) {
    // Reached again while its own rebuild is still running, which is a cycle.
    // There is no answer here: the rebuild is unfinished, so the only reference
    // available is the pre-walk one, and returning that hands back a graph
    // still holding live instances with nothing to say so. Prisma cannot
    // serialise a cycle either, and its own argument copy recurses until the
    // stack ends, so refusing is both earlier and clearer.
    if (memoized.pending) {
      throw new PrismaCyclicArgumentError(path);
    }
    return memoized.result;
  }

  const entry: MemoEntry = { result: value, pending: true };
  done.set(value, entry);

  if (Array.isArray(value)) {
    let changed = false;
    const mapped = value.map((item, index) => {
      const next = walk(item, join(path, String(index)), base, done);
      if (next !== item) changed = true;
      return next;
    });
    entry.result = changed ? mapped : value;
    entry.pending = false;
    return entry.result;
  }

  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    // Any other class instance, `Prisma.Sql` included when it is nested rather
    // than the whole argument. Returned untouched, and not a container this
    // walk descends into, so it can never be part of a cycle it sees.
    entry.pending = false;
    return value;
  }

  const source = value as Record<string, unknown>;
  let changed = false;
  const entries = Object.entries(source).map<[string, unknown]>(([key, item]) => {
    const next = walk(item, join(path, key), base, done);
    if (next !== item) changed = true;
    return [key, next];
  });

  entry.result = changed ? rebuildObject(source, entries) : value;
  entry.pending = false;
  return entry.result;
}

/**
 * What the walk has produced for a container, or that it is still producing it.
 *
 * A `Map` rather than a `WeakSet` because the walk rebuilds rather than reads:
 * knowing an object has been seen is not enough, the result has to come back so
 * every reference to it agrees. `pending` is what separates the two ways an
 * object is reached twice: a second reference to a finished subtree gets the
 * result, and a reference reached from inside its own rebuild is a cycle.
 */
interface MemoEntry {
  result: unknown;
  pending: boolean;
}

type Memo = Map<object, MemoEntry>;

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
  return walk(args, '', buildRevealContext(attribution), new Map());
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
  // One memo across every parameter, so a container bound at two positions is
  // rebuilt once. An instance bound twice is still two reveals: the walk
  // reveals a leaf before it consults the memo, and two bindings are two reads.
  const done: Memo = new Map();
  let changed = false;
  const values = args.values.map((value, index) => {
    const next = walk(value, `values.${index}`, base, done);
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
