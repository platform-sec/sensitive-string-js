import { SensitiveStringError } from './errors.js';
import { getGlobalSingleton } from './global-state.js';
import { snapshotStatelessRegExp } from './regexp.js';
import type {
  RevocationRegistry,
  RevocationScope,
  RevokeAuditDetails,
  SensitiveStringOptions,
} from './types.js';

/**
 * Describe a rejected option without disclosing it.
 */
function describeType(value: unknown): string {
  return value === null ? 'null' : typeof value;
}

/**
 * Why a value is refused, and where the refusal came from.
 *
 * `at` is epoch milliseconds rather than a Date, so a record can be shared and
 * cannot be moved by whoever reads it.
 */
export interface RevocationRecord {
  readonly reason: string;
  readonly at: number;
  readonly scope: RevocationScope;
  /** What an unreachable registry threw, for a record of scope `'unavailable'`. */
  readonly cause?: unknown;
}

/**
 * Raised when an operation needs the raw value of a revoked instance.
 *
 * `scope` says which of the four revocation sources refused, and separates a
 * value somebody revoked from one whose registry could not be reached: the
 * first is permanent and the caller fetches a new secret, the second may clear
 * and the caller may retry.
 *
 * `reason` and `label` are developer-supplied text and appear in the message.
 * Neither may carry any part of the protected value.
 */
export class RevokedSensitiveValueError extends SensitiveStringError {
  override readonly name = 'RevokedSensitiveValueError';
  override readonly code = 'revoked-value';

  readonly scope: RevocationScope;

  constructor(
    readonly reason: string,
    readonly revokedAt: Date,
    readonly label?: string,
    scope: RevocationScope = 'instance',
    cause?: unknown
  ) {
    const named = label !== undefined ? ` '${label}'` : '';
    const message =
      scope === 'unavailable'
        ? `Sensitive value${named} cannot be read: ${reason}`
        : `Sensitive value${named} was revoked at ${revokedAt.toISOString()}: ${reason}`;

    super(message, cause === undefined ? undefined : { cause });
    this.scope = scope;
  }
}

/**
 * A value's own revocation state, shared by reference between a value and
 * everything derived from it.
 *
 * `label` is the label the owning value was constructed with, which is what
 * label and pattern revocation match. A derived value is matched against the
 * labels of the values it came from rather than against the label the
 * derivation gave it, because no value was ever constructed under that one.
 */
export interface RevocationCell {
  /**
   * The revocation observed for this value. Latched: assigned once and never
   * cleared, so pruning the entry that produced it cannot bring the value back.
   */
  record: RevocationRecord | undefined;
  /**
   * The generation of the process-global lists at which this cell was last
   * found clean, or `-1` when it has never been checked. Comparing it is what
   * keeps a read that revokes nothing from walking the pattern list.
   */
  generation: number;
  readonly label: string | undefined;
  readonly registry: RevocationRegistry | undefined;
}

/** The part of a value's shared state this module reads and writes. */
export interface RevocationHolder {
  readonly revocation: RevocationCell;
}

/**
 * The process-global label and pattern lists.
 *
 * `generation` increments on every change. A value that has already looked and
 * found nothing compares one integer instead of searching again, which is what
 * the overwhelming majority of reads in a process that never revokes anything
 * pay for this feature.
 *
 * The Symbol.for()-backed singleton keeps a revocation visible when an
 * application loads more than one physical copy of core. Like the policy
 * registry, it is mutable process-global state: it protects against a stale
 * secret and a misconfiguration, not against code already executing in the
 * process, which can revoke anything or prune anything.
 */
interface GlobalRevocations {
  readonly labels: Map<string, RevocationRecord>;
  readonly patterns: { readonly pattern: RegExp; readonly record: RevocationRecord }[];
  generation: number;
}

const revocations = getGlobalSingleton<GlobalRevocations>('revocations', () => ({
  labels: new Map(),
  patterns: [],
  generation: 0,
}));

function requireLabel(value: unknown, operation: string): string {
  if (typeof value !== 'string') {
    throw new TypeError(`${operation}: label must be a string, received ${describeType(value)}`);
  }

  if (value.length === 0) {
    throw new RangeError(
      `${operation}: label must not be empty; a value with no label cannot be revoked by label`
    );
  }

  return value;
}

export function requireReason(value: unknown, operation: string): string {
  if (typeof value !== 'string') {
    throw new TypeError(`${operation}: reason must be a string, received ${describeType(value)}`);
  }

  return value;
}

/**
 * Read the quantifier at `index`, or `undefined` when there is none.
 *
 * `unbounded` marks the quantifiers that admit more than one repetition, which
 * are the ones that turn an ambiguous group into exponential backtracking. `?`
 * is a quantifier but not an unbounded one: it admits a single repetition and
 * cannot multiply the work inside the group it follows.
 */
function readQuantifier(
  source: string,
  index: number
): { unbounded: boolean; end: number } | undefined {
  const char = source[index];

  if (char === '*' || char === '+') {
    return { unbounded: true, end: index };
  }

  if (char === '?') {
    return { unbounded: false, end: index };
  }

  if (char !== '{') {
    return undefined;
  }

  const close = source.indexOf('}', index);

  if (close < 0) {
    return undefined;
  }

  const body = source.slice(index + 1, close);
  const bounds = /^(\d+)(,(\d*))?$/.exec(body);

  if (bounds === null) {
    // Not a quantifier at all: a literal brace, which JavaScript permits.
    return undefined;
  }

  const [, minimum, comma, maximum] = bounds;
  const upper = comma === undefined ? Number(minimum) : maximum === '' ? Infinity : Number(maximum);

  return { unbounded: upper > 1, end: close };
}

/**
 * Whether a pattern applies a quantifier admitting more than one repetition
 * (`*`, `+`, or a `{...}` form whose upper bound is above one) to a group that
 * can already match the same input more than one way.
 *
 * This is the nested-quantifier heuristic, and it is deliberately strict: it
 * rejects `(a+)+`, `(a*)*`, `(a|b)+`, and anything that nests them, including
 * shapes that happen to be safe because their alternatives are disjoint. A
 * pattern kept in a process-global list is tested against every label a value
 * carries, on a thread that cannot be interrupted, so a false rejection with a
 * message and an easy rewrite is the right trade against a pattern that hangs
 * the process on the first read after somebody revokes something.
 *
 * It is a heuristic and not a decision procedure. It says nothing about
 * backtracking that arises between groups rather than inside one.
 */
function nestsQuantifiers(source: string): boolean {
  // One frame per open group, plus an implicit outermost frame for the pattern
  // itself. `ambiguous` records that the frame's body can match the same input
  // in more than one way, which is a quantifier or an alternation inside it.
  const stack: { ambiguous: boolean }[] = [{ ambiguous: false }];
  let inClass = false;

  for (let index = 0; index < source.length; index++) {
    const char = source[index];

    if (char === '\\') {
      index++;
      continue;
    }

    if (inClass) {
      if (char === ']') {
        inClass = false;
      }
      continue;
    }

    if (char === '[') {
      inClass = true;
      continue;
    }

    const frame = stack[stack.length - 1];

    if (frame === undefined) {
      // Unbalanced source. The RegExp constructor already accepted it, so this
      // is a shape the scanner does not model; refuse rather than guess.
      return true;
    }

    if (char === '(') {
      stack.push({ ambiguous: false });
      index = skipGroupPrefix(source, index);
      continue;
    }

    if (char === ')') {
      if (stack.length === 1) {
        return true;
      }

      stack.pop();
      const parent = stack[stack.length - 1];

      if (parent === undefined) {
        return true;
      }

      const quantifier = readQuantifier(source, index + 1);

      if (quantifier !== undefined) {
        if (quantifier.unbounded && frame.ambiguous) {
          return true;
        }

        // A repeated group is itself a repetition in whatever contains it.
        parent.ambiguous = true;
        index = quantifier.end;
      }

      // A group whose body is ambiguous makes its container ambiguous too, so
      // `((a+))+` is caught at the outer quantifier.
      parent.ambiguous ||= frame.ambiguous;
      continue;
    }

    if (char === '|') {
      frame.ambiguous = true;
      continue;
    }

    const quantifier = readQuantifier(source, index);

    if (quantifier !== undefined) {
      frame.ambiguous = true;
      index = quantifier.end;
    }
  }

  return false;
}

/**
 * Move past `(?:`, `(?=`, `(?!`, `(?<=`, `(?<!`, and `(?<name>`.
 *
 * Returns the index of the last character of the prefix, which the scanner's
 * own increment steps off. Without this the `?` of `(?:` reads as a quantifier
 * and every non-capturing group looks ambiguous.
 */
function skipGroupPrefix(source: string, open: number): number {
  if (source[open + 1] !== '?') {
    return open;
  }

  const marker = source[open + 2];

  if (marker !== '<') {
    // (?: (?= (?!
    return open + 2;
  }

  if (source[open + 3] === '=' || source[open + 3] === '!') {
    return open + 3;
  }

  const close = source.indexOf('>', open + 3);
  return close < 0 ? open + 2 : close;
}

/**
 * Revoke every value constructed under a label, in this process.
 *
 * The first revocation of a label wins: a second call leaves the original
 * reason and timestamp in place, because a revocation is a fact that already
 * happened and re-stating it does not change when it did.
 *
 * @throws TypeError If `label` or `reason` is not a string.
 * @throws RangeError If `label` is empty.
 */
export function revokeByLabel(label: string, reason: string): void {
  const key = requireLabel(label, 'revokeByLabel');
  const why = requireReason(reason, 'revokeByLabel');

  if (revocations.labels.has(key)) {
    return;
  }

  revocations.labels.set(key, Object.freeze({ reason: why, at: Date.now(), scope: 'label' }));
  revocations.generation++;
}

/**
 * Revoke every value whose construction label matches a pattern, in this
 * process.
 *
 * The pattern is copied out of the caller's RegExp, so mutating theirs
 * afterwards changes nothing, and the copy drops `g` and `y`, which would
 * otherwise make it match every other time it was consulted.
 *
 * @throws TypeError If `pattern` is not a regular expression, if `reason` is
 *   not a string, or if the pattern nests quantifiers.
 */
export function revokeByPattern(pattern: RegExp, reason: string): void {
  const why = requireReason(reason, 'revokeByPattern');
  const compiled = snapshotStatelessRegExp(pattern, 'revokeByPattern');

  if (nestsQuantifiers(compiled.source)) {
    throw new TypeError(
      `revokeByPattern: /${compiled.source}/ applies an unbounded quantifier to a group that ` +
        'can match the same input more than one way, which backtracks exponentially. ' +
        'Rewrite it without the nested quantifier.'
    );
  }

  revocations.patterns.push({
    pattern: compiled,
    record: Object.freeze({ reason: why, at: Date.now(), scope: 'pattern' }),
  });
  revocations.generation++;
}

/**
 * Drop label and pattern revocations recorded before a cutoff, and report how
 * many were dropped.
 *
 * The lists hold strong references and grow for the life of the process, so
 * something has to be able to shrink them. Dropping an entry while a value it
 * matches is still reachable would bring that value back, so this is only safe
 * once every instance that could match has been collected: after a rotation has
 * drained, after the request that held the value has finished, at a point where
 * the process no longer holds a reference to anything constructed under the
 * label. A value that has already been refused stays refused whatever is
 * pruned, because the refusal is latched onto the value when it is observed.
 *
 * @param olderThan - A Date or epoch milliseconds. Entries recorded strictly
 *   before it are dropped.
 */
export function pruneRevocations(olderThan: Date | number): number {
  const cutoff = typeof olderThan === 'number' ? olderThan : olderThan.getTime();

  if (!Number.isFinite(cutoff)) {
    throw new RangeError('pruneRevocations: olderThan must be a valid Date or a finite number');
  }

  let dropped = 0;

  for (const [label, record] of revocations.labels) {
    if (record.at < cutoff) {
      revocations.labels.delete(label);
      dropped++;
    }
  }

  for (let index = revocations.patterns.length - 1; index >= 0; index--) {
    const entry = revocations.patterns[index];

    if (entry !== undefined && entry.record.at < cutoff) {
      revocations.patterns.splice(index, 1);
      dropped++;
    }
  }

  if (dropped > 0) {
    revocations.generation++;
  }

  return dropped;
}

/** How many label and pattern revocations the process is holding. */
export function revocationCount(): { labels: number; patterns: number } {
  return { labels: revocations.labels.size, patterns: revocations.patterns.length };
}

/**
 * A revocation list held in this process, for callers who want a scope smaller
 * than the whole process, and the shape a store-backed registry implements.
 */
export class RevocationList implements RevocationRegistry {
  readonly #entries = new Map<string, RevocationRecord>();

  /**
   * Revoke a label. The first revocation of a label wins, as it does globally.
   *
   * @throws TypeError If `label` or `reason` is not a string.
   * @throws RangeError If `label` is empty.
   */
  revoke(label: string, reason: string): void {
    const key = requireLabel(label, 'RevocationList.revoke');
    const why = requireReason(reason, 'RevocationList.revoke');

    if (!this.#entries.has(key)) {
      this.#entries.set(key, Object.freeze({ reason: why, at: Date.now(), scope: 'registry' }));
    }
  }

  isRevoked(label: string | undefined): boolean {
    return label !== undefined && this.#entries.has(label);
  }

  getReason(label: string): string | undefined {
    return this.#entries.get(label)?.reason;
  }

  /** When a label was revoked, or `undefined` when it was not. */
  revokedAt(label: string): Date | undefined {
    const at = this.#entries.get(label)?.at;
    return at === undefined ? undefined : new Date(at);
  }

  /** Drop entries recorded before a cutoff. The caveat on {@link pruneRevocations} applies. */
  prune(olderThan: Date | number): number {
    const cutoff = typeof olderThan === 'number' ? olderThan : olderThan.getTime();
    let dropped = 0;

    for (const [label, record] of this.#entries) {
      if (record.at < cutoff) {
        this.#entries.delete(label);
        dropped++;
      }
    }

    return dropped;
  }

  get size(): number {
    return this.#entries.size;
  }
}

/**
 * Build the revocation state for a newly constructed value.
 *
 * @throws TypeError If `revocationRegistry` is not an object with an `isRevoked` method.
 */
export function planRevocation(
  options: SensitiveStringOptions | undefined,
  label: string | undefined
): RevocationCell {
  const registry = options?.revocationRegistry;

  if (registry !== undefined) {
    if (typeof registry !== 'object' || registry === null) {
      throw new TypeError(
        `SensitiveString: revocationRegistry must be an object, received ${describeType(registry)}`
      );
    }

    if (typeof registry.isRevoked !== 'function') {
      throw new TypeError('SensitiveString: revocationRegistry must have an isRevoked method');
    }
  }

  return { record: undefined, generation: -1, label, registry };
}

/**
 * Search the process-global lists for this cell, and cache a clean answer
 * against the generation it was taken at.
 *
 * Only ever called when the generation has moved, so a cell that has looked
 * once does not search again until something is revoked or pruned. The
 * comparison that decides that is inline at both call sites rather than here,
 * so the common case reaches no call at all.
 */
function searchGlobal(cell: RevocationCell, generation: number): RevocationRecord | undefined {
  const { label } = cell;

  if (label !== undefined) {
    const byLabel = revocations.labels.get(label);

    if (byLabel !== undefined) {
      return byLabel;
    }

    for (const { pattern, record } of revocations.patterns) {
      if (pattern.test(label)) {
        return record;
      }
    }
  }

  cell.generation = generation;
  return undefined;
}

/**
 * Ask an external registry, failing closed.
 *
 * A registry that throws is a store that could not be reached, and a value
 * whose revocation cannot be checked is not one to hand out. So is a registry
 * that answers with anything but a boolean: an `async isRevoked` returns a
 * Promise, which is truthy and would revoke everything if truthiness were the
 * test, and is not `true`, so it would revoke nothing if strict equality were.
 * Refusing the answer catches the mistake instead of quietly picking one of
 * those two failures.
 *
 * Neither refusal is latched. Both describe the registry rather than the value,
 * and a store that comes back must be able to answer again.
 */
function registryRevocation(cell: RevocationCell): RevocationRecord | undefined {
  const { registry } = cell;

  if (registry === undefined) {
    return undefined;
  }

  let answer: unknown;

  try {
    answer = registry.isRevoked(cell.label);
  } catch (cause) {
    return {
      reason: 'the revocation registry is unreachable',
      at: Date.now(),
      scope: 'unavailable',
      cause,
    };
  }

  if (typeof answer !== 'boolean') {
    return {
      reason:
        `the revocation registry answered with ${describeType(answer)} rather than a boolean; ` +
        'it must answer synchronously',
      at: Date.now(),
      scope: 'unavailable',
    };
  }

  if (!answer) {
    return undefined;
  }

  let reason: string | undefined;

  try {
    reason = cell.label === undefined ? undefined : registry.getReason?.(cell.label);
  } catch {
    // A registry that can say "revoked" but not why still said "revoked".
    reason = undefined;
  }

  return {
    reason: typeof reason === 'string' ? reason : 'revoked by the registry',
    at: Date.now(),
    scope: 'registry',
  };
}

/**
 * The revocation that refuses a read of these states, or `undefined`.
 *
 * A definite revocation is latched onto the cell that produced it, so a value
 * that has once been refused stays refused even if the entry behind it is
 * pruned. An unreachable registry is not latched: it describes the store.
 */
export function revocationInForce(
  states: readonly RevocationHolder[]
): RevocationRecord | undefined {
  for (const state of states) {
    const cell = state.revocation;

    if (cell.record !== undefined) {
      return cell.record;
    }

    // Read per state rather than once for the walk. A registry consulted for an
    // earlier state is caller code, and it is free to revoke something; a
    // generation hoisted out of the loop would let a later state cache that
    // stale number and skip the search that would have found it.
    const { generation } = revocations;

    // Both guards are inline. A value that has looked once and was given no
    // registry leaves this check having compared two integers and called
    // nothing, which is what every read in a process that revokes nothing pays.
    if (cell.generation !== generation) {
      const global = searchGlobal(cell, generation);

      if (global !== undefined) {
        cell.record = global;
        return global;
      }
    }

    if (cell.registry !== undefined) {
      const external = registryRevocation(cell);

      if (external !== undefined) {
        if (external.scope !== 'unavailable') {
          cell.record = external;
        }

        return external;
      }
    }
  }

  return undefined;
}

/**
 * The revocation an inspection can see.
 *
 * Inspection observes and does not decide: it never calls out to an external
 * registry, because a log line must not make a network call, and it never
 * latches, because a value that was only ever printed has not been used.
 */
export function observedRevocation(
  states: readonly RevocationHolder[]
): RevocationRecord | undefined {
  for (const state of states) {
    const cell = state.revocation;

    if (cell.record !== undefined) {
      return cell.record;
    }

    const { generation } = revocations;

    if (cell.generation !== generation) {
      const global = searchGlobal(cell, generation);

      if (global !== undefined) {
        return global;
      }
    }
  }

  return undefined;
}

/**
 * Revoke every state a value shares, and report the record written, or
 * `undefined` when every one of them was already revoked.
 *
 * Revocation runs along derivation edges in both directions. A derivative
 * carries the material of the values it was built from, so a compromised
 * substring is a compromised secret, and refusing to revoke through the handle
 * a caller happens to be holding would fail open in exactly the incident this
 * feature exists for. That is the opposite of `renew()`, which refuses on a
 * derivative: refusing to extend a lifetime fails closed, refusing to end one
 * does not.
 */
export function revokeStates(
  states: readonly RevocationHolder[],
  reason: string,
  scope: RevocationScope = 'instance'
): RevocationRecord | undefined {
  let written: RevocationRecord | undefined;

  for (const state of states) {
    if (state.revocation.record !== undefined) {
      continue;
    }

    written ??= Object.freeze({ reason, at: Date.now(), scope });
    state.revocation.record = written;
  }

  return written;
}

/** The audit record for a revocation that took effect. */
export function revokeAuditDetails(record: RevocationRecord): RevokeAuditDetails {
  return Object.freeze({
    operation: 'revoke' as const,
    reason: record.reason,
    revokedAt: new Date(record.at).toISOString(),
    scope: record.scope,
  });
}
