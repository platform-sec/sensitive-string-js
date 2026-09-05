import type { SensitiveStringOptions } from './types.js';

/**
 * Describe a rejected option without disclosing it.
 */
function describeType(value: unknown): string {
  return value === null ? 'null' : typeof value;
}

/**
 * Raised when a value has been exposed as many times as it is allowed to be.
 *
 * The condition is permanent: nothing resets the count, so a caller that sees
 * this fetches a fresh secret rather than retrying.
 */
export class RevealLimitExceededError extends Error {
  override readonly name = 'RevealLimitExceededError';

  constructor(
    /** The lifetime limit that was reached. */
    readonly limit: number,
    /** Which attempt this was, counting from one. Always greater than `limit`. */
    readonly attempts: number,
    readonly label?: string
  ) {
    super(
      `Sensitive value${label !== undefined ? ` '${label}'` : ''} has been revealed ` +
        `${limit} time${limit === 1 ? '' : 's'}, which is its limit`
    );
  }
}

/**
 * Raised when a value has been exposed too often within its window.
 *
 * The condition is temporary, and `retryAfter` says how temporary, so a caller
 * that means to continue can back off rather than fetch a new secret.
 */
export class RevealRateLimitError extends Error {
  override readonly name = 'RevealRateLimitError';

  constructor(
    /** Milliseconds until the window has room again. Always positive. */
    readonly retryAfter: number,
    /** The number of reveals the window allows. */
    readonly windowLimit: number,
    readonly label?: string
  ) {
    super(
      `Sensitive value${label !== undefined ? ` '${label}'` : ''} exceeded its rate limit of ` +
        `${windowLimit} reveal${windowLimit === 1 ? '' : 's'}; retry in ${retryAfter}ms`
    );
  }
}

/**
 * The sliding window, when one is configured.
 *
 * `times` holds the charge times still inside the window, oldest at `head`.
 * Entries ahead of `head` are dead and are dropped in place, which keeps the
 * common case free of allocation; the array is compacted once its dead prefix
 * is at least as large as what remains, so it holds at most twice the limit
 * however long the value lives and however much traffic passes through it.
 */
export interface RevealRate {
  readonly window: number;
  readonly limit: number;
  readonly times: number[];
  head: number;
}

/**
 * The limits on how often a value may be exposed.
 *
 * Shared by reference between a value and everything derived from it, so a
 * substring of a single-use token spends the same budget the token has. A value
 * with neither limit has no budget object at all, which is what keeps the gate
 * free for the values that configure nothing.
 */
export interface RevealBudget {
  /** Lifetime limit, or `undefined` when the number of reveals is unbounded. */
  readonly maxReveals: number | undefined;
  /** Sliding window, or `undefined` when there is no rate limit. */
  readonly rate: RevealRate | undefined;
}

/**
 * The part of a value's shared state this module reads and writes.
 *
 * Every value counts its reveals, whether or not it limits them, so
 * `revealCount` answers honestly for a value that was constructed with no
 * options at all.
 */
export interface RevealCounted {
  reveals: number;
  readonly budget: RevealBudget | undefined;
}

/** A state that carries limits, which is the only kind the check walks. */
export interface RevealConstrained extends RevealCounted {
  readonly budget: RevealBudget;
}

/**
 * Validate a lifetime limit.
 *
 * Zero is a valid limit and means the value may never be exposed, which is the
 * most conservative budget a caller can ask for. Testing the option for
 * truthiness would turn it into no limit at all.
 */
function requireMaxReveals(value: unknown): number | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (typeof value !== 'number') {
    throw new TypeError(
      `SensitiveString: maxReveals must be a number, received ${describeType(value)}`
    );
  }

  if (!Number.isInteger(value) || value < 0) {
    throw new RangeError('SensitiveString: maxReveals must be a non-negative integer');
  }

  return value;
}

/**
 * Validate the window length.
 *
 * Zero is rejected rather than read as "already elapsed". A zero-length window
 * holds no timestamps and so can never be full, which is the least restrictive
 * reading of the most restrictive-looking configuration. `ttl: 0` accepts zero
 * for the opposite reason: there, zero denies everything.
 */
function requireWindow(value: unknown): number | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (typeof value !== 'number') {
    throw new TypeError(
      `SensitiveString: revealWindow must be a number of milliseconds, received ${describeType(value)}`
    );
  }

  if (!Number.isFinite(value) || value <= 0) {
    throw new RangeError('SensitiveString: revealWindow must be a positive, finite number');
  }

  return value;
}

/**
 * Validate the per-window limit.
 *
 * One is the floor. A window that admits nothing describes a value that can
 * never be exposed, which `maxReveals: 0` says plainly, and it would raise a
 * rate-limit error whose `retryAfter` no waiting could satisfy.
 */
function requireWindowLimit(value: unknown): number | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (typeof value !== 'number') {
    throw new TypeError(
      `SensitiveString: maxRevealsPerWindow must be a number, received ${describeType(value)}`
    );
  }

  if (!Number.isInteger(value) || value < 1) {
    throw new RangeError(
      'SensitiveString: maxRevealsPerWindow must be a positive integer; ' +
        'use maxReveals: 0 for a value that may never be revealed'
    );
  }

  return value;
}

/**
 * Build the reveal budget for a newly constructed value, or `undefined` when it
 * has no limits.
 *
 * @throws TypeError If an option has the wrong type.
 * @throws RangeError If a limit is out of range.
 * @throws Error If only one half of the rate limit is given.
 */
export function planRevealBudget(
  options: SensitiveStringOptions | undefined
): RevealBudget | undefined {
  const maxReveals = requireMaxReveals(options?.maxReveals);
  const window = requireWindow(options?.revealWindow);
  const limit = requireWindowLimit(options?.maxRevealsPerWindow);

  // Either option alone configures no rate limit whatsoever, which is the
  // opposite of what somebody writing one of them meant.
  if ((window === undefined) !== (limit === undefined)) {
    throw new Error(
      'SensitiveString: revealWindow and maxRevealsPerWindow must be given together; ' +
        'one without the other is no rate limit at all'
    );
  }

  if (maxReveals === undefined && window === undefined) {
    return undefined;
  }

  return {
    maxReveals,
    rate:
      window === undefined || limit === undefined
        ? undefined
        : { window, limit, times: [], head: 0 },
  };
}

/**
 * Drop the charges that have left the window and report how many remain.
 */
function prune(rate: RevealRate, now: number): number {
  const { times } = rate;
  const cutoff = now - rate.window;
  let head = rate.head;

  // A charge at exactly the cutoff has left the window, matching expiry, where
  // a value is not usable at its own deadline.
  for (; head < times.length; head++) {
    const at = times[head];

    if (at === undefined || at > cutoff) {
      break;
    }
  }

  // Compacting when the dead prefix has grown to match what remains copies each
  // entry a constant number of times and bounds the array at twice the limit.
  if (head > 0 && head >= times.length - head) {
    times.splice(0, head);
    head = 0;
  }

  rate.head = head;
  return times.length - head;
}

/**
 * Decide whether every budget admits one more reveal, without charging any.
 *
 * Separating the decision from the charge is what lets the gate refuse before
 * it authorizes and audits, so a refusal is not recorded as a reveal, and lets
 * an audit hook that throws stop a reveal before it is counted.
 *
 * Every budget is checked before any is charged, so a derivative of two values
 * cannot spend one parent's budget on a read the other refused.
 *
 * @throws RevealLimitExceededError If a lifetime limit has been reached.
 * @throws RevealRateLimitError If a window is full.
 */
export function checkRevealBudget(
  states: readonly RevealConstrained[],
  label: string | undefined
): void {
  // The lifetime limit first. A value that is both exhausted and rate limited
  // should report the condition that waiting will not clear.
  for (const state of states) {
    const { maxReveals } = state.budget;

    if (maxReveals !== undefined && state.reveals >= maxReveals) {
      throw new RevealLimitExceededError(maxReveals, state.reveals + 1, label);
    }
  }

  let now = -1;
  let retryAfter = 0;
  let windowLimit = 0;

  for (const state of states) {
    const { rate } = state.budget;

    if (rate === undefined) {
      continue;
    }

    // Read at most once, and only when a window can actually refuse.
    if (now < 0) {
      now = Date.now();
    }

    if (prune(rate, now) < rate.limit) {
      continue;
    }

    // The oldest live charge is the one whose departure makes room. It is still
    // inside the window, so the wait is positive.
    const oldest = rate.times[rate.head] ?? now;
    const wait = oldest + rate.window - now;

    // The longest wait among the windows that refused, so a caller that honors
    // it is not refused again by a second window on the next attempt.
    if (wait > retryAfter) {
      retryAfter = wait;
      windowLimit = rate.limit;
    }
  }

  if (retryAfter > 0) {
    throw new RevealRateLimitError(retryAfter, windowLimit, label);
  }
}

/**
 * Charge one reveal against every state a value reads.
 *
 * Called only once {@link checkRevealBudget} has admitted the read and the
 * policy and audit hooks have let it through, so the count is of reveals that
 * reached the caller rather than of attempts.
 *
 * The window records this instant rather than the one the check read, because
 * the two are separated by however long a caller's audit hook takes. Dating a
 * charge from the check would let an audit hook slower than the window push
 * every entry out of it as it was written.
 */
export function chargeReveal(states: readonly RevealCounted[]): void {
  let now = -1;

  for (const state of states) {
    state.reveals++;

    const rate = state.budget?.rate;

    if (rate !== undefined) {
      // Read at most once, and only for a value that has a window.
      if (now < 0) {
        now = Date.now();
      }

      rate.times.push(now);
    }
  }
}

/**
 * Whether any of these states has spent its lifetime limit.
 */
export function isBudgetExhausted(states: readonly RevealConstrained[]): boolean {
  for (const state of states) {
    const { maxReveals } = state.budget;

    if (maxReveals !== undefined && state.reveals >= maxReveals) {
      return true;
    }
  }

  return false;
}

/**
 * The smallest number of reveals any of these states still allows, or
 * `undefined` when none of them limits the total.
 */
export function revealsRemaining(states: readonly RevealConstrained[]): number | undefined {
  let fewest: number | undefined;

  for (const state of states) {
    const { maxReveals } = state.budget;

    if (maxReveals === undefined) {
      continue;
    }

    const remaining = Math.max(0, maxReveals - state.reveals);

    if (fewest === undefined || remaining < fewest) {
      fewest = remaining;
    }
  }

  return fewest;
}
