import type {
  SensitivityClass,
  SensitivityPolicy,
  SensitiveStringOptions,
  SerializedSensitiveString,
  MaskOptions,
  HashAlgorithm,
  HashOptions,
  HmacOptions,
  RenewalOptions,
  RevealContext,
  RevealDetails,
} from './types.js';
import { constantTimeEquals } from './compare.js';
import { getPolicy, defaultCombineClasses, hasPolicy } from './policy.js';
import { getCurrentRevealContext } from './context.js';
import { isInsideRedaction, RevealDuringRedactionError } from './redaction-scope.js';
import { applyMask, maskAuditDetails, planMask } from './mask.js';
import {
  applyHash,
  applyHmac,
  hashAuditDetails,
  hashLabel,
  hmacAuditDetails,
  planHash,
  requireHmacKey,
} from './hash.js';
import { devMode, readDevInfo, recordCreation, recordReveal, type DevInfo } from './dev-mode.js';
import {
  ExpiredSensitiveValueError,
  expiredDeadline,
  planExpiry,
  planRenewal,
  renewAuditDetails,
  RenewalNotAllowedError,
  type ExpiryState,
} from './ttl.js';
import {
  chargeReveal,
  checkRevealBudget,
  isBudgetExhausted,
  planRevealBudget,
  revealsRemaining,
  unshareableBudgetOptions,
  type RevealBudget,
  type RevealConstrained,
} from './reveal-budget.js';
import {
  observedRevocation,
  planRevocation,
  requireReason,
  revocationInForce,
  revokeAuditDetails,
  RevokedSensitiveValueError,
  revokeStates,
  type RevocationCell,
  type RevocationRecord,
} from './revocation.js';
import {
  carriesCustomRestriction,
  checkEnvironmentRestrictions,
  deserializeRestrictions,
  NO_RESTRICTIONS,
  planRestrictions,
  serializeRestrictions,
  UnserializableRestrictionError,
  type ResolvedRestrictions,
} from './environment.js';
import { snapshotRegExp } from './regexp.js';
import { ClearedSensitiveValueError, hygiene, trackInstance } from './hygiene.js';

/**
 * Node.js custom inspect symbol for util.inspect() and console.log().
 */
const NODE_INSPECT_SYMBOL = Symbol.for('nodejs.util.inspect.custom');

/**
 * Name the kind of value the constructor refused, and nothing of its content:
 * the message may be logged, and an object or array can hold the secret that
 * was meant to be protected.
 */
function describeNonString(value: unknown): string {
  if (value === null || value === undefined) {
    return String(value);
  }

  if (value instanceof SensitiveString) {
    return 'a SensitiveString';
  }

  if (Array.isArray(value)) {
    return 'an array';
  }

  const type = typeof value;
  return type === 'object' ? 'an object' : `a ${type}`;
}

/**
 * The audit record every operation but `mask()` reports. Shared and frozen: it
 * is handed to caller-supplied audit hooks.
 */
const REVEAL_AUDIT_DETAILS: RevealDetails = Object.freeze({ operation: 'reveal' as const });

/**
 * How a caller uses the raw value determines authorization and auditing.
 * Safe reads only feed redaction or intentionally public metadata. Comparisons
 * are authorized but are not reveals. Exposing reads are authorized and audited.
 */
/**
 * Refuse a policy hook's answer unless it is the one the gate can act on.
 *
 * `checkRevealAllowed` denies by throwing, so its only meaningful return is
 * `undefined`. TypeScript accepts an `async` function where a `void`-returning
 * one is expected, and an `async` hook that throws after its first `await`
 * throws into a Promise nobody reads, after the gate has already handed the
 * raw value back: the hook fails open, silently, on exactly the reads it was
 * written to refuse. The declared type is `undefined`, which rejects the
 * `async` form at compile time; this is the same rule at runtime, for a hook
 * written in JavaScript or cast past the type. A Promise cannot deny a read
 * that has already returned, so returning one is treated as a denial, and so
 * is any other value: a hook that returns `false` meant to deny.
 */
function refuseHookReturn(returned: unknown, klass: SensitivityClass): void {
  if (returned === undefined) {
    return;
  }

  const why = isThenable(returned)
    ? 'a Promise. The hook must be synchronous: a Promise cannot deny a read that has already returned'
    : `${returned === null ? 'null' : `a ${typeof returned}`}. The hook denies by throwing and must return undefined`;

  throw new TypeError(`checkRevealAllowed for sensitivity class '${klass}' returned ${why}`);
}

function isThenable(value: unknown): boolean {
  return (
    (typeof value === 'object' || typeof value === 'function') &&
    value !== null &&
    typeof (value as { then?: unknown }).then === 'function'
  );
}

type RawValueAccess = 'safe' | 'compare' | 'expose';

/**
 * Shared by a value and all of its derivatives. Feature implementations add
 * constraint state (such as reveal counters) here rather than copying it.
 */
interface SensitiveStringState {
  readonly options: SensitiveStringOptions;
  readonly expiry: ExpiryState;
  /**
   * Exposures charged against this value. Monotonic, counted whether or not
   * the value limits them, so `revealCount` answers for every value.
   */
  reveals: number;
  /** The limits on those exposures, or undefined when there are none. */
  readonly budget: RevealBudget | undefined;
  /**
   * Whether this value has been revoked, and the label and registry that decide
   * it. Mutable, unlike everything else here that is not a counter: a revocation
   * arrives after construction by definition.
   */
  readonly revocation: RevocationCell;
  /**
   * Where this value may be read, or `undefined` when it may be read anywhere.
   *
   * Frozen at construction, unlike the revocation cell beside it: a restriction
   * is a property of the value, and the environment it is decided against is
   * the thing that moves.
   */
  readonly restrictions: readonly ResolvedRestrictions[] | undefined;
  /**
   * When the value this state belongs to was destroyed, epoch milliseconds, or
   * `undefined` while it still exists.
   *
   * Mutable and shared, like the revocation cell: an owner's `clear()` writes
   * it and every value derived from that owner reads it, which is how a clear
   * refuses a substring the caller cleared nothing on. A derivative never
   * writes it, because the state object it would write is the one its sources
   * are still using.
   */
  clearedAt: number | undefined;
}

/** A state that carries reveal limits. */
type ConstrainedState = SensitiveStringState & RevealConstrained;

function isConstrained(state: SensitiveStringState): state is ConstrainedState {
  return state.budget !== undefined;
}

/**
 * The shared empty array every unconstrained value points at, so a value that
 * configures no limits allocates nothing for the ones it does not have.
 */
const NO_BUDGETS: readonly ConstrainedState[] = Object.freeze([]);

/** The same, for a derivative between construction and adopting its sources. */
const NO_STATES: readonly SensitiveStringState[] = Object.freeze([]);

/**
 * The subset of these states that limits reveals.
 *
 * A filtered view of `#states` rather than a second source of truth: the state
 * objects are the same ones, so the two cannot disagree about a count. It
 * exists so the gate can dismiss the overwhelmingly common unconstrained case
 * with a length check instead of a walk.
 */
function constrainedStates(states: readonly SensitiveStringState[]): readonly ConstrainedState[] {
  let constrained: ConstrainedState[] | undefined;

  for (const state of states) {
    if (isConstrained(state)) {
      (constrained ??= []).push(state);
    }
  }

  return constrained ?? NO_BUDGETS;
}

/**
 * Every restriction set these states carry, flattened.
 *
 * The same shape as the constrained view above and for the same reason: the
 * gate dismisses the overwhelmingly common unrestricted case with a length
 * check instead of walking states that restrict nothing.
 */
function restrictedStates(
  states: readonly SensitiveStringState[]
): readonly ResolvedRestrictions[] {
  let restrictions: ResolvedRestrictions[] | undefined;

  for (const state of states) {
    if (state.restrictions !== undefined) {
      (restrictions ??= []).push(...state.restrictions);
    }
  }

  return restrictions ?? NO_RESTRICTIONS;
}

/**
 * Passed in place of options by `#derived`, which supplies the state of the
 * values the derivative came from instead of planning its own.
 *
 * Without it a derived value would be planned as a fresh one, and a class whose
 * policy sets `requireExpiration` would refuse to produce a substring of a value
 * that does have a deadline. The symbol is module-private and unreachable from
 * a caller, so the only way onto this path is from inside the class.
 */
const DERIVED_CONSTRUCTION = Symbol('SensitiveString.derived');

/**
 * Package-internal derivation of a value from one or more existing values.
 *
 * An operation that builds on protected values must retain the state of every
 * value it read, so a constraint such as a reveal counter is never dropped by
 * deriving from it. That logic lives in the private `SensitiveString.#derived`,
 * which is only reachable from inside the class body, so the class publishes it
 * here for the sibling modules that build derived values.
 *
 * This binding is deliberately absent from `index.ts`, and the package `exports`
 * map declares no deep entry, so it is not part of the published API.
 *
 * @internal
 */
export type DeriveSensitiveString = <D extends SensitivityClass>(
  value: string,
  klass: D,
  label: string | undefined,
  sources: readonly SensitiveString<SensitivityClass>[]
) => SensitiveString<D>;

/**
 * Assigned once, from the static block at the end of the class body.
 *
 * @internal
 */
export let deriveSensitiveString: DeriveSensitiveString;

/**
 * Package-internal serialization under a caller-described audit record.
 *
 * `serialize()` reads through the gate with the fixed `reveal` record, so a
 * sibling module that puts a value on the wire for a reason of its own, as
 * `toWorkerPayload()` does, could not say so in the audit log. This is the
 * same read with the details supplied, published the way `deriveSensitiveString`
 * is: absent from `index.ts` and unreachable through the package `exports` map.
 *
 * @internal
 */
export type SerializeSensitiveString = (
  value: SensitiveString<SensitivityClass>,
  ctx: RevealContext | undefined,
  details: RevealDetails
) => SerializedSensitiveString;

/**
 * Assigned once, from the static block at the end of the class body.
 *
 * @internal
 */
export let serializeSensitiveString: SerializeSensitiveString;

/**
 * Package-internal question: which of this value's constraints cannot be
 * shared with another isolate. Empty for a value that can cross.
 *
 * Reads nothing through the gate, so asking is not a reveal and is not
 * charged, audited, or refused by anything the gate enforces.
 *
 * @internal
 */
export type UnshareableConstraints = (
  value: SensitiveString<SensitivityClass>
) => readonly (keyof SensitiveStringOptions)[];

/**
 * Assigned once, from the static block at the end of the class body.
 *
 * @internal
 */
export let unshareableConstraints: UnshareableConstraints;

/**
 * Secure wrapper for sensitive string data.
 *
 * Features:
 * - Runtime encapsulation via ES2022 #private fields.
 * - Automatic redaction in `toString()`, `toJSON()`, and `util.inspect()`.
 * - Constant-time comparison for credentials.
 * - Audit hooks on access via `reveal()`.
 *
 * @typeParam C - Sensitivity class ('sensitive' | 'credential').
 *
 * @example
 * ```ts
 * const apiKey = new SensitiveString(process.env.API_KEY!, 'credential', 'api_key');
 * console.log(apiKey); // SensitiveString<credential:api_key> { [REDACTED:credential] }
 *
 * // Explicit access with audit context
 * const raw = apiKey.reveal({ name: 'api-call', reason: 'authenticating' });
 * ```
 */
/**
 * ISO 8601 renderings of deadlines, memoized.
 *
 * `serialize()` formatted one on every call, which cost more than the rest of
 * the method put together. A deadline is a plain number that already travels
 * on the wire in this form, so nothing secret is held here. Keyed by the
 * deadline itself, so a renewal misses and re-renders on its own.
 */
const isoDeadlines = new Map<number, string>();

function isoDeadline(deadline: number): string {
  let iso = isoDeadlines.get(deadline);

  if (iso === undefined) {
    iso = new Date(deadline).toISOString();

    // A service with many distinct deadlines must not grow this without bound.
    if (isoDeadlines.size >= 256) {
      isoDeadlines.clear();
    }

    isoDeadlines.set(deadline, iso);
  }

  return iso;
}

export class SensitiveString<C extends SensitivityClass = 'sensitive'> {
  /**
   * The raw value. Using ES2022 #private for true runtime encapsulation.
   * This field is inaccessible outside the class, even via reflection or type coercion.
   */
  #value: string;

  /**
   * State inherited from the values this instance was derived from. Multiple
   * sources are retained for concat so future constraints and counters remain
   * shared without dropping either parent.
   */
  #states: readonly SensitiveStringState[] = NO_STATES;

  /**
   * The states above that limit reveals, assigned only through `#adopt` so it
   * cannot drift from `#states`. Empty for a value with no limits, which is
   * how the gate skips the whole feature in one comparison.
   */
  #constrained: readonly ConstrainedState[] = NO_BUDGETS;

  /**
   * The restrictions of every state above, flattened, so the gate answers with
   * a length check on a value that has none.
   */
  #restrictions: readonly ResolvedRestrictions[] = NO_RESTRICTIONS;

  /**
   * This instance's own state, or undefined when it was derived from other
   * values. Only an owner may renew: a derivative shares its sources' state by
   * reference, so renewing through one would silently extend the lifetime of
   * the value it came from, and of every other derivative of it.
   */
  #own: SensitiveStringState | undefined;

  /**
   * This instance's own clear, epoch milliseconds, or `undefined`.
   *
   * Set on any instance, owner or derivative. The shared `clearedAt` beside it
   * says a value this one was built from was destroyed; this one says this
   * instance dropped its own copy of the plaintext, which is a separate fact
   * with a separate consequence: only the second releases anything.
   */
  #ownClearedAt: number | undefined;

  /**
   * The redacted rendering, taken by `clear()` from the live value immediately
   * before it is dropped, or `undefined` on a value that still has one.
   *
   * Retaining it discloses nothing the design had not already accepted: it is
   * the string the policy exists to emit in place of the value, so a copy of it
   * is what a log line would have held anyway.
   */
  #redaction: string | undefined;

  /**
   * The sensitivity classification for this value.
   */
  readonly klass: C;

  /**
   * Optional label for audit/compliance categorization.
   * Examples: 'api_key', 'email', 'ssn', 'session_token'
   */
  readonly label: string | undefined;

  /**
   * Create a new SensitiveString.
   *
   * @param value - The raw string value to protect
   * @param klass - The sensitivity classification ('credential' or 'sensitive')
   * @param label - Optional label for audit/compliance (e.g., 'api_key', 'email')
   * @param options - Shared options for access constraints and feature behavior
   * @throws Error If both `ttl` and `expiresAt` are given, if only one half of the rate limit is given, if a restriction set expresses no restriction, or if the class policy requires an expiration and neither is.
   * @throws TypeError If `value` is not a string, or an option has the wrong type.
   * @throws RangeError If `ttl` is negative, `expiresAt` is an invalid Date, a reveal limit is out of range, or a restriction list is empty or holds a pattern that is neither a literal name nor a prefix.
   */
  constructor(value: string, klass: C, label?: string, options?: SensitiveStringOptions) {
    // Anything but a string would still redact, and then fail far from here:
    // a number breaks `equals()` inside Buffer.from, and an instance wrapped
    // again reveals the inner instance instead of its value. Refusing at
    // construction keeps a wrong value from surviving long enough to be trusted.
    if (typeof value !== 'string') {
      throw new TypeError(
        `SensitiveString expects a string value; received ${describeNonString(value)}`
      );
    }

    this.#value = value;
    this.klass = klass;
    this.label = label;

    // Before the derived early return, so a substring of a value is tracked in
    // its own right. The guard is one property read when development mode is
    // off, which is what production pays for the feature.
    if (devMode.config.enabled) {
      recordCreation(this);
    }

    // Before the derived early return, and for the reason tracking exists: a
    // derivative of 13 characters or more pins its origin's whole backing
    // store, so it is the value a bulk clear most needs to reach, and it is
    // usually a local whose holder a caller cannot name. Registering after the
    // return would track origins only.
    //
    // Freezing goes here too, after the last own-property write and before
    // both returns, so an owner and a derivative are frozen alike. Every
    // assignment below this point is to a `#private` field, which `Object.freeze`
    // does not touch.
    if (hygiene.config.trackInstances) {
      trackInstance(this);
    }

    if (hygiene.config.freezeInstances) {
      Object.freeze(this);
    }

    if ((options as unknown) === DERIVED_CONSTRUCTION) {
      // #derived assigns the sources' state objects immediately after this
      // returns. Planning state here would be discarded, and a policy that
      // requires an expiration would reject a derivative that has one.
      this.#own = undefined;
      return;
    }

    const state: SensitiveStringState = {
      options: options ?? {},
      expiry: planExpiry(options, klass, getPolicy(klass)),
      reveals: 0,
      budget: planRevealBudget(options),
      revocation: planRevocation(options, label),
      restrictions: planRestrictions(options),
      clearedAt: undefined,
    };

    this.#own = state;
    this.#adopt([state]);
  }

  /**
   * Take on a set of shared states.
   *
   * The only assignment to `#states`, so the constrained view is never left
   * behind by a derivation that forgot it. A derivation that dropped the view
   * would hand back an unlimited copy of a value that was meant to be spent.
   */
  #adopt(
    states: readonly SensitiveStringState[],
    constrained?: readonly ConstrainedState[],
    restricted?: readonly ResolvedRestrictions[]
  ): void {
    this.#states = states;
    this.#constrained = constrained ?? constrainedStates(states);
    this.#restrictions = restricted ?? restrictedStates(states);
  }

  /**
   * Get the policy for this instance's sensitivity class.
   */
  private get policy(): SensitivityPolicy {
    return getPolicy(this.klass);
  }

  /**
   * The earliest deadline among the values this one was built from, or
   * undefined when none of them expires.
   *
   * Private on purpose: `serialize()` puts this on the wire, so it must not read
   * an `expiresAt` getter that a subclass could override.
   */
  #earliestDeadline(): number | undefined {
    let earliest: number | undefined;

    for (const state of this.#states) {
      const { deadline } = state.expiry;

      if (deadline !== undefined && (earliest === undefined || deadline < earliest)) {
        earliest = deadline;
      }
    }

    return earliest;
  }

  /**
   * The earliest deadline this value has passed, or undefined while it is live.
   *
   * Private on purpose: the gate must not route its decision through the public
   * `isExpired()`, which a subclass could override to lift it.
   */
  #expiredDeadline(notify: boolean): number | undefined {
    // Read at most once, and only when a state can actually expire. An
    // unconditional read cost more than the rest of the gate put together on a
    // value with no deadline, which is most of them.
    let now = -1;
    let earliest: number | undefined;

    // Every source state is checked rather than only the first match, so a
    // derivative of two expiring values fires both onExpire callbacks.
    for (const state of this.#states) {
      if (state.expiry.deadline === undefined) {
        continue;
      }

      if (now < 0) {
        now = Date.now();
      }

      const deadline = expiredDeadline(state.expiry, now, notify);

      if (deadline !== undefined && (earliest === undefined || deadline < earliest)) {
        earliest = deadline;
      }
    }

    return earliest;
  }

  /**
   * The earliest clear affecting this value: its own, or one that destroyed a
   * value it was derived from.
   *
   * Mirrors `#earliestDeadline`, and private for the same reason: the gate must
   * not route its decision through a public `isCleared` that a subclass could
   * override. Reporting the earliest rather than the most recent means an error
   * says when the value stopped being usable rather than when the last clear in
   * its lineage happened to run.
   */
  #clearedFlag(): number | undefined {
    let earliest = this.#ownClearedAt;

    for (const state of this.#states) {
      const { clearedAt } = state;

      if (clearedAt !== undefined && (earliest === undefined || clearedAt < earliest)) {
        earliest = clearedAt;
      }
    }

    return earliest;
  }

  /**
   * Refuse an operation that needs a value this process has destroyed.
   *
   * Written once because three callers need it: the gate, and the two `'safe'`
   * readers that are exempt from the gate and have nothing to fall back on.
   */
  #refuseIfCleared(): void {
    const cleared = this.#clearedFlag();

    if (cleared !== undefined) {
      throw new ClearedSensitiveValueError(new Date(cleared), new Date(), this.label);
    }
  }

  /**
   * The sole accessor for #value.
   *
   * Feature-level checks such as expiry, revocation, and environment
   * restrictions belong here so no operation can bypass them. Redaction and
   * documented metadata reads stay available even when access is denied.
   */
  #readRawValue(
    access: RawValueAccess,
    ctx?: RevealContext,
    details: RevealDetails = REVEAL_AUDIT_DETAILS
  ): string {
    if (access === 'safe') {
      return this.#value;
    }

    // A walk that is running a toJSON() on the object's behalf gets no raw
    // value: whatever the toJSON() returned would be logged as it is. Refused
    // before the deadline check, the policy and the audit hook, because a log
    // line asking is not an access and must fire none of them.
    if (access === 'expose' && isInsideRedaction()) {
      throw new RevealDuringRedactionError(this.klass, this.label);
    }

    // First of the lifecycle checks, ahead of revocation as well as expiry.
    // Two reasons, and neither is that a destruction outranks a revocation.
    // It is the only one of the three that reads a plain field: it cannot
    // fail, cannot allocate, and cannot call out of the process, where the
    // revocation check may consult an external registry. Asking a registry
    // about a value this process has already destroyed would let a registry
    // outage decide which refusal a destroyed value reports. And a lapse
    // invites a fresh fetch and a retry where a destruction says this code
    // holds a reference past its own teardown, which is the more useful thing
    // to be told when both are true.
    this.#refuseIfCleared();

    // Ahead of the deadline, because when both refuse, the revocation is the
    // one worth reporting: expiry invites a renewal and a retry, and a revoked
    // value must never look renewable. It is also the check that can consult
    // something outside the process, so a caller sees the reason that came from
    // there rather than a lapsed clock.
    const revoked = revocationInForce(this.#states);
    if (revoked !== undefined) {
      throw new RevokedSensitiveValueError(
        revoked.reason,
        new Date(revoked.at),
        this.label,
        revoked.scope,
        revoked.cause
      );
    }

    // Before authorization and before the audit hook: a denied read is not a
    // reveal, and must not be logged as one.
    const expired = this.#expiredDeadline(true);
    if (expired !== undefined) {
      throw new ExpiredSensitiveValueError(new Date(expired), new Date(), this.label);
    }

    // After the deadline and before the budget, which is the order the
    // restriction was specified in, and before the policy hook and the audit
    // hook for the reason the two above are: a refused read is not a reveal.
    // A comparison is checked too. Rule R2 names `equals()` as a read for the
    // purposes of expiry, revocation and restrictions alike: a value that may
    // not be read in this region must not still be able to answer whether a
    // guess matches it here.
    if (this.#restrictions.length !== 0) {
      checkEnvironmentRestrictions(this.#restrictions, this.label);
    }

    // The same rule one step later, and the same reason the budget is decided
    // here but charged below: a refusal is not a reveal, and neither is a read
    // an audit hook stopped. A comparison is not charged and so is not refused
    // by a spent budget either; it reads the value without disclosing it, and
    // it is the operation the library wants used in place of a reveal.
    if (access === 'expose' && this.#constrained.length !== 0) {
      checkRevealBudget(this.#constrained, this.label);
    }

    const effectiveCtx = ctx ?? getCurrentRevealContext();
    // `access` is narrowed to 'compare' | 'expose' by the early return above, so
    // a policy is never asked to authorize a read that only feeds redaction.
    refuseHookReturn(this.policy.checkRevealAllowed?.(effectiveCtx, this, access), this.klass);

    if (access === 'expose') {
      effectiveCtx?.auditReveal?.(this, details, effectiveCtx);

      // After the audit hook, which is free to throw and stop the reveal: what
      // is counted, charged, and recorded is what actually reached the caller.
      chargeReveal(this.#states);

      if (devMode.config.enabled) {
        recordReveal(this, this.klass, this.label, this.#value, effectiveCtx, details);
      }
    }

    return this.#value;
  }

  /**
   * Construct a derived instance while retaining every source state object.
   */
  static #derived<D extends SensitivityClass>(
    value: string,
    klass: D,
    label: string | undefined,
    sources: readonly SensitiveString<SensitivityClass>[]
  ): SensitiveString<D> {
    const derived = new SensitiveString(
      value,
      klass,
      label,
      DERIVED_CONSTRUCTION as unknown as SensitiveStringOptions
    );
    const only = sources.length === 1 ? sources[0] : undefined;

    // One source is the common case, and its state arrays are already exactly
    // what the derivative needs. `#states` is assigned once and never mutated,
    // and the state objects are shared between derivatives by design.
    if (only !== undefined) {
      derived.#adopt(only.#states, only.#constrained, only.#restrictions);
      return derived;
    }

    // A Set, so a value derived from two values that already share a state
    // charges that state once per read rather than twice.
    const states = new Set<SensitiveStringState>();

    for (const source of sources) {
      for (const state of source.#states) {
        states.add(state);
      }
    }

    derived.#adopt(Array.from(states));
    return derived;
  }

  static {
    // The private access is deferred to call time on purpose. A CommonJS emit
    // rewrites the class name inside the class body to a temporary that is only
    // assigned once the class definition completes, so reading `#derived` here
    // would fail the brand check.
    deriveSensitiveString = (value, klass, label, sources) =>
      SensitiveString.#derived(value, klass, label, sources);
    serializeSensitiveString = (value, ctx, details) => value.#serialize(ctx, details);
    unshareableConstraints = (value) => {
      const names = [...unshareableBudgetOptions(value.#constrained)];

      if (carriesCustomRestriction(value.#restrictions)) {
        names.push('restrictions');
      }

      return names;
    };
  }

  /**
   * Apply an audited transformation and retain this instance's shared state.
   */
  #transform(transform: (value: string) => string, ctx?: RevealContext): SensitiveString<C> {
    const value = this.#readRawValue('expose', ctx);
    return SensitiveString.#derived(transform(value), this.klass, this.label, [this]);
  }

  /**
   * Read the raw value for a partial query after enforcing the class policy.
   */
  #readPartialQueryValue(ctx?: RevealContext): string {
    const policy = this.policy;
    const allowPartialQueries = policy.allowPartialQueries ?? this.klass === 'sensitive';

    if (!allowPartialQueries) {
      throw new Error(`Partial queries are not allowed for sensitivity class '${this.klass}'`);
    }

    return this.#readRawValue('expose', ctx);
  }

  /**
   * Returns the redacted form of this value.
   * Safe for logging and display.
   */
  toString(): string {
    // An instance that destroyed its own value renders the snapshot `clear()`
    // took from it. One that only inherited a clear still holds its own copy
    // and redacts that live, which is why the `'safe'` path stays exempt from
    // the cleared check: logging a sensitive value must never throw, and an
    // error handler doing `logger.error({ err, token })` on a cleared token
    // would otherwise lose the diagnostic it was writing.
    return this.#redaction ?? this.policy.redact(this.#readRawValue('safe'));
  }

  /**
   * Returns the redacted form for JSON serialization.
   * Automatically called by JSON.stringify().
   */
  toJSON(): string {
    return this.toString();
  }

  /**
   * Custom inspect for Node.js util.inspect() and console.log().
   * Displays the class, optional label, redacted value, and expiry state.
   *
   * The redacted form stays exactly what the class policy produces: expiry is
   * reported next to it rather than in place of it, so a custom redaction is
   * never replaced by a lifecycle marker. Inspecting is not an access, so this
   * does not fire `onExpire`, and it neither calls out to an external
   * revocation registry nor latches what it finds: a log line must not make a
   * network call, and a value that was only printed has not been used.
   */
  [NODE_INSPECT_SYMBOL](): string {
    const klassLabel = this.label ? `${this.klass}:${this.label}` : this.klass;
    // In the order the gate would refuse them, so a value that is both cleared
    // and expired reads as the error it would raise followed by the one it
    // would not.
    const cleared = this.#clearedFlag() !== undefined ? ' CLEARED' : '';
    const revoked = observedRevocation(this.#states) !== undefined ? ' REVOKED' : '';
    const expired = this.#expiredDeadline(false) !== undefined ? ' EXPIRED' : '';
    const exhausted = isBudgetExhausted(this.#constrained) ? ' EXHAUSTED' : '';
    return (
      `SensitiveString<${klassLabel}> ` +
      `{ ${this.toString()}${cleared}${revoked}${expired}${exhausted} }`
    );
  }

  /**
   * Returns the raw (unredacted) value.
   *
   * Triggers audit logging if a RevealContext is active.
   *
   * @param ctx - Optional explicit reveal context.
   * @throws If policy checking fails.
   * @throws ExpiredSensitiveValueError If the value has expired.
   * @throws RevokedSensitiveValueError If the value has been revoked, or a registry it consults cannot be reached.
   * @throws RevealLimitExceededError If `maxReveals` has been reached.
   * @throws RevealRateLimitError If `maxRevealsPerWindow` has been reached within the window.
   */
  reveal(ctx?: RevealContext): string {
    return this.#readRawValue('expose', ctx);
  }

  /**
   * What development mode recorded about this value, or `undefined`.
   *
   * `undefined` unless development mode is on and was on when this value was
   * constructed, so a production build reads `undefined` here rather than
   * failing on a missing property. The record holds no part of the raw value:
   * when the value was made, where it was made, how often it has been exposed
   * and from where.
   *
   * @see setDevMode
   */
  get __devInfo(): DevInfo | undefined {
    return readDevInfo(this);
  }

  /**
   * Returns a partially masked rendering of the value, for display.
   *
   * This is a partial reveal: it runs the same authorization and audit hooks as
   * `reveal()`, and the audit record says `operation: 'mask'` so a log can tell
   * the two apart. The result is a plain string and is not protected; it is
   * meant for a support screen, a confirmation prompt, or a log line, not for
   * further processing.
   *
   * The rendering must hide at least `minMasked` characters, which defaults to
   * 4 for `sensitive` and 8 for `credential` and may only be raised. Positional
   * masking clamps what it shows to satisfy the floor; a strategy that cannot
   * reach it, including one applied to a value of the wrong shape, falls back
   * to the class's full redaction. Counts are code points, and the length of
   * the value is disclosed by construction.
   *
   * @param options - Positional bounds or a format strategy. Defaults to hiding everything.
   * @param ctx - Optional reveal context for authorization and auditing.
   * @throws Error If the class policy sets `allowMask: false`, as `credential` does by default.
   * @throws TypeError If an option has the wrong type or names an unknown strategy.
   * @throws RangeError If a count is not a whole number, or `minMasked` is below the class floor.
   *
   * @example
   * ```ts
   * const key = new SensitiveString('sk_live_abc123xyz9', 'sensitive', 'api_key');
   * key.mask({ showFirst: 2, showLast: 4 }); // 'sk************xyz9'
   *
   * const email = new SensitiveString('jane@example.com', 'sensitive', 'email');
   * email.mask({ strategy: 'email' }); // 'j***@e******.com'
   * ```
   */
  mask(options: MaskOptions = {}, ctx?: RevealContext): string {
    const policy = this.policy;

    if (!(policy.allowMask ?? this.klass === 'sensitive')) {
      const label = this.label !== undefined ? ` (${this.label})` : '';
      throw new Error(`Masking is not allowed for sensitivity class '${this.klass}'${label}`);
    }

    // Options are validated before the value is read, so a rejected call leaves
    // no audit record for a mask that was never rendered.
    const plan = planMask(options, this.klass);
    const value = this.#readRawValue('expose', ctx, maskAuditDetails(plan));

    return applyMask(value, plan, (raw) => policy.redact(raw));
  }

  /**
   * Refuse a digest when the class policy forbids one.
   *
   * `advisory.allowHash` has been declared since the beginning and read by
   * nothing. This is what reads it. `undefined` allows, which is the opposite
   * of how `allowSendToExternal` is read and is deliberate: hashing is the
   * operation this library wants used in place of holding a value, so the flag
   * exists to forbid it for a class where even a digest is too much, not to
   * require permission for the safe path.
   */
  #requireHashingAllowed(operation: 'hash' | 'hmac'): void {
    if (this.policy.advisory?.allowHash === false) {
      const label = this.label !== undefined ? ` (${this.label})` : '';
      throw new Error(
        `SensitiveString.${operation}: hashing is not allowed for sensitivity class ` +
          `'${this.klass}'${label}; its policy sets advisory.allowHash: false`
      );
    }
  }

  /**
   * A one-way digest of the value, as a protected value.
   *
   * For a lookup key, a deduplication key, or a correlation token: something
   * derived from the value that can be stored or compared without storing the
   * value. It is an exposure like any other, so it runs the class policy, fires
   * the audit hook with `operation: 'hash'`, counts against a reveal budget,
   * and refuses on an expired or revoked value.
   *
   * ⚠️ This is not password hashing. The digest is fast to compute, which is
   * the one property a stored password must not have: a wordlist runs through
   * SHA-256 at billions of guesses a second, and a salt does not slow that down
   * for the attacker who has the salt, which is everyone holding the record.
   * Use `hashForStorage` from `@platform-sec/sensitive-string-kdf`.
   *
   * The result is always `credential`, whatever the source class was, because a
   * digest of a value an attacker can guess is a copy of that value behind a
   * lookup table, and one that correlates the same subject across every system
   * that stores it. It carries the deadline, the reveal budget and the
   * revocation of the value it came from, for the same reason.
   *
   * @param algorithm - One of sha256, sha384, sha512, sha3-256, sha3-512.
   * @param options - Salt and digest encoding.
   * @param ctx - Optional reveal context for authorization and auditing.
   * @throws Error If the class policy sets `advisory.allowHash: false`, or the algorithm is broken or unavailable in this Node build.
   * @throws TypeError If the algorithm, encoding, salt or options object has the wrong type.
   * @throws RangeError If the salt is empty.
   *
   * @example
   * ```ts
   * const token = new SensitiveString(raw, 'credential', 'session_token');
   * const lookupKey = token.hash('sha256');            // SensitiveString<'credential'>
   * await db.sessions.findUnique({ where: { tokenHash: lookupKey.reveal() } });
   * ```
   */
  hash(
    algorithm: HashAlgorithm,
    options: HashOptions = {},
    ctx?: RevealContext
  ): SensitiveString<'credential'> {
    this.#requireHashingAllowed('hash');

    // Options are validated before the value is read, so a rejected call leaves
    // no audit record and charges nothing for a digest that was never taken.
    const plan = planHash('hash', algorithm, options);
    const value = this.#readRawValue('expose', ctx, hashAuditDetails(plan));

    return SensitiveString.#derived(
      applyHash(value, plan),
      'credential',
      hashLabel(this.label, 'hash'),
      [this]
    );
  }

  /**
   * A keyed one-way digest of the value, as a protected value.
   *
   * The version of `hash()` to reach for when the value is something an
   * attacker can enumerate: an email address, a phone number, a card number, a
   * six-digit code. A salt stops precomputation and nothing else, because the
   * salt sits beside the digest in the same record; a key that the attacker
   * does not have is what makes the digest unanswerable, and it is also what
   * stops the same subject being correlated across two systems that both
   * store one.
   *
   * The key may itself be protected, and then it is read through its own gate:
   * its policy, its audit hook, its budget and its revocation all apply, and
   * the result carries the constraints of the value and the key both. Using a
   * value as a key reads it.
   *
   * @param algorithm - One of sha256, sha384, sha512, sha3-256, sha3-512.
   * @param key - At least 16 bytes. 32 bytes from `randomBytes` or a secrets manager is the recommendation.
   * @param options - Digest encoding.
   * @param ctx - Optional reveal context for authorization and auditing.
   * @throws Error If the class policy sets `advisory.allowHash: false`, or the algorithm is broken or unavailable in this Node build.
   * @throws TypeError If the algorithm, encoding, key or options object has the wrong type, or a salt is supplied.
   * @throws RangeError If the key is shorter than 16 bytes.
   *
   * @example
   * ```ts
   * const email = new SensitiveString('jane@example.com', 'sensitive', 'email');
   * const pseudonym = email.hmac('sha256', process.env.CORRELATION_KEY!);
   * ```
   */
  hmac(
    algorithm: HashAlgorithm,
    key: string | Uint8Array | SensitiveString<SensitivityClass>,
    options: HmacOptions = {},
    ctx?: RevealContext
  ): SensitiveString<'credential'> {
    this.#requireHashingAllowed('hmac');

    const plan = planHash('hmac', algorithm, options);
    const details = hmacAuditDetails(plan, key instanceof SensitiveString);

    // The key is read and measured before the value is, which is the one place
    // this class puts an argument ahead of its receiver. A key below the floor
    // is a call that will not produce a digest, and refusing it after the
    // receiver had been read would charge an exposure for nothing.
    const keyBytes = requireHmacKey(
      key instanceof SensitiveString ? key.#readRawValue('expose', ctx, details) : key
    );
    const value = this.#readRawValue('expose', ctx, details);

    const sources: SensitiveString<SensitivityClass>[] =
      key instanceof SensitiveString ? [this, key] : [this];

    return SensitiveString.#derived(
      applyHmac(value, keyBytes, plan),
      'credential',
      hashLabel(this.label, 'hmac'),
      sources
    );
  }

  /**
   * The deadline after which this value can no longer be read, if it has one.
   *
   * A derived value carries the deadlines of every value it came from, and this
   * reports the earliest of them: a substring of an expired OTP is expired, and
   * a concatenation is only usable while both of its operands are.
   *
   * Returns a copy, so the deadline cannot be moved through it.
   */
  get expiresAt(): Date | undefined {
    const earliest = this.#earliestDeadline();
    return earliest === undefined ? undefined : new Date(earliest);
  }

  /**
   * Whether the deadline has passed. A value is not usable at its own deadline.
   *
   * The first detection fires the `onExpire` callback of every expired source.
   */
  isExpired(): boolean {
    return this.#expiredDeadline(true) !== undefined;
  }

  /**
   * Milliseconds until the deadline, `-1` once it has passed, or `undefined`
   * when this value does not expire.
   */
  ttlRemaining(): number | undefined {
    const earliest = this.#earliestDeadline();

    if (earliest === undefined) {
      return undefined;
    }

    const remaining = earliest - Date.now();
    return remaining <= 0 ? -1 : remaining;
  }

  /**
   * Whether `renew()` would be accepted right now.
   *
   * Renewal needs a deadline to extend, permission from the class policy and
   * the construction options, an unexhausted renewal budget, and ownership of
   * the deadline: a derived value cannot renew one it shares.
   */
  isRenewable(): boolean {
    const own = this.#own;

    if (own === undefined || own.expiry.deadline === undefined || !own.expiry.allowRenewal) {
      return false;
    }

    const { maxRenewals, renewalCount } = own.expiry;
    return maxRenewals === undefined || renewalCount < maxRenewals;
  }

  /**
   * How many times this value has extended the deadline it owns.
   *
   * A derived value owns no deadline and reports `0`, however often the value
   * it came from has been renewed.
   */
  get renewalCount(): number {
    return this.#own?.expiry.renewalCount ?? 0;
  }

  /**
   * Extend the deadline, when the class policy and the construction options
   * allow it.
   *
   * An expired value extends from now rather than from its lapsed deadline, so
   * a sliding session that missed a heartbeat is granted the full duration.
   * Reviving a value this way is why `allowRenewal` defaults to `false` for
   * `credential` and why a policy may forbid it outright.
   *
   * The extension is audited before it takes effect, so an audit sink that
   * throws stops it, and a refused renewal leaves no record of one that never
   * happened. Renewing is not a read: it does not disclose the value, and it
   * works on an expired one. It does not work on a revoked one, or on one this
   * environment may not read, because neither of those is a lapsed deadline:
   * both say the value must not be used here, and extending its life is using
   * it.
   *
   * @param additionalTtl - Milliseconds to add. Must be positive.
   * @param options - `maxExtension` clamps the resulting deadline.
   * @param ctx - Optional reveal context for authorization and auditing.
   * @throws ClearedSensitiveValueError If the value, or one it was derived from, has been cleared.
   * @throws RenewalNotAllowedError If renewal is refused, or a cap leaves no room to extend.
   * @throws RangeError If `additionalTtl` is not a positive, finite number.
   * @throws RevokedSensitiveValueError If the value has been revoked.
   * @throws EnvironmentRestrictedError If this environment may not read the value.
   *
   * @example
   * ```ts
   * const session = new SensitiveString(token, 'sensitive', 'session', { ttl: 15 * 60_000 });
   * session.renew(15 * 60_000, { maxExtension: absoluteSessionDeadline });
   * ```
   */
  renew(additionalTtl: number, options: RenewalOptions = {}, ctx?: RevealContext): void {
    // Renewal reads nothing, so it does not route through the gate, and
    // without this a value that no longer exists would still have its deadline
    // moved. Ahead of the ownership check as well, and ahead of everything
    // else here for the same reason the gate puts it first: whatever else is
    // true of a destroyed value, extending its life is not a thing to report
    // success for.
    this.#refuseIfCleared();

    const own = this.#own;

    if (own === undefined) {
      throw new RenewalNotAllowedError('derived', this.label);
    }

    // Renewal does not read the value, so it does not go through the gate, and
    // without this a revoked value could still have its deadline extended. It
    // would stay unreadable, but a lifecycle control that keeps working on a
    // revoked value is one somebody will eventually mistake for the value
    // working.
    const revoked = revocationInForce(this.#states);
    if (revoked !== undefined) {
      throw new RevokedSensitiveValueError(
        revoked.reason,
        new Date(revoked.at),
        this.label,
        revoked.scope,
        revoked.cause
      );
    }

    // The same reason, one restriction along: renewal does not read the value,
    // so nothing else here consults the environment, and without this a process
    // the value forbids could keep extending its life. Reading it is the thing
    // the restriction denies, and a lifecycle control that keeps working where
    // the value does not is one somebody will mistake for the value working.
    if (this.#restrictions.length !== 0) {
      checkEnvironmentRestrictions(this.#restrictions, this.label);
    }

    const { expiry } = own;
    const plan = planRenewal(expiry, additionalTtl, options, this.label);

    const effectiveCtx = ctx ?? getCurrentRevealContext();
    // Renewal reads no value, so it does not go through the gate, but it is
    // still an operation a policy may refuse.
    refuseHookReturn(this.policy.checkRevealAllowed?.(effectiveCtx, this, 'renew'), this.klass);
    effectiveCtx?.auditReveal?.(this, renewAuditDetails(expiry, plan), effectiveCtx);

    expiry.deadline = plan.next;
    expiry.renewalCount++;
    // The new deadline is a new expiration, so its own notification is due.
    expiry.notified = false;
  }

  /**
   * The revocation in force on this value, or `undefined`. Shared by the three
   * public accessors below; the gate calls the same module function directly,
   * so that its decision never routes through anything a subclass could
   * override.
   *
   * Latches what it finds, so a value that has once been refused stays refused
   * even if the entry behind it is pruned, and consults an external registry,
   * so each accessor is a live question rather than a cached answer.
   */
  #revocation(): RevocationRecord | undefined {
    return revocationInForce(this.#states);
  }

  /**
   * Stop this value from being read, permanently.
   *
   * There is no way back. Nothing lifts a revocation: not a policy, not a new
   * options object, not a round trip through the wire format.
   *
   * Revocation runs along derivation edges in both directions. Every value this
   * one was derived from is revoked too, and so is everything else derived from
   * those, because a derivative is made of its sources' material: a leaked
   * substring is a leaked secret. Refusing to revoke through the handle a
   * caller happens to be holding would fail open in exactly the incident this
   * exists for, which is why this is the one piece of shared state a derived
   * value may write, where `renew()` refuses.
   *
   * Nothing may refuse a revocation, so no policy hook is consulted and the
   * audit record is reported after the fact, with anything the sink throws
   * swallowed. `renew()` audits first for the opposite reason.
   *
   * Revoking an already-revoked value changes nothing and reports nothing: the
   * first reason and timestamp stand, because a revocation is a fact that
   * already happened.
   *
   * @param reason - Why, for the error message and the audit record. Developer
   *   text: it must not carry any part of the protected value.
   * @param ctx - Optional reveal context for auditing.
   * @throws TypeError If `reason` is not a string.
   *
   * @example
   * ```ts
   * apiKey.revoke('Rotated 2026-08-01');
   * apiKey.reveal(); // throws RevokedSensitiveValueError
   * ```
   */
  revoke(reason: string, ctx?: RevealContext): void {
    const why = requireReason(reason, 'SensitiveString.revoke');
    const record = revokeStates(this.#states, why);

    if (record === undefined) {
      return;
    }

    const effectiveCtx = ctx ?? getCurrentRevealContext();

    try {
      effectiveCtx?.auditReveal?.(this, revokeAuditDetails(record), effectiveCtx);
    } catch {
      // The value is already revoked. A sink that fails must not make it look
      // as though the revocation did.
    }
  }

  /**
   * Whether this value has been revoked, by any of the four sources: its own
   * `revoke()`, the process-global label and pattern lists, or the registry it
   * was constructed with.
   *
   * `true` as well when a registry it was given cannot be reached, because a
   * value whose revocation cannot be checked is not one to hand out.
   */
  get isRevoked(): boolean {
    return this.#revocation() !== undefined;
  }

  /**
   * Why this value was revoked, or `undefined` when it was not.
   *
   * The reason recorded by whichever source refused first. For a value revoked
   * through several of them, that is the one observed earliest rather than the
   * one highest in any precedence order: a latched revocation is a fact that
   * already happened.
   */
  get revocationReason(): string | undefined {
    return this.#revocation()?.reason;
  }

  /**
   * When this value was revoked, or `undefined` when it was not.
   *
   * For a label or pattern revocation this is when the list was written, not
   * when this value first noticed.
   */
  get revokedAt(): Date | undefined {
    const record = this.#revocation();
    return record === undefined ? undefined : new Date(record.at);
  }

  /**
   * Destroy this instance's copy of the plaintext, permanently.
   *
   * What it does is narrow, and the first paragraph of the documentation is the
   * right place to say so: it drops **the library's** reference to the string
   * and refuses every later read. It is not zeroing. JavaScript cannot
   * overwrite the backing store of a string it holds a reference to, and
   * whether the library's was the last reference is a property of the calling
   * code rather than of this method.
   *
   * ```ts
   * // Works: the library's copy is the only copy.
   * const password = new SensitiveString(await kms.decrypt(blob), 'credential', 'db_password');
   * await connect(password.reveal(ctx));
   * password.clear();
   *
   * // Does nothing while the handler still holds req.body: req.body.token and
   * // the instance's value are the same string object.
   * const token = new SensitiveString(req.body.token, 'credential');
   * token.clear();
   * ```
   *
   * The second shape is not fixable from inside the library, and no boundary
   * integration fixes it either: a body has to be parsed into strings before
   * any field can be classified. The fix belongs to the caller, which is to
   * drop or delete the source property once the value is wrapped.
   *
   * Derivatives are refused, not released. Clearing an owner refuses every
   * value derived from it, because they share the state object this writes;
   * clearing a derivative refuses only that derivative, because it has no
   * shared state of its own to write. The traffic also runs the other way: a
   * derivative of 13 characters or more is a V8 `SlicedString` pinning its
   * origin's entire backing store, and a `concat()` result pins both operands,
   * so an origin's `clear()` releases nothing at all until the derivatives are
   * cleared too. Clear them, or turn on `trackInstances` and let
   * `clearAllSensitiveValues()` find the ones you no longer hold.
   *
   * Redaction keeps working: `toString()`, `toJSON()` and `inspect()` render
   * the rendering this snapshotted from the live value, so logging a cleared
   * value never throws. `length` and `isEmpty()` refuse instead of answering
   * `0` and `true`, which would be wrong rather than degraded.
   *
   * No policy is consulted. Clearing reduces exposure, so there is no
   * confidentiality outcome a denial would protect, and the same caller could
   * drop the reference by letting it go out of scope. It is audited, after the
   * fact, with anything the sink throws swallowed.
   *
   * Irreversible, and idempotent per instance: a second call on the same
   * instance changes nothing and reports nothing. A derivative whose origin was
   * cleared has still not dropped its own copy, so `clear()` on it is not a
   * no-op.
   *
   * @param ctx - Optional reveal context for auditing. The ambient context is used when this is omitted.
   *
   * @example
   * ```ts
   * token.clear();
   * token.isCleared;   // true
   * token.toString();  // '[REDACTED:credential]', unchanged
   * token.reveal();    // throws ClearedSensitiveValueError
   * ```
   */
  clear(ctx?: RevealContext): void {
    // Guarded on this instance's own clear, never on the inherited flag. A
    // derivative whose origin was cleared is already refused for every read,
    // and still holds its own copy of the plaintext and its own pin on the
    // origin's, so it still has work to do here. Guarding on #clearedFlag()
    // would return early for every derivative a bulk clear reaches after its
    // origin, which is precisely the set that function exists to reach.
    if (this.#ownClearedAt !== undefined) {
      return;
    }

    const now = Date.now();
    const own = this.#own;

    // Taken from the live value, immediately before it is dropped, so
    // toString() keeps answering afterwards. The 'safe' path is exempt from the
    // cleared check, so this works on an instance that inherited a clear too.
    //
    // A custom redact that throws must not leave the value uncleared: refusing
    // to destroy a secret because its renderer is broken is the wrong way to
    // fail. The fallback is the marker the class would have emitted anyway.
    try {
      this.#redaction = this.policy.redact(this.#readRawValue('safe'));
    } catch {
      this.#redaction = `[REDACTED:${this.klass}]`;
    }

    this.#ownClearedAt = now;

    if (own !== undefined) {
      // Only an owner writes shared state. A derivative shares its sources'
      // state by reference, so writing it would destroy the value it came from.
      own.clearedAt = now;
    }

    this.#value = '';

    const effectiveCtx = ctx ?? getCurrentRevealContext();

    try {
      // After the state change, which is the inverse of renew()'s order and the
      // same as revoke()'s. renew() audits first so a sink that throws stops the
      // extension; a clear is not something a sink may veto, and a sink that
      // fails must not make it look as though the destruction did not happen.
      effectiveCtx?.auditReveal?.(
        this,
        { operation: 'clear', propagated: own !== undefined },
        effectiveCtx
      );
    } catch {
      // See above. The value is already gone.
    }
  }

  /**
   * Whether this value has been destroyed, by its own `clear()` or by one on a
   * value it was derived from.
   */
  get isCleared(): boolean {
    return this.#clearedFlag() !== undefined;
  }

  /**
   * When this value was destroyed, or `undefined` when it was not.
   *
   * The earliest clear affecting it, so a derivative cleared after its origin
   * reports the origin's time: that is when it stopped being usable.
   */
  get clearedAt(): Date | undefined {
    const cleared = this.#clearedFlag();
    return cleared === undefined ? undefined : new Date(cleared);
  }

  /**
   * How many times this value has been exposed.
   *
   * Counted for every value, whether or not it limits reveals. An exposure is
   * what an audit hook sees: `reveal()`, `mask()`, `hash()`, `hmac()`,
   * `serialize()`, `map()`, and the string, regex, and template operations, one
   * per call. An `hmac()` with a protected key counts once against the value
   * and once against the key. `equals()` is
   * not, because a comparison reads the value without disclosing it, and
   * neither is redaction. A read the gate refused, or one an audit hook stopped
   * by throwing, is not counted: a denied reveal is not a reveal.
   *
   * A derived value reports the highest count among the values it was built
   * from, which is the one nearest a limit.
   */
  get revealCount(): number {
    let highest = 0;

    for (const state of this.#states) {
      if (state.reveals > highest) {
        highest = state.reveals;
      }
    }

    return highest;
  }

  /**
   * Exposures still allowed before `maxReveals` is reached, or `undefined` when
   * this value sets no lifetime limit.
   *
   * A derived value reports the smallest remaining budget among the values it
   * was built from, which is the one that will refuse first.
   */
  get revealsRemaining(): number | undefined {
    return revealsRemaining(this.#constrained);
  }

  /**
   * Whether the lifetime limit has been reached, so no further exposure is
   * possible. Permanent: nothing resets a reveal count.
   *
   * A rate limit does not make a value exhausted, because waiting clears it.
   */
  isExhausted(): boolean {
    return isBudgetExhausted(this.#constrained);
  }

  /**
   * Compare this value with another string or SensitiveString.
   *
   * Uses constant-time comparison when either operand's class requires it, as
   * 'credential' does, to prevent timing attacks. The receiver alone used to
   * decide, so `input.equals(storedCredential)` compared with `===` while
   * `storedCredential.equals(input)` did not, and which side of the call a
   * credential lands on is not a decision anyone makes on purpose.
   *
   * @param other - The value to compare against
   * @param ctx - Optional reveal context for policy checks
   * @returns true if values are equal
   *
   * @remarks
   * The constant-time path hides the stored value's contents, and hides its
   * length to the granularity of a SHA-256 block: a comparand of the wrong
   * length costs what a comparand of the right length costs, and a stored
   * value of 8 bytes costs what one of 55 costs. See `compare.ts` for why that
   * needs more than `timingSafeEqual` alone, and for what it still leaves.
   */
  equals(other: string | SensitiveString<SensitivityClass>, ctx?: RevealContext): boolean {
    const value = this.#readRawValue('compare', ctx);
    const rawOther = other instanceof SensitiveString ? other.#readRawValue('compare', ctx) : other;
    const constantTime =
      this.policy.requireConstantTimeEquals === true ||
      (other instanceof SensitiveString && other.policy.requireConstantTimeEquals === true);

    if (constantTime) {
      return constantTimeEquals(value, rawOther);
    }

    return value === rawOther;
  }

  /**
   * Concatenate with another string or SensitiveString.
   *
   * Inherits the most restrictive sensitivity class.
   * Labels are combined with '/' separator.
   *
   * @param other - The value to append.
   * @param ctx - Audit context for raw-value access.
   */
  concat<D extends SensitivityClass>(
    other: string | SensitiveString<D>,
    ctx?: RevealContext
  ): SensitiveString<SensitivityClass> {
    const value = this.#readRawValue('expose', ctx);
    const rawOther = other instanceof SensitiveString ? other.#readRawValue('expose', ctx) : other;
    const otherClass: SensitivityClass =
      other instanceof SensitiveString ? other.klass : 'sensitive';
    const otherLabel = other instanceof SensitiveString ? other.label : undefined;

    const combinedClass = this.policy.combineClasses
      ? this.policy.combineClasses(this.klass, otherClass)
      : defaultCombineClasses(this.klass, otherClass);

    // Combine labels if both exist
    const combinedLabel =
      this.label && otherLabel ? `${this.label}/${otherLabel}` : (this.label ?? otherLabel);

    const sources: SensitiveString<SensitivityClass>[] =
      other instanceof SensitiveString ? [this, other] : [this];

    return SensitiveString.#derived(value + rawOther, combinedClass, combinedLabel, sources);
  }

  /**
   * Get the length of the raw value.
   * Note: Length is generally not considered sensitive for most use cases.
   *
   * @throws ClearedSensitiveValueError If the value, or one it was derived from, has been cleared. `0` would be a wrong answer, not a degraded one.
   */
  get length(): number {
    // The `'safe'` path is exempt from the cleared check so redaction survives
    // one, and this reader has nothing to fall back on: after a clear it would
    // answer `0` from the empty string. That is a wrong answer rather than a
    // degraded one, and a caller branching on `if (!token.length)` would read a
    // destroyed credential as an absent one.
    this.#refuseIfCleared();
    return this.#readRawValue('safe').length;
  }

  /**
   * Check if the raw value is empty.
   *
   * @throws ClearedSensitiveValueError If the value, or one it was derived from, has been cleared. `true` would be a wrong answer, not a degraded one.
   */
  isEmpty(): boolean {
    this.#refuseIfCleared();
    return this.#readRawValue('safe').length === 0;
  }

  /**
   * Create a substring, preserving sensitivity class and label.
   *
   * @param start - Start index.
   * @param end - Optional end index.
   * @param ctx - Audit context.
   * @throws If policy checking fails (e.g., context required but not provided).
   */
  substring(start: number, end?: number, ctx?: RevealContext): SensitiveString<C> {
    return this.#transform((value) => value.substring(start, end), ctx);
  }

  /**
   * Remove whitespace from both ends, preserving sensitivity and label.
   *
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  trim(ctx?: RevealContext): SensitiveString<C> {
    return this.#transform((value) => value.trim(), ctx);
  }

  /**
   * Remove leading whitespace, preserving sensitivity and label.
   *
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  trimStart(ctx?: RevealContext): SensitiveString<C> {
    return this.#transform((value) => value.trimStart(), ctx);
  }

  /**
   * Remove trailing whitespace, preserving sensitivity and label.
   *
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  trimEnd(ctx?: RevealContext): SensitiveString<C> {
    return this.#transform((value) => value.trimEnd(), ctx);
  }

  /**
   * Convert the value to lowercase, preserving sensitivity and label.
   *
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  toLowerCase(ctx?: RevealContext): SensitiveString<C> {
    return this.#transform((value) => value.toLowerCase(), ctx);
  }

  /**
   * Convert the value to uppercase, preserving sensitivity and label.
   *
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  toUpperCase(ctx?: RevealContext): SensitiveString<C> {
    return this.#transform((value) => value.toUpperCase(), ctx);
  }

  /**
   * Pad the start of the value to a target length.
   *
   * @param targetLength - Desired result length.
   * @param padString - String used for padding.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  padStart(targetLength: number, padString?: string, ctx?: RevealContext): SensitiveString<C> {
    return this.#transform((value) => value.padStart(targetLength, padString), ctx);
  }

  /**
   * Pad the end of the value to a target length.
   *
   * @param targetLength - Desired result length.
   * @param padString - String used for padding.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  padEnd(targetLength: number, padString?: string, ctx?: RevealContext): SensitiveString<C> {
    return this.#transform((value) => value.padEnd(targetLength, padString), ctx);
  }

  /**
   * Extract a section of the value, preserving sensitivity and label.
   *
   * @param start - Zero-based start index. Negative indices count from the end.
   * @param end - Optional exclusive end index.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  slice(start?: number, end?: number, ctx?: RevealContext): SensitiveString<C> {
    return this.#transform((value) => value.slice(start, end), ctx);
  }

  /**
   * Test whether the value begins with a string.
   *
   * Partial queries are disabled for credentials by default because their
   * results can be used as a character-by-character oracle.
   *
   * @param searchString - Prefix to find.
   * @param position - Position at which to begin searching.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  startsWith(searchString: string, position?: number, ctx?: RevealContext): boolean {
    return this.#readPartialQueryValue(ctx).startsWith(searchString, position);
  }

  /**
   * Test whether the value ends with a string.
   *
   * @param searchString - Suffix to find.
   * @param endPosition - End position to use for the search.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  endsWith(searchString: string, endPosition?: number, ctx?: RevealContext): boolean {
    return this.#readPartialQueryValue(ctx).endsWith(searchString, endPosition);
  }

  /**
   * Test whether the value contains a string.
   *
   * @param searchString - String to find.
   * @param position - Position at which to begin searching.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  includes(searchString: string, position?: number, ctx?: RevealContext): boolean {
    return this.#readPartialQueryValue(ctx).includes(searchString, position);
  }

  /**
   * Find the first index of a string in the value.
   *
   * @param searchString - String to find.
   * @param position - Position at which to begin searching.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  indexOf(searchString: string, position?: number, ctx?: RevealContext): number {
    return this.#readPartialQueryValue(ctx).indexOf(searchString, position);
  }

  /**
   * Find the last index of a string in the value.
   *
   * @param searchString - String to find.
   * @param position - Position at which to begin searching backward.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  lastIndexOf(searchString: string, position?: number, ctx?: RevealContext): number {
    return this.#readPartialQueryValue(ctx).lastIndexOf(searchString, position);
  }

  /**
   * Test whether a regular expression matches the value.
   *
   * Regex tests are partial queries and are disabled for credentials by default
   * because caller-controlled patterns can form a powerful content oracle.
   *
   * @param pattern - Regular expression to test.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  test(pattern: RegExp, ctx?: RevealContext): boolean {
    const regex = snapshotRegExp(pattern, 'SensitiveString.test');
    return regex.test(this.#readPartialQueryValue(ctx));
  }

  /**
   * Find the index of the first regular-expression match.
   *
   * This is a partial query and is disabled for credentials by default.
   *
   * @param pattern - Regular expression to search for.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  search(pattern: RegExp, ctx?: RevealContext): number {
    const regex = snapshotRegExp(pattern, 'SensitiveString.search');
    return this.#readPartialQueryValue(ctx).search(regex);
  }

  /**
   * Return regular-expression matches as protected values.
   *
   * Native match metadata such as `input` is intentionally omitted because it
   * contains the complete raw value. Unmatched optional captures are omitted.
   *
   * @param pattern - Regular expression to match.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  match(pattern: RegExp, ctx?: RevealContext): SensitiveString<C>[] | null {
    const regex = snapshotRegExp(pattern, 'SensitiveString.match');
    const matches = this.#readRawValue('expose', ctx).match(regex);

    if (matches === null) {
      return null;
    }

    return matches
      .filter((match): match is string => match !== undefined)
      .map((match) => SensitiveString.#derived(match, this.klass, this.label, [this]));
  }

  /**
   * Return named regular-expression groups as protected values.
   *
   * A successful match without named groups returns an empty, null-prototype
   * object. Named groups that did not participate in the match are omitted.
   *
   * @param pattern - Regular expression containing optional named groups.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  matchGroups(pattern: RegExp, ctx?: RevealContext): Record<string, SensitiveString<C>> | null {
    const regex = snapshotRegExp(pattern, 'SensitiveString.matchGroups');
    const match = regex.exec(this.#readRawValue('expose', ctx));

    if (match === null) {
      return null;
    }

    const groups = Object.create(null) as Record<string, SensitiveString<C>>;

    for (const [group, value] of Object.entries(match.groups ?? {})) {
      if (value === undefined) {
        continue;
      }

      const label = this.label !== undefined ? `${this.label}:${group}` : group;
      Object.defineProperty(groups, group, {
        value: SensitiveString.#derived(value, this.klass, label, [this]),
        enumerable: true,
        configurable: true,
        writable: true,
      });
    }

    return groups;
  }

  /**
   * Return every regular-expression match as an iterator of protected arrays.
   *
   * The pattern must have the global (`g`) flag, matching native String.matchAll
   * requirements. Match metadata containing the complete input is omitted.
   *
   * @param pattern - Global regular expression to match.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  matchAll(pattern: RegExp, ctx?: RevealContext): IterableIterator<SensitiveString<C>[]> {
    const regex = snapshotRegExp(pattern, 'SensitiveString.matchAll');

    if (!regex.global) {
      throw new TypeError('SensitiveString.matchAll requires a global regular expression');
    }

    const matches = this.#readRawValue('expose', ctx).matchAll(regex);
    const protect = (match: RegExpMatchArray): SensitiveString<C>[] =>
      match
        .filter((part): part is string => part !== undefined)
        .map((part) => SensitiveString.#derived(part, this.klass, this.label, [this]));

    return (function* protectedMatches(): IterableIterator<SensitiveString<C>[]> {
      for (const match of matches) {
        yield protect(match);
      }
    })();
  }

  /**
   * Split the value into protected parts.
   *
   * @param separator - String or regular expression used to divide the value.
   * @param limit - Maximum number of results.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  split(separator: string | RegExp, limit?: number, ctx?: RevealContext): SensitiveString<C>[] {
    const safeSeparator =
      typeof separator === 'string'
        ? separator
        : snapshotRegExp(separator, 'SensitiveString.split');
    const value = this.#readRawValue('expose', ctx);
    return value
      .split(safeSeparator, limit)
      .map((part) => SensitiveString.#derived(part, this.klass, this.label, [this]));
  }

  /**
   * Replace the first matching string or the matches selected by a regular expression.
   *
   * Replacement callbacks are intentionally unsupported because they receive raw
   * matched content.
   *
   * @param searchValue - String or regular expression to replace.
   * @param replaceValue - String replacement pattern.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  replace(
    searchValue: string | RegExp,
    replaceValue: string,
    ctx?: RevealContext
  ): SensitiveString<C> {
    if (typeof replaceValue !== 'string') {
      throw new TypeError('SensitiveString replacement value must be a string');
    }

    const safeSearchValue =
      typeof searchValue === 'string'
        ? searchValue
        : snapshotRegExp(searchValue, 'SensitiveString.replace');
    return this.#transform((value) => value.replace(safeSearchValue, replaceValue), ctx);
  }

  /**
   * Replace every matching string or regular-expression match.
   *
   * Replacement callbacks are intentionally unsupported because they receive raw
   * matched content.
   *
   * @param searchValue - String or global regular expression to replace.
   * @param replaceValue - String replacement pattern.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  replaceAll(
    searchValue: string | RegExp,
    replaceValue: string,
    ctx?: RevealContext
  ): SensitiveString<C> {
    if (typeof replaceValue !== 'string') {
      throw new TypeError('SensitiveString replacement value must be a string');
    }

    const safeSearchValue =
      typeof searchValue === 'string'
        ? searchValue
        : snapshotRegExp(searchValue, 'SensitiveString.replaceAll');

    if (safeSearchValue instanceof RegExp && !safeSearchValue.global) {
      throw new TypeError('SensitiveString.replaceAll requires a global regular expression');
    }

    return this.#transform((value) => value.replaceAll(safeSearchValue, replaceValue), ctx);
  }

  /**
   * Return the character at an index as a protected value.
   *
   * An out-of-range index returns a protected empty string, matching String.charAt().
   *
   * @param index - Zero-based character index.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  charAt(index: number, ctx?: RevealContext): SensitiveString<C> {
    return this.#transform((value) => value.charAt(index), ctx);
  }

  /**
   * Return the character at an index as a protected value.
   *
   * @param index - Character index. Negative indices count from the end.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  at(index: number, ctx?: RevealContext): SensitiveString<C> | undefined {
    const value = this.#readRawValue('expose', ctx).at(index);
    return value === undefined
      ? undefined
      : SensitiveString.#derived(value, this.klass, this.label, [this]);
  }

  /**
   * Serialize for secure service boundary transmission.
   *
   * ⚠️ RETURNS RAW VALUE - DO NOT LOG ⚠️
   *
   * Intended for mTLS/encrypted transmission only.
   *
   * A deadline travels with the value, so a token with five minutes left still
   * has five minutes left on the other side. The receiver enforces it against
   * its own clock: a receiver whose clock runs ahead of the sender's rejects the
   * value early, which is the direction to fail in. Renewal permission and
   * renewal counts do not travel, so a payload cannot grant the right to extend
   * a credential's lifetime.
   *
   * A revoked value is not transmittable: reading it to build the payload goes
   * through the same gate as any other read, so this throws rather than
   * emitting the wire format's `revoked` flag. That flag is for the receiving
   * side, and `deserialize()` honours it.
   *
   * Environment restrictions travel too, so a value that may only be read in
   * the EU is still restricted to the EU on the other side. A restriction that
   * is a function does not travel and cannot: such a value refuses to
   * serialize rather than arriving with half of its restriction enforced.
   *
   * @param ctx - Optional context for audit/permission checks
   * @throws ExpiredSensitiveValueError If the value has expired.
   * @throws RevokedSensitiveValueError If the value has been revoked.
   * @throws EnvironmentRestrictedError If this environment may not read the value.
   * @throws UnserializableRestrictionError If the value carries a custom restriction.
   */
  serialize(ctx?: RevealContext): SerializedSensitiveString {
    return this.#serialize(ctx, REVEAL_AUDIT_DETAILS);
  }

  /**
   * The wire form, read under the given audit record.
   *
   * `serialize()` reports a reveal; a handoff to another thread reports itself
   * as one, through `serializeSensitiveString`. Same gate, same access kind.
   */
  #serialize(ctx: RevealContext | undefined, details: RevealDetails): SerializedSensitiveString {
    // Before the read, so a value that cannot cross intact is refused without
    // being revealed or audited. A function has no wire form: emitting the
    // declarative half and dropping this would hand the receiver a value it
    // believes it has fully checked.
    if (carriesCustomRestriction(this.#restrictions)) {
      throw new UnserializableRestrictionError(this.label);
    }

    const value = this.#readRawValue('expose', ctx, details);
    const deadline = this.#earliestDeadline();

    const serialized: SerializedSensitiveString = {
      __sensitive: true as const,
      klass: this.klass,
      value,
    };

    if (this.label !== undefined) {
      serialized.label = this.label;
    }

    if (deadline !== undefined) {
      serialized.expiresAt = isoDeadline(deadline);
    }

    if (this.#restrictions.length !== 0) {
      serialized.restrictions = serializeRestrictions(this.#restrictions);
    }

    return serialized;
  }

  /**
   * Reconstruct a SensitiveString from a serialized form.
   *
   * @param serialized - The serialized form (potentially untrusted data from external source).
   * @throws If the serialized form is invalid or missing required fields.
   * @throws If the klass is not a registered sensitivity class.
   */
  static deserialize<C extends SensitivityClass>(serialized: unknown): SensitiveString<C> {
    // Type guard for runtime validation of untrusted data
    if (
      typeof serialized !== 'object' ||
      serialized === null ||
      !('__sensitive' in serialized) ||
      serialized.__sensitive !== true
    ) {
      throw new Error('Invalid SerializedSensitiveString: missing __sensitive marker');
    }
    if (!('value' in serialized) || typeof serialized.value !== 'string') {
      throw new Error('Invalid SerializedSensitiveString: value must be a string');
    }
    if (!('klass' in serialized) || typeof serialized.klass !== 'string') {
      throw new Error('Invalid SerializedSensitiveString: klass must be a string');
    }

    // Validate that klass is a registered sensitivity class
    if (!hasPolicy(serialized.klass as SensitivityClass)) {
      throw new Error(
        `Invalid SerializedSensitiveString: unknown sensitivity class '${serialized.klass}'`
      );
    }

    if (
      'label' in serialized &&
      serialized.label !== undefined &&
      typeof serialized.label !== 'string'
    ) {
      throw new Error('Invalid SerializedSensitiveString: label must be a string or undefined');
    }

    const label =
      'label' in serialized && typeof serialized.label === 'string' ? serialized.label : undefined;

    const value = new SensitiveString<C>(
      serialized.value,
      serialized.klass as C,
      label,
      SensitiveString.#deserializeOptions(serialized)
    );

    const revoked = SensitiveString.#deserializeRevocation(serialized);

    if (revoked !== undefined) {
      revokeStates(value.#states, revoked, 'wire');
    }

    return value;
  }

  /**
   * The reason a payload carries for a value it marks revoked, or `undefined`.
   *
   * `serialize()` never writes these fields, because the gate refuses to read a
   * revoked value at all. They exist so a payload assembled elsewhere can tell
   * the receiver not to use what it is sending, and they can only tighten:
   * there is no spelling of "not revoked" here, which is why `revoked: false`
   * is rejected rather than honoured. A reason without the flag is rejected
   * too, since it reads as a revocation that would silently not happen.
   */
  static #deserializeRevocation(serialized: object): string | undefined {
    const flag = 'revoked' in serialized ? serialized.revoked : undefined;
    const reason = 'revocationReason' in serialized ? serialized.revocationReason : undefined;

    if (flag !== undefined && flag !== true) {
      throw new Error(
        'Invalid SerializedSensitiveString: revoked must be true or absent; ' +
          'there is no way to mark a value as not revoked'
      );
    }

    if (reason !== undefined && typeof reason !== 'string') {
      throw new Error('Invalid SerializedSensitiveString: revocationReason must be a string');
    }

    if (flag === undefined) {
      if (reason !== undefined) {
        throw new Error(
          'Invalid SerializedSensitiveString: revocationReason without revoked: true'
        );
      }

      return undefined;
    }

    return reason ?? 'revoked by the sender';
  }

  /**
   * Rebuild the construction options carried by a serialized form.
   *
   * The deadline and the environment restrictions cross, and nothing else.
   * Both only ever narrow what the receiver may do. Renewal permission and
   * renewal counts are decided locally, by the receiving process's policy:
   * taking them from a payload would let a sender declare a credential
   * renewable.
   */
  static #deserializeOptions(serialized: object): SensitiveStringOptions | undefined {
    const restrictions = deserializeRestrictions(serialized);

    if (!('expiresAt' in serialized) || serialized.expiresAt === undefined) {
      return restrictions === undefined ? undefined : { restrictions };
    }

    if (typeof serialized.expiresAt !== 'string') {
      throw new Error('Invalid SerializedSensitiveString: expiresAt must be an ISO 8601 string');
    }

    const expiresAt = new Date(serialized.expiresAt);

    if (Number.isNaN(expiresAt.getTime())) {
      throw new Error(
        `Invalid SerializedSensitiveString: expiresAt '${serialized.expiresAt}' is not a valid date`
      );
    }

    return restrictions === undefined ? { expiresAt } : { expiresAt, restrictions };
  }

  /**
   * Create a SensitiveString if the input is truthy, otherwise return null.
   * Useful for optional fields.
   */
  static fromOptional<C extends SensitivityClass>(
    value: string | null | undefined,
    klass: C,
    label?: string,
    options?: SensitiveStringOptions
  ): SensitiveString<C> | null {
    if (value == null || value === '') {
      return null;
    }
    return new SensitiveString(value, klass, label, options);
  }

  /**
   * Map over the raw value, producing a new SensitiveString.
   * The transformation function receives the raw value.
   *
   * @param fn - Transformation function
   * @param ctx - Reveal context for audit
   * @returns A new SensitiveString with the transformed value, preserving class and label
   * @throws If policy checking fails (e.g., context required but not provided).
   */
  map(fn: (value: string) => string, ctx?: RevealContext): SensitiveString<C> {
    const value = this.#readRawValue('expose', ctx);
    return SensitiveString.#derived(fn(value), this.klass, this.label, [this]);
  }

  /**
   * Reclassify this value with a different sensitivity class and/or label.
   * Creates a new SensitiveString with the same value but different class/label.
   *
   * @param newKlass - The new sensitivity class
   * @param newLabel - Optional new label (if undefined, preserves existing label)
   * @param ctx - Reveal context for audit
   * @returns A new SensitiveString with the new class
   * @throws If policy checking fails (e.g., context required but not provided).
   *
   * @remarks
   * Use with caution - this bypasses the automatic class escalation logic.
   */
  reclassify<D extends SensitivityClass>(
    newKlass: D,
    newLabel?: string,
    ctx?: RevealContext
  ): SensitiveString<D> {
    const value = this.#readRawValue('expose', ctx);
    return SensitiveString.#derived(value, newKlass, newLabel ?? this.label, [this]);
  }
}
