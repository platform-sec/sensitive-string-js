import type {
  RenewalOptions,
  RenewAuditDetails,
  SensitivityClass,
  SensitivityPolicy,
  SensitiveStringOptions,
} from './types.js';

/**
 * The intrinsic `getTime`, so a deadline is read from a Date's internal slot.
 *
 * Calling it verifies the internal slot across realms and bypasses an
 * instance's overridden `getTime`, which could otherwise report one deadline to
 * the constructor and another to anything else that inspected the same object.
 */
// eslint-disable-next-line @typescript-eslint/unbound-method -- detaching it is the point, per the note above; it is invoked with an explicit receiver via .call()
const DATE_GET_TIME = Date.prototype.getTime;

/**
 * The largest time value ECMAScript can represent, from the Date specification.
 *
 * A duration is only bounded by the float range, so a deadline computed from one
 * can land past this. Such a deadline is worse than useless: `new Date()` of it
 * is an Invalid Date, `now < deadline` is true forever, and `toISOString()`
 * throws when the value is serialized. A deadline that can never be reached is
 * the same as no deadline at all, so it is rejected rather than accepted as one.
 */
const MAX_TIMESTAMP = 8_640_000_000_000_000;

/**
 * Describe a rejected option without disclosing it.
 */
function describeType(value: unknown): string {
  return value === null ? 'null' : typeof value;
}

/**
 * Raised when an operation needs the raw value of an expired instance.
 *
 * Callers distinguish this from a policy denial to decide whether to fetch a
 * fresh secret or to fail the request outright.
 */
export class ExpiredSensitiveValueError extends Error {
  override readonly name = 'ExpiredSensitiveValueError';

  constructor(
    readonly expiredAt: Date,
    readonly attemptedAt: Date,
    readonly label?: string
  ) {
    super(
      `Sensitive value${label !== undefined ? ` '${label}'` : ''} expired at ` +
        expiredAt.toISOString()
    );
  }

  /** Milliseconds between the deadline and the attempted access. */
  get expiredFor(): number {
    return this.attemptedAt.getTime() - this.expiredAt.getTime();
  }
}

/** Why a renewal was refused. */
export type RenewalRefusal = 'policy' | 'exhausted' | 'no-expiration' | 'derived' | 'capped';

/**
 * Raised when `renew()` cannot extend a deadline.
 */
export class RenewalNotAllowedError extends Error {
  override readonly name = 'RenewalNotAllowedError';

  constructor(
    readonly reason: RenewalRefusal,
    readonly label?: string
  ) {
    const reasons: Record<RenewalRefusal, string> = {
      policy: 'renewal is not allowed for this value',
      exhausted: 'the maximum number of renewals has been reached',
      'no-expiration': 'the value has no expiration to renew',
      derived: 'the value is derived from another value, so renew the value it came from',
      capped: 'the lifetime cap leaves no room to extend',
    };

    super(`Cannot renew${label !== undefined ? ` '${label}'` : ''}: ${reasons[reason]}`);
  }
}

/**
 * Expiry state, shared by reference between a value and everything derived from
 * it, so a substring of an expiring value expires with it and a renewal of the
 * original is seen by every derivative.
 */
export interface ExpiryState {
  /** Deadline, epoch milliseconds, or `undefined` when the value does not expire. */
  deadline: number | undefined;
  /**
   * Latest deadline any renewal may reach, epoch milliseconds. The policy's
   * `maxTtl` measured from construction, so the cap is absolute rather than
   * something a renewal can push forward.
   */
  readonly lifetimeCap: number | undefined;
  readonly allowRenewal: boolean;
  readonly maxRenewals: number | undefined;
  renewalCount: number;
  readonly onExpire: (() => void) | undefined;
  /** Whether `onExpire` has already fired for the current deadline. */
  notified: boolean;
}

/**
 * Validate a duration in milliseconds.
 *
 * Zero is a valid duration and means "already expired". Rejecting it, or
 * testing the option for truthiness, would turn the most conservative TTL a
 * caller can ask for into no TTL at all.
 */
function requireDuration(value: unknown, name: string): number | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (typeof value !== 'number') {
    throw new TypeError(
      `SensitiveString: ${name} must be a number of milliseconds, received ${describeType(value)}`
    );
  }

  if (!Number.isFinite(value) || value < 0) {
    throw new RangeError(`SensitiveString: ${name} must be a non-negative, finite number`);
  }

  return value;
}

/**
 * Validate an absolute deadline and read it as epoch milliseconds.
 *
 * The result is a number, so a caller that mutates the Date it passed does not
 * move a deadline the library already accepted.
 */
function requireDeadline(value: unknown, name: string): number | undefined {
  if (value === undefined) {
    return undefined;
  }

  let time: number;
  try {
    time = DATE_GET_TIME.call(value as Date);
  } catch {
    throw new TypeError(`SensitiveString: ${name} must be a Date, received ${describeType(value)}`);
  }

  if (!Number.isFinite(time)) {
    throw new RangeError(`SensitiveString: ${name} must be a valid Date`);
  }

  return time;
}

/**
 * Reject a computed deadline that no Date can represent.
 */
function requireRepresentable(deadline: number, name: string): number {
  if (deadline > MAX_TIMESTAMP) {
    throw new RangeError(
      `SensitiveString: ${name} puts the deadline past the largest representable date, ` +
        new Date(MAX_TIMESTAMP).toISOString()
    );
  }

  return deadline;
}

/**
 * Validate a renewal budget.
 */
function requireCount(value: unknown, name: string): number | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (typeof value !== 'number') {
    throw new TypeError(
      `SensitiveString: ${name} must be a number, received ${describeType(value)}`
    );
  }

  if (!Number.isInteger(value) || value < 0) {
    throw new RangeError(`SensitiveString: ${name} must be a non-negative integer`);
  }

  return value;
}

function requireFunction(value: unknown, name: string): (() => void) | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (typeof value !== 'function') {
    throw new TypeError(
      `SensitiveString: ${name} must be a function, received ${describeType(value)}`
    );
  }

  return value as () => void;
}

function requireBoolean(value: unknown, name: string): boolean | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (typeof value !== 'boolean') {
    throw new TypeError(
      `SensitiveString: ${name} must be a boolean, received ${describeType(value)}`
    );
  }

  return value;
}

/**
 * Decide whether this value may ever be renewed.
 *
 * A policy that sets `allowRenewal: false` is a prohibition and the instance
 * option cannot lift it, because a control every caller can switch off is not a
 * control. A policy that says nothing, or that permits renewal, leaves the
 * decision to the caller, whose default is the class default: credentials are
 * not renewable, everything else is.
 */
function resolveAllowRenewal(
  options: SensitiveStringOptions | undefined,
  klass: SensitivityClass,
  policy: SensitivityPolicy
): boolean {
  if (policy.allowRenewal === false) {
    return false;
  }

  return (
    requireBoolean(options?.allowRenewal, 'allowRenewal') ??
    policy.allowRenewal ??
    klass !== 'credential'
  );
}

/**
 * Build the expiry state for a newly constructed value.
 *
 * Every deadline is decided here, at creation, so a policy change later in the
 * process cannot extend the life of a value that already exists.
 *
 * @throws TypeError If an option has the wrong type.
 * @throws RangeError If a duration is negative or a Date is invalid.
 * @throws Error If both `ttl` and `expiresAt` are given, or the policy requires an expiration and none was set.
 */
export function planExpiry(
  options: SensitiveStringOptions | undefined,
  klass: SensitivityClass,
  policy: SensitivityPolicy
): ExpiryState {
  const createdAt = Date.now();
  const ttl = requireDuration(options?.ttl, 'ttl');
  const absolute = requireDeadline(options?.expiresAt, 'expiresAt');

  if (ttl !== undefined && absolute !== undefined) {
    throw new Error(
      'SensitiveString: ttl and expiresAt are mutually exclusive; pass a duration or a deadline'
    );
  }

  const maxTtl = requireDuration(policy.maxTtl, 'policy maxTtl');
  const lifetimeCap = maxTtl === undefined ? undefined : createdAt + maxTtl;

  let deadline: number | undefined;
  if (ttl !== undefined) {
    deadline = createdAt + ttl;
  } else if (absolute !== undefined) {
    deadline = absolute;
  } else {
    const defaultTtl = requireDuration(policy.defaultTtl, 'policy defaultTtl');
    deadline = defaultTtl === undefined ? undefined : createdAt + defaultTtl;
  }

  // The cap applies to a deadline the caller chose as well as to one the policy
  // supplied, and it applies even when neither set a deadline at all. A class
  // that caps its lifetime has no unexpiring values.
  if (lifetimeCap !== undefined) {
    deadline = deadline === undefined ? lifetimeCap : Math.min(deadline, lifetimeCap);
  }

  // After the cap, which can bring an out-of-range deadline back into range. A
  // class that caps its lifetime has already decided how long is too long.
  if (deadline !== undefined) {
    requireRepresentable(deadline, 'the requested lifetime');
  }

  if (deadline === undefined && policy.requireExpiration === true) {
    throw new Error(
      `SensitiveString: sensitivity class '${klass}' requires an expiration; ` +
        'pass ttl or expiresAt'
    );
  }

  return {
    deadline,
    lifetimeCap,
    allowRenewal: resolveAllowRenewal(options, klass, policy),
    maxRenewals: requireCount(options?.maxRenewals, 'maxRenewals'),
    renewalCount: 0,
    onExpire: requireFunction(options?.onExpire, 'onExpire'),
    notified: false,
  };
}

/**
 * The deadline this state has passed, or `undefined` while it is still live.
 *
 * A value is not usable at its own expiry instant, so the comparison is
 * inclusive. When `notify` is set, the first detection fires `onExpire`; the
 * flag is raised before the call, so a callback that reaches back into the
 * value cannot start an unbounded recursion.
 */
export function expiredDeadline(
  state: ExpiryState,
  now: number,
  notify: boolean
): number | undefined {
  const { deadline } = state;

  if (deadline === undefined || now < deadline) {
    return undefined;
  }

  if (notify && !state.notified) {
    state.notified = true;

    try {
      state.onExpire?.();
    } catch {
      // A notification that fails must not replace the expiry error with its
      // own, which would hide why the operation was denied.
    }
  }

  return deadline;
}

/**
 * A renewal that has been decided but not committed.
 */
export interface RenewalPlan {
  /** The deadline in force before the renewal. */
  readonly previous: number;
  /** The deadline the renewal would set. */
  readonly next: number;
}

/**
 * The deadline a renewal would produce, without committing it.
 *
 * Separating the decision from the commit keeps a refused renewal out of the
 * audit log, and lets an audit hook that throws stop the extension.
 *
 * @throws RangeError If `additionalTtl` is not a positive, finite number.
 * @throws RenewalNotAllowedError If the value cannot be renewed, or the cap leaves no room.
 */
export function planRenewal(
  state: ExpiryState,
  additionalTtl: number,
  options: RenewalOptions,
  label: string | undefined
): RenewalPlan {
  const previous = state.deadline;

  if (previous === undefined) {
    throw new RenewalNotAllowedError('no-expiration', label);
  }

  if (!state.allowRenewal) {
    throw new RenewalNotAllowedError('policy', label);
  }

  if (state.maxRenewals !== undefined && state.renewalCount >= state.maxRenewals) {
    throw new RenewalNotAllowedError('exhausted', label);
  }

  if (typeof additionalTtl !== 'number') {
    throw new TypeError(
      'SensitiveString.renew: additionalTtl must be a number of milliseconds, received ' +
        describeType(additionalTtl)
    );
  }

  if (!Number.isFinite(additionalTtl) || additionalTtl <= 0) {
    throw new RangeError('SensitiveString.renew: additionalTtl must be a positive, finite number');
  }

  const maxExtension = requireDeadline(options.maxExtension, 'maxExtension');
  const now = Date.now();

  // An expired value extends from now rather than from its lapsed deadline, so
  // a renewal grants the full duration asked for instead of a fraction of it.
  let next = Math.max(previous, now) + additionalTtl;

  if (maxExtension !== undefined) {
    next = Math.min(next, maxExtension);
  }

  if (state.lifetimeCap !== undefined) {
    next = Math.min(next, state.lifetimeCap);
  }

  requireRepresentable(next, 'additionalTtl');

  // Reporting success for a renewal a cap swallowed would leave the caller
  // believing an expired value is live again.
  if (next <= previous) {
    throw new RenewalNotAllowedError('capped', label);
  }

  return { previous, next };
}

/**
 * The audit record for a committed renewal.
 *
 * Deadlines are ISO strings rather than Dates: an audit sink receives a record
 * it can serialize directly and cannot use to move a deadline.
 */
export function renewAuditDetails(state: ExpiryState, plan: RenewalPlan): RenewAuditDetails {
  return Object.freeze({
    operation: 'renew' as const,
    previousExpiresAt: new Date(plan.previous).toISOString(),
    expiresAt: new Date(plan.next).toISOString(),
    renewalCount: state.renewalCount + 1,
  });
}
