import type { SensitiveStringOptions } from './types.js';
import { SensitiveStringError } from './errors.js';

/**
 * A reveal that waits on a verification.
 *
 * The destination binding answers where a value may go; it cannot answer
 * whether the recipient has been checked yet. The adoption corpus has the
 * case: a credential whose destination trust is decided by an SSH host key
 * digest against a known-hosts store, an asynchronous check that settles
 * after the connection is opened and before the password may be sent. No
 * arrangement of wrappers expressed "not readable until this promise
 * resolves", and the record said a primitive for it would sit beside the
 * model rather than inside it.
 *
 * This is that primitive. A value constructed with `releasedBy` holds a cell
 * that starts `pending`, becomes `released` when the promise resolves `true`,
 * and becomes `refused`, for good, when it resolves anything else or rejects.
 * The gate reads the cell on every exposing read. Nothing lifts a refusal:
 * a verification that did not say yes has said no, and a retry is a new
 * value with a new check.
 *
 * Shared by reference between a value and its derivatives, like every other
 * lifecycle cell, though a derivative of an unreleased value cannot be built:
 * deriving reads the value, and the read refuses.
 */

/** Where a released value stands. */
export type ReleaseStatus = 'pending' | 'released' | 'refused';

/**
 * Raised when an operation needs the raw value of an instance whose
 * verification has not settled, or settled against it.
 *
 * `status` separates the two, because they invite different responses: a
 * caller who reads a `pending` value read it too early and can await the
 * verification, and one who reads a `refused` value has a credential the
 * check rejected. `label` is developer text; the message carries no part of
 * the value.
 */
export class UnreleasedSensitiveValueError extends SensitiveStringError {
  override readonly name = 'UnreleasedSensitiveValueError';
  override readonly code = 'unreleased-value';

  constructor(
    readonly status: Exclude<ReleaseStatus, 'released'>,
    readonly label?: string,
    detail?: string,
    cause?: unknown
  ) {
    const named = label !== undefined ? ` '${label}'` : '';

    super(
      status === 'pending'
        ? `Sensitive value${named} cannot be read yet: the verification it was constructed ` +
            'with has not settled. Await it before reading the value.'
        : `Sensitive value${named} cannot be read: ${detail ?? 'its verification refused'}. ` +
            'A refusal is final; construct a new value with a new verification to try again.',
      cause === undefined ? undefined : { cause }
    );
  }
}

/**
 * The release state a value and its derivatives share.
 *
 * Mutated only by the promise's own settlement, from inside this module. The
 * cell is the promise's answer and nothing else: there is no setter, and no
 * way to release a value from outside.
 */
export interface ReleaseCell {
  status: ReleaseStatus;
  /** Why a `refused` cell refused, as text that carries no value. */
  detail: string | undefined;
  /** What the verification threw, when it threw. */
  cause: unknown;
}

/** A state object that may carry a release cell. */
export interface ReleaseHolder {
  readonly release: ReleaseCell | undefined;
}

function describeType(value: unknown): string {
  return value === null ? 'null' : typeof value;
}

/**
 * Build the release cell for a newly constructed value, or `undefined` when
 * the value waits on nothing.
 *
 * The option has to be a thenable. A plain boolean is refused rather than read
 * as an already-settled verification, because a caller who wrote
 * `releasedBy: verified` where `verified` is the result rather than the
 * promise has a bug this would otherwise hide in both directions: `true`
 * releases a value nothing checked and `false` bricks one for no reason.
 *
 * Both handlers are attached here, so a rejected verification is consumed by
 * the cell and never surfaces as an unhandled rejection: the refusal is
 * reported where the value is read, which is where it matters.
 *
 * @throws TypeError If `releasedBy` is not a thenable.
 */
export function planRelease(options: SensitiveStringOptions | undefined): ReleaseCell | undefined {
  const verification = options?.releasedBy;

  if (verification === undefined) {
    return undefined;
  }

  if (
    verification === null ||
    (typeof verification !== 'object' && typeof verification !== 'function') ||
    typeof (verification as { then?: unknown }).then !== 'function'
  ) {
    throw new TypeError(
      `SensitiveString: releasedBy must be a promise of a boolean, received ${describeType(verification)}. ` +
        'Pass the verification itself, not its result.'
    );
  }

  const cell: ReleaseCell = { status: 'pending', detail: undefined, cause: undefined };

  // `Promise.resolve` adopts a foreign thenable, so a handler runs at most
  // once whatever the thenable does. The cell latches: the first settlement
  // decides, and a status other than `pending` is never overwritten.
  Promise.resolve(verification).then(
    (answer) => {
      if (cell.status !== 'pending') {
        return;
      }

      if (answer === true) {
        cell.status = 'released';
        return;
      }

      cell.status = 'refused';
      cell.detail =
        answer === false
          ? 'its verification refused'
          : `its verification answered with ${describeType(answer)} instead of a boolean, which ` +
            'is read as a refusal';
    },
    (error: unknown) => {
      if (cell.status !== 'pending') {
        return;
      }

      cell.status = 'refused';
      cell.detail = 'its verification threw instead of answering';
      cell.cause = error;
    }
  );

  return cell;
}

/**
 * The first release cell among these states that is not released, or
 * `undefined` when every value this one came from is readable.
 *
 * A pending cell is reported ahead of a refused one only by state order; both
 * refuse, and a value derived from a refused value cannot exist anyway.
 */
export function releaseInForce(states: readonly ReleaseHolder[]): ReleaseCell | undefined {
  for (const state of states) {
    const cell = state.release;

    if (cell !== undefined && cell.status !== 'released') {
      return cell;
    }
  }

  return undefined;
}
