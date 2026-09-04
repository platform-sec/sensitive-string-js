import { DEFAULT_DENY_KEYS, DEFAULT_DENY_PATHS } from './deny.js';
import type { ResolvedScrubPolicy, ScrubPolicy } from './types.js';

/**
 * The replacement written in place of a denied value.
 *
 * Deliberately not `[REDACTED]`. That is the shape of this library's own
 * markers, and a scrubber that emits one would be indistinguishable from the
 * marker sighting the walk reports, which is evidence that a different
 * integration failed. Two different findings must not produce the same string.
 */
export const DEFAULT_CENSOR = '[SCRUBBED]';

/** Raised when a policy cannot be resolved. Thrown at install time, never on the error path. */
export class ScrubPolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ScrubPolicyError';
  }
}

/**
 * Fold a caller's policy into the defaults and compile the matchers.
 *
 * Runs once, at install time, so the walk does no list arithmetic per payload
 * and an unusable policy fails where the stack trace points at the caller's
 * `init` rather than at an event six hours later.
 *
 * @throws ScrubPolicyError when `allowKeys` carries an entry without a
 *         non-empty reason, or when a key is both denied and allowed.
 */
export function resolveScrubPolicy(policy: ScrubPolicy = {}): ResolvedScrubPolicy {
  const denyKeys = new Set(DEFAULT_DENY_KEYS.map(lower));

  for (const key of policy.denyKeys ?? []) {
    denyKeys.add(lower(key));
  }

  for (const allowance of policy.allowKeys ?? []) {
    // Removing a key from the denylist is the one operation in this package
    // that makes it leak more. Requiring a reason is what makes the line
    // reviewable in a configuration diff rather than a bare name in a list.
    if (typeof allowance?.key !== 'string' || allowance.key === '') {
      throw new ScrubPolicyError('allowKeys entries need a key name');
    }

    if (typeof allowance.reason !== 'string' || allowance.reason.trim() === '') {
      throw new ScrubPolicyError(
        `allowKeys entry for '${allowance.key}' needs a reason explaining why the value is safe to send`
      );
    }

    if ((policy.denyKeys ?? []).some((key) => lower(key) === lower(allowance.key))) {
      throw new ScrubPolicyError(
        `'${allowance.key}' appears in both denyKeys and allowKeys; one of the two is a mistake`
      );
    }

    denyKeys.delete(lower(allowance.key));
  }

  const denyPaths = new Set(DEFAULT_DENY_PATHS.map(lower));

  for (const path of policy.denyPaths ?? []) {
    denyPaths.add(lower(path));
  }

  return {
    denyKeys,
    denyPaths,
    urlKeys: new Set((policy.urlKeys ?? []).map(lower)),
    censor: policy.censor ?? DEFAULT_CENSOR,
    onMarker: policy.onMarker ?? 'tag',
    reportLabels: policy.reportLabels ?? false,
    onScrub: policy.onScrub,
  };
}

/**
 * Merge a vendor package's own policy into a caller's, caller last.
 *
 * A vendor package knows the paths of its payload shape and the caller knows
 * their application. Both sets of `denyKeys`, `denyPaths` and `urlKeys` apply;
 * the caller wins on the single-valued fields, and `allowKeys` is the caller's
 * alone, since a vendor package has no business handing back a default.
 */
export function mergeScrubPolicy(vendor: ScrubPolicy, caller: ScrubPolicy = {}): ScrubPolicy {
  const merged: ScrubPolicy = {
    denyKeys: [...(vendor.denyKeys ?? []), ...(caller.denyKeys ?? [])],
    denyPaths: [...(vendor.denyPaths ?? []), ...(caller.denyPaths ?? [])],
    urlKeys: [...(vendor.urlKeys ?? []), ...(caller.urlKeys ?? [])],
    censor: caller.censor ?? vendor.censor ?? DEFAULT_CENSOR,
    onMarker: caller.onMarker ?? vendor.onMarker ?? 'tag',
    reportLabels: caller.reportLabels ?? vendor.reportLabels ?? false,
  };

  const allowKeys = caller.allowKeys ?? vendor.allowKeys;
  const onScrub = caller.onScrub ?? vendor.onScrub;

  // `exactOptionalPropertyTypes` is on, so an absent field is absent rather
  // than present and undefined.
  return {
    ...merged,
    ...(allowKeys === undefined ? {} : { allowKeys }),
    ...(onScrub === undefined ? {} : { onScrub }),
  };
}

function lower(value: string): string {
  return value.toLowerCase();
}
