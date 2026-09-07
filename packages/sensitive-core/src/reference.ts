import { probeProperty } from './probe.js';
import { hasPolicy } from './policy.js';
import type { SensitivityClass } from './types.js';

/**
 * The wire shape of a pointer to a value in a secrets store, and the guards
 * that recognize one.
 *
 * `serialize()` puts the raw value on the wire and asks the transport for
 * confidentiality. A reference asks for nothing: it names where the value is
 * and the receiver fetches it with its own credentials, so the value never
 * leaves the process that read it. That is the whole of what this file knows.
 * Minting a reference needs the store identity, the version and the provider,
 * and resolving one needs credentials and an authorization decision, so both
 * live in `@platform-sec/sensitive-string-secrets`. The format lives here for
 * the same reason the `serialize()` format does: the walks that must decide
 * what to do with a wire object when they meet one are here.
 *
 * What they decide, for this shape, is to leave it alone. A reference carries
 * no secret material at any version of the format, and reading one gets an
 * attacker no closer to the value than the label already does, since resolving
 * it needs credentials of their own. Redacting it would break the debugging
 * that a reference-passing system exists to make possible, which is being able
 * to see which secret a job refers to. So there is no `redactReference` next to
 * `redactSerialized`, the walks descend into a reference as they would into any
 * other plain object, and `containsSensitive()` answers false for one. Those
 * are asserted positively in `reference.test.ts` rather than left to be
 * incidental, so that a later change to redact everything carrying a
 * `__sensitive`-shaped marker fails a test and arrives here.
 */

/**
 * The only format version this build understands.
 *
 * A receiver that does not recognize a version refuses rather than guessing,
 * and the refusal names the version it saw and nothing else from the payload.
 */
export const REFERENCE_VERSION = 1;

/**
 * A pointer to a value in a secrets store. Carries no secret material.
 *
 * `klass` and `label` are advisory: they arrive from the sender, and a receiver
 * that took either as given would let the sender choose how its own runtime
 * treats the value it fetches. A resolver derives the label itself and takes
 * the more restrictive of its own class and this one, which is the direction a
 * wire field is allowed to move a classification in.
 */
export interface SensitiveValueReference {
  readonly __sensitiveRef: true;
  readonly v: typeof REFERENCE_VERSION;
  /** Logical store identity, agreed out of band. Not a URL and not an account id. */
  readonly store: string;
  /** The logical path within that store, under the label rule. */
  readonly path: string;
  /** The concrete version the sender read. Absent means the sender pinned none. */
  readonly version?: string;
  /** One field of a multi-value secret, as a dot path. */
  readonly field?: string;
  /** Advisory. A resolver takes the more restrictive of this and its own rule. */
  readonly klass?: SensitivityClass;
  /** Advisory. A resolver derives its own under the label rule. */
  readonly label?: string;
}

/**
 * Whether an object carries the reference marker, judged by the marker alone.
 *
 * Separate from {@link isSensitiveValueReference} because the two answer
 * different questions. This one asks whether a sender meant to send a
 * reference, which is what decides between "this is not a reference at all" and
 * "this is a reference this build cannot accept": a receiver that answered the
 * first for a marked object with a version it does not know would report a
 * caller's own payload as malformed rather than reporting the version skew it
 * actually found.
 *
 * The read goes through `probeProperty` because a walk runs it against every
 * object it reaches, and an object that refuses the question is not a payload
 * this library built.
 */
export function carriesReferenceMarker(value: object): boolean {
  return probeProperty(value, '__sensitiveRef') === true;
}

/**
 * The format version a marked object claims, or `undefined` when it claims
 * none this build can read.
 *
 * A receiver refusing a version it does not know has to name the version it
 * saw, and it must name a number rather than whatever the sender put in the
 * field, so the read is guarded and anything that is not a number answers
 * `undefined`.
 */
export function referenceFormatVersion(value: object): number | undefined {
  const version = probeProperty(value, 'v');

  return typeof version === 'number' && Number.isFinite(version) ? version : undefined;
}

/** Whether a value is a non-empty string, which every required field must be. */
function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value !== '';
}

/** Whether an optional field is absent or a non-empty string. */
function isAbsentOrNonEmptyString(value: unknown): boolean {
  return value === undefined || isNonEmptyString(value);
}

/**
 * Whether a value is a well-formed reference of the version this build knows.
 *
 * Structural rather than nominal, because a reference crosses a process
 * boundary as JSON and arrives as a plain object that no `instanceof` can
 * recognize. Every required member is checked, so a resolver that has this
 * answer can read the members it needs without repeating the question, and the
 * advisory `klass` is checked against the policy registry here rather than
 * accepted as any string: a class the receiving process never registered is not
 * a class it can act on.
 *
 * A registered class is still only advisory. This answers whether the field is
 * readable, never whether the receiver should honour it.
 */
export function isSensitiveValueReference(value: unknown): value is SensitiveValueReference {
  if (typeof value !== 'object' || value === null) {
    return false;
  }

  if (!carriesReferenceMarker(value)) {
    return false;
  }

  if (referenceFormatVersion(value) !== REFERENCE_VERSION) {
    return false;
  }

  if (!isNonEmptyString(probeProperty(value, 'store'))) {
    return false;
  }

  if (!isNonEmptyString(probeProperty(value, 'path'))) {
    return false;
  }

  if (!isAbsentOrNonEmptyString(probeProperty(value, 'version'))) {
    return false;
  }

  if (!isAbsentOrNonEmptyString(probeProperty(value, 'field'))) {
    return false;
  }

  if (!isAbsentOrNonEmptyString(probeProperty(value, 'label'))) {
    return false;
  }

  const klass = probeProperty(value, 'klass');

  return klass === undefined || (typeof klass === 'string' && hasPolicy(klass as SensitivityClass));
}
