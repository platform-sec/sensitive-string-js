/**
 * Every error this package throws, and the rule they all obey.
 *
 * No error here contains secret material. That is not a style preference: a
 * decoder that fails on content puts content in its error, and the error goes
 * to the tracker. `JSON.parse` on a string that is not JSON echoes the whole
 * input when it is 20 characters or fewer and the first 10 characters
 * otherwise, measured on Node 22.15.0, so calling a JSON read on a secret that
 * turns out to hold a bare API key discloses it through a `SyntaxError`.
 *
 * The consequence is that none of these errors sets `cause`. Chaining the
 * original would satisfy the usual advice about preserving errors and would
 * undo the entire fix, because every error reporter serializes the cause chain.
 */

/** Base class, so a caller can catch everything this layer produces. */
export class SecretError extends Error {
  override readonly name: string = 'SecretError';

  constructor(
    message: string,
    /** The logical path of the secret. Never an account-scoped identifier. */
    readonly path: string,
    /** The version the provider served, where one is known. */
    readonly version?: string
  ) {
    super(message);
  }
}

/**
 * A payload could not be decoded, or did not have the shape the caller declared.
 *
 * The message names the source and never the content. There is no `cause`, on
 * purpose: see the note at the top of this file before adding one.
 */
export class SecretPayloadError extends SecretError {
  override readonly name = 'SecretPayloadError';
}

/** The provider reports the secret, or the requested version, as absent. */
export class SecretNotFoundError extends SecretError {
  override readonly name = 'SecretNotFoundError';
}

/** Why a write was refused before anything was transmitted. */
export type WriteRefusal =
  /** The bytes about to be sent contain a redaction marker. */
  | 'marker'
  /** No `RevealContext` was supplied, and a write must not use an ambient one. */
  | 'no-context'
  /** The value read back after the write did not match what was written. */
  | 'read-back'
  /** The provider does not accept the payload shape that was offered. */
  | 'shape';

/**
 * A write was refused, or a write's read-back verification failed.
 *
 * `marker` is the refusal this class exists for. A `SensitiveString` handed to
 * a provider's write call stringifies to `[REDACTED:credential]` and is stored
 * under that value; the write succeeds, the provider reports success, and every
 * later reader receives the literal marker as their password.
 */
export class SecretWriteRefusedError extends SecretError {
  override readonly name = 'SecretWriteRefusedError';

  constructor(
    readonly reason: WriteRefusal,
    message: string,
    path: string,
    version?: string
  ) {
    super(message, path, version);
  }
}

/** Which rule refused a reference, before the store was ever reached. */
export type ReferenceRefusal =
  /** Not a reference at all, or one missing a member the format requires. */
  | 'shape'
  /** A format version this build does not know. */
  | 'format'
  /** Minted for a different store than the resolver was constructed for. */
  | 'store'
  /**
   * A path carrying a traversal, an empty segment or a control character, or a
   * path no allowlist entry covers.
   */
  | 'path'
  /** A version outside the accepted charset. */
  | 'version'
  /**
   * The matching entries resolve the other kind of reference, or none of them
   * declares the field this one names.
   */
  | 'field'
  /**
   * No `RevealContext` was supplied, and resolving must not use an ambient one.
   *
   * The receiver's own mistake rather than the sender's, and named separately
   * from `'shape'` for that reason: the two lead to different fixes and only
   * one of them is a reason to distrust whoever sent the reference. It is the
   * same refusal the write path makes for the same reason.
   */
  | 'no-context';

/**
 * A reference was refused before anything was fetched.
 *
 * The path is on the `path` property and never in `message`. `ref.path` is text
 * a sender chose, a refusal is the case where the sender is least likely to be
 * one this receiver trusts, and a message that interpolated it would put
 * attacker-chosen text into the receiver's own logs. Same for the version, on
 * `version`.
 *
 * What is on `path` after a refusal is what the sender asked for, which may
 * name no secret that exists in any store. A handler that logs it is logging a
 * request rather than an identifier of anything.
 */
export class ReferenceRefusedError extends SecretError {
  override readonly name = 'ReferenceRefusedError';

  constructor(
    readonly reason: ReferenceRefusal,
    message: string,
    path: string,
    version?: string
  ) {
    super(message, path, version);
  }
}
