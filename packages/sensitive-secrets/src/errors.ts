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
