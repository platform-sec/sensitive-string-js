/**
 * age on its own, decrypted in process.
 *
 * A single age-encrypted blob, with no SOPS document around it, does not need a
 * subprocess. `age-encryption` is a maintained TypeScript implementation by
 * age's own author, so this path decrypts in process and wraps, with no binary
 * requirement and no stdout buffer.
 *
 * The split is between a format with one cipher and a maintained JS
 * implementation, which is safe to do in process, and a format with five key
 * backends and a canonical Go implementation, which is not. "Why does one of
 * these shell out and the other does not" is the obvious question, so it is
 * answered here and in the README.
 *
 * The dependency is an optional peer and this module is its own entry point, so
 * an application using only the SOPS path never loads it.
 */

import { SensitiveString, createChildContext } from '@platform-sec/sensitive-string-core';
import type { RevealContext, SensitivityClass } from '@platform-sec/sensitive-string-core';
import { SecretPayloadError } from '@platform-sec/sensitive-string-secrets';

/**
 * The context an identity is read under.
 *
 * A child of whatever is ambient, so the reveal carries this module's name and
 * still reaches an application's audit sink. A fresh context object would name
 * the operation correctly and make the most security-relevant reveal in the
 * process the one nobody's `auditReveal` sees.
 */
function decryptContext(): RevealContext {
  return createChildContext({ name: 'age-decrypt', reason: 'decrypting an age ciphertext' });
}

/** The part of `age-encryption`'s `Decrypter` this module uses. */
export interface AgeDecrypter {
  addIdentity(identity: string): void;
  decrypt(file: Uint8Array, outputFormat: 'text'): Promise<string>;
}

export interface DecryptAgeOptions<C extends SensitivityClass = 'credential'> {
  /** The identity, as a credential. Revealed once, under this module's context. */
  readonly identity: SensitiveString<'credential'>;
  /**
   * A `Decrypter` from `age-encryption`.
   *
   * Injected rather than constructed, so this module imports nothing from the
   * optional peer and a caller who has it installed passes `new Decrypter()`.
   */
  readonly decrypter: AgeDecrypter;
  readonly klass?: C;
  readonly label?: string;
}

/**
 * Decrypt an age ciphertext and wrap the result.
 *
 * @example
 * ```ts
 * import { Decrypter } from 'age-encryption';
 * import { decryptAge } from '@platform-sec/sensitive-string-sops/age';
 *
 * const secret = await decryptAge(ciphertext, {
 *   identity: ageIdentity,
 *   decrypter: new Decrypter(),
 *   label: 'webhook-key',
 * });
 * ```
 *
 * @throws SecretPayloadError when the ciphertext does not decrypt. The
 *   underlying error is discarded rather than chained, for the reason every
 *   decoder in this row gives: a decoder that fails on content puts content in
 *   its error, and every reporter serializes the cause chain.
 */
export async function decryptAge<C extends SensitivityClass = 'credential'>(
  ciphertext: Uint8Array | string,
  options: DecryptAgeOptions<C>
): Promise<SensitiveString<C>> {
  const label = options.label ?? 'age';
  const klass = (options.klass ?? 'credential') as C;

  options.decrypter.addIdentity(options.identity.reveal(decryptContext()));

  const bytes = typeof ciphertext === 'string' ? new TextEncoder().encode(ciphertext) : ciphertext;

  let plaintext: string;

  try {
    plaintext = await options.decrypter.decrypt(bytes, 'text');
  } catch {
    throw new SecretPayloadError(
      `The age ciphertext for '${label}' did not decrypt. The identity does not match any ` +
        `recipient, or the file is not an age file.`,
      label,
      'age'
    );
  }

  return new SensitiveString<C>(plaintext, klass, label);
}
