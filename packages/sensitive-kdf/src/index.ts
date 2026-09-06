/**
 * @platform-sec/sensitive-string-kdf
 *
 * Password hashing for `SensitiveString` values: Argon2, bcrypt and scrypt
 * behind one audited API, with the stored hash wrapped as a `credential`.
 *
 * Two functions. `hashForStorage` turns a password into something safe to put
 * in a database column, and `verifyHash` checks one against what is in that
 * column. Both read a protected value through `core`'s ordinary gate, so the
 * class policy, the audit hook, the deadline, the reveal budget and any
 * revocation all apply, and hashing a password appears in an audit log as the
 * exposure it is.
 *
 * This package exists rather than living in `core` because Argon2 and bcrypt
 * are native modules and `core` has no runtime dependencies. Both are optional
 * peer dependencies here: an application that installs neither can still hash
 * with scrypt, which `node:crypto` computes.
 *
 * ⚠️ `SensitiveString.hash('sha256')` in `core` is not password hashing and is
 * not an alternative to this. It is a fast digest, for a lookup key or a
 * correlation token; speed is the one property a stored password must not
 * have.
 *
 * @example
 * ```ts
 * import { SensitiveString } from '@platform-sec/sensitive-string-core';
 * import { hashForStorage, verifyHash } from '@platform-sec/sensitive-string-kdf';
 *
 * const password = new SensitiveString(body.password, 'credential', 'password');
 * const stored = await hashForStorage(password, { algorithm: 'argon2id' });
 *
 * await verifyHash(stored, body.password); // true
 * ```
 *
 * @packageDocumentation
 */

export { hashForStorage, verifyHash } from './storage.js';

export { MissingKdfModuleError, UnknownStoredHashError } from './errors.js';

export type {
  Argon2Options,
  BcryptOptions,
  KdfAlgorithm,
  ScryptOptions,
  StorageHashOptions,
} from './types.js';

// The floors, defaults and ceilings, so a caller can cite them rather than
// copy them, and a test can assert against the same numbers the code applies.
export {
  ARGON2_DEFAULT_HASH_LENGTH,
  ARGON2_DEFAULT_MEMORY_COST,
  ARGON2_DEFAULT_PARALLELISM,
  ARGON2_DEFAULT_TIME_COST,
  ARGON2_MIN_HASH_LENGTH,
  ARGON2_MIN_MEMORY_COST,
  ARGON2_MIN_TIME_COST,
  BCRYPT_DEFAULT_ROUNDS,
  BCRYPT_MAX_ROUNDS,
  BCRYPT_MIN_ROUNDS,
  MAX_BCRYPT_PASSWORD_BYTES,
  SCRYPT_DEFAULT_KEY_LENGTH,
  SCRYPT_DEFAULT_N,
  SCRYPT_DEFAULT_P,
  SCRYPT_DEFAULT_R,
  SCRYPT_MIN_KEY_LENGTH,
  SCRYPT_MIN_N,
  SCRYPT_MIN_R,
} from './options.js';
