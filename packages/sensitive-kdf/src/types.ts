/**
 * Password hashing algorithms this package will produce.
 *
 * `argon2id` is the one to choose. `argon2i` and `argon2d` exist because a
 * caller migrating an existing store may have to reproduce what is already in
 * it; neither is a better answer than `argon2id` for a new system.
 */
export type KdfAlgorithm = 'argon2id' | 'argon2i' | 'argon2d' | 'bcrypt' | 'scrypt';

/**
 * Argon2 parameters. Defaults follow the OWASP Password Storage Cheat Sheet's
 * higher configuration: 64 MiB of memory, three passes, four lanes.
 *
 * Every parameter has a floor as well as a default, and the floor is what the
 * defaults are there to keep callers away from having to think about. A number
 * below it is refused rather than quietly raised, because a caller who wrote
 * `memoryCost: 1024` believed something about the cost of an offline attack
 * and needs to be told it was wrong.
 */
export interface Argon2Options {
  algorithm: 'argon2id' | 'argon2i' | 'argon2d';
  /** Memory in KiB. Minimum 19456 (19 MiB), default 65536 (64 MiB). */
  memoryCost?: number;
  /** Passes over memory. Minimum 2, default 3. */
  timeCost?: number;
  /**
   * Lanes. Minimum 1, maximum 64, default 4.
   *
   * Argon2 also requires `memoryCost` to be at least 8 times this, which the
   * floors above already guarantee.
   */
  parallelism?: number;
  /** Output bytes. Minimum 16, default 32. */
  hashLength?: number;
}

/**
 * bcrypt parameters.
 *
 * ⚠️ bcrypt hashes at most 72 bytes of a password and silently ignores the
 * rest, which makes two different passwords sharing a 72-byte prefix verify
 * against each other's hash. This package refuses a longer password instead,
 * on both the hashing and the verifying side.
 */
export interface BcryptOptions {
  algorithm: 'bcrypt';
  /** Cost exponent. Minimum 10, default 12, maximum 20. */
  rounds?: number;
}

/**
 * scrypt parameters, computed by `node:crypto` and needing no native module.
 *
 * The default is the `N = 2^14, r = 8, p = 1` configuration OWASP names, which
 * is 16 MiB of memory per hash.
 */
export interface ScryptOptions {
  algorithm: 'scrypt';
  /** CPU and memory cost. A power of two, minimum 16384, default 16384. */
  N?: number;
  /** Block size. Minimum 8, default 8. */
  r?: number;
  /** Parallelization. Minimum 1, default 1. */
  p?: number;
  /** Output bytes. Minimum 32, default 64. */
  keyLength?: number;
}

/** What to hash with. The `algorithm` field selects the rest of the shape. */
export type StorageHashOptions = Argon2Options | BcryptOptions | ScryptOptions;
