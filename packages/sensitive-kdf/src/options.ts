import type {
  Argon2Options,
  BcryptOptions,
  KdfAlgorithm,
  ScryptOptions,
  StorageHashOptions,
} from './types.js';

/**
 * Validated parameters, with every default applied.
 *
 * Producing one needs no access to the value, so a call with impossible
 * parameters is refused before the password is read: a rejected call leaves no
 * audit record for a hash that was never taken, which is the same rule `core`
 * applies to a rejected `mask()`.
 */
export interface Argon2Plan {
  readonly algorithm: 'argon2id' | 'argon2i' | 'argon2d';
  readonly memoryCost: number;
  readonly timeCost: number;
  readonly parallelism: number;
  readonly hashLength: number;
}

export interface BcryptPlan {
  readonly algorithm: 'bcrypt';
  readonly rounds: number;
}

export interface ScryptPlan {
  readonly algorithm: 'scrypt';
  readonly N: number;
  readonly r: number;
  readonly p: number;
  readonly keyLength: number;
  /**
   * The memory ceiling handed to `node:crypto`, which defaults to 32 MiB and
   * refuses anything above it. Computed from the parameters rather than left
   * at the default, so raising `N` fails on this package's bound with a
   * message about the parameters instead of on OpenSSL's with a message about
   * memory.
   */
  readonly maxmem: number;
}

export type StoragePlan = Argon2Plan | BcryptPlan | ScryptPlan;

/**
 * The longest password bcrypt actually hashes.
 *
 * Everything past it is ignored, so two passwords sharing a 72-byte prefix
 * have the same hash. Refusing here is a deliberate deviation from what the
 * `bcrypt` package does, which is to truncate and say nothing.
 */
export const MAX_BCRYPT_PASSWORD_BYTES = 72;

/** Floors, defaults and ceilings, in one place so the documentation can cite them. */
export const ARGON2_MIN_MEMORY_COST = 19_456;
export const ARGON2_DEFAULT_MEMORY_COST = 65_536;
export const ARGON2_MIN_TIME_COST = 2;
export const ARGON2_DEFAULT_TIME_COST = 3;
export const ARGON2_DEFAULT_PARALLELISM = 4;
export const ARGON2_MIN_HASH_LENGTH = 16;
export const ARGON2_DEFAULT_HASH_LENGTH = 32;

export const BCRYPT_MIN_ROUNDS = 10;
export const BCRYPT_DEFAULT_ROUNDS = 12;
/**
 * A ceiling on the cost exponent, because it is an exponent.
 *
 * Each round doubles the work. 20 is around thirty seconds per hash on current
 * hardware; 31, which bcrypt accepts, is measured in weeks. A caller who types
 * one digit too many gets an error rather than a login handler that never
 * returns.
 */
export const BCRYPT_MAX_ROUNDS = 20;

export const SCRYPT_MIN_N = 16_384;
export const SCRYPT_DEFAULT_N = 16_384;
export const SCRYPT_MIN_R = 8;
export const SCRYPT_DEFAULT_R = 8;
export const SCRYPT_DEFAULT_P = 1;
export const SCRYPT_MIN_KEY_LENGTH = 32;
export const SCRYPT_DEFAULT_KEY_LENGTH = 64;

/** One gibibyte, the most memory this package will ask for in a single hash. */
export const SCRYPT_MAX_MEMORY_BYTES = 1_073_741_824;

const ALGORITHMS: readonly KdfAlgorithm[] = ['argon2id', 'argon2i', 'argon2d', 'bcrypt', 'scrypt'];

function describeType(value: unknown): string {
  return value === null ? 'null' : typeof value;
}

/**
 * A whole number within bounds, or the default when it was not given.
 */
function requireCount(
  value: unknown,
  name: string,
  fallback: number,
  minimum: number,
  maximum: number
): number {
  if (value === undefined) {
    return fallback;
  }

  if (typeof value !== 'number') {
    throw new TypeError(
      `hashForStorage: ${name} must be a number, received ${describeType(value)}`
    );
  }

  if (!Number.isInteger(value)) {
    throw new RangeError(`hashForStorage: ${name} must be a whole number, received ${value}`);
  }

  if (value < minimum) {
    throw new RangeError(
      `hashForStorage: ${name} must be at least ${minimum}, received ${value}; the floor is ` +
        'what makes an offline attack expensive and it may be raised but not lowered'
    );
  }

  if (value > maximum) {
    throw new RangeError(`hashForStorage: ${name} must be at most ${maximum}, received ${value}`);
  }

  return value;
}

function planArgon2(options: Argon2Options): Argon2Plan {
  const parallelism = requireCount(
    options.parallelism,
    'parallelism',
    ARGON2_DEFAULT_PARALLELISM,
    1,
    64
  );
  const memoryCost = requireCount(
    options.memoryCost,
    'memoryCost',
    ARGON2_DEFAULT_MEMORY_COST,
    ARGON2_MIN_MEMORY_COST,
    // 4 GiB expressed in KiB. Argon2 allows more; a web application asking for
    // it has made a mistake with a unit.
    4_194_304
  );

  // Argon2 requires memoryCost >= 8 * parallelism. No check for it here: the
  // memory floor is 19456 KiB and the lane ceiling is 64, so the smallest
  // memory this function can return is already 38 times the largest lane count
  // it can return, and a check would be a branch no input reaches.

  return {
    algorithm: options.algorithm,
    memoryCost,
    timeCost: requireCount(
      options.timeCost,
      'timeCost',
      ARGON2_DEFAULT_TIME_COST,
      ARGON2_MIN_TIME_COST,
      64
    ),
    parallelism,
    hashLength: requireCount(
      options.hashLength,
      'hashLength',
      ARGON2_DEFAULT_HASH_LENGTH,
      ARGON2_MIN_HASH_LENGTH,
      1024
    ),
  };
}

function planBcrypt(options: BcryptOptions): BcryptPlan {
  return {
    algorithm: 'bcrypt',
    rounds: requireCount(
      options.rounds,
      'rounds',
      BCRYPT_DEFAULT_ROUNDS,
      BCRYPT_MIN_ROUNDS,
      BCRYPT_MAX_ROUNDS
    ),
  };
}

function planScrypt(options: ScryptOptions): ScryptPlan {
  const N = requireCount(options.N, 'N', SCRYPT_DEFAULT_N, SCRYPT_MIN_N, 2 ** 22);

  // PHC records the exponent rather than the value, and OpenSSL requires a
  // power of two regardless, so a value that is not one cannot be hashed or
  // written down.
  if ((N & (N - 1)) !== 0) {
    throw new RangeError(`hashForStorage: N must be a power of two, received ${N}`);
  }

  const r = requireCount(options.r, 'r', SCRYPT_DEFAULT_R, SCRYPT_MIN_R, 64);
  const p = requireCount(options.p, 'p', SCRYPT_DEFAULT_P, 1, 16);
  const maxmem = 128 * N * r * p + 1_048_576;

  if (maxmem > SCRYPT_MAX_MEMORY_BYTES) {
    throw new RangeError(
      `hashForStorage: N=${N}, r=${r}, p=${p} needs about ${Math.round(maxmem / 1_048_576)} MiB ` +
        `per hash, above this package's ceiling of ${SCRYPT_MAX_MEMORY_BYTES / 1_048_576} MiB`
    );
  }

  return {
    algorithm: 'scrypt',
    N,
    r,
    p,
    keyLength: requireCount(
      options.keyLength,
      'keyLength',
      SCRYPT_DEFAULT_KEY_LENGTH,
      SCRYPT_MIN_KEY_LENGTH,
      1024
    ),
    maxmem,
  };
}

/**
 * Validate the options for one stored hash.
 *
 * @throws TypeError If `options` is not an object, names no algorithm, or a parameter has the wrong type.
 * @throws RangeError If a parameter is outside the documented bounds.
 */
export function planStorageHash(options: StorageHashOptions): StoragePlan {
  if (options === null || typeof options !== 'object') {
    throw new TypeError(
      `hashForStorage: options must be an object naming an algorithm, received ${describeType(options)}`
    );
  }

  switch (options.algorithm) {
    case 'argon2id':
    case 'argon2i':
    case 'argon2d':
      return planArgon2(options);
    case 'bcrypt':
      return planBcrypt(options);
    case 'scrypt':
      return planScrypt(options);
    default:
      throw new TypeError(
        `hashForStorage: unknown algorithm ${JSON.stringify(
          (options as { algorithm?: unknown }).algorithm
        )}; use one of ${ALGORITHMS.join(', ')}`
      );
  }
}
