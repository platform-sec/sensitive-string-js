import { createHash, createHmac, getHashes } from 'node:crypto';
import type {
  HashAlgorithm,
  HashAuditDetails,
  HashEncoding,
  HashOptions,
  HmacAuditDetails,
  HmacOptions,
} from './types.js';
import { MIN_DERIVATION_KEY_BYTES } from './derive.js';

/**
 * One-way transformations of a protected value, on `node:crypto` alone.
 *
 * This module holds the algorithm allowlist, the option validation and the
 * digest itself. It does not read a `SensitiveString`, does not authorize and
 * does not audit: the class reads the value through the ordinary gate and
 * hands it here, so a digest costs exactly one audited exposure and appears in
 * the log as one.
 *
 * What is deliberately absent is password storage. A digest from here is fast
 * by construction, which is the property a password hash must not have, and
 * the memory-hard functions that do have it need a native module that rule R7
 * keeps out of `core`. That lives in `@platform-sec/sensitive-string-kdf`.
 */

/** Digest algorithms this library will compute. */
const ALLOWED_ALGORITHMS: readonly HashAlgorithm[] = [
  'sha256',
  'sha384',
  'sha512',
  'sha3-256',
  'sha3-512',
];

const ALLOWED_ALGORITHM_SET: ReadonlySet<string> = new Set(ALLOWED_ALGORITHMS);

/**
 * Names worth refusing with a reason rather than with a list.
 *
 * Every one of them is reachable from `node:crypto`, so a caller who asks for
 * one has usually copied it from code that predates the break. The message
 * says what is wrong with it instead of leaving the caller to guess which of
 * the allowed names is the near equivalent.
 */
const BROKEN_ALGORITHMS: ReadonlyMap<string, string> = new Map([
  ['md5', 'MD5 collides in milliseconds'],
  ['md5-sha1', 'MD5 collides in milliseconds'],
  ['md4', 'MD4 is broken beyond collisions'],
  ['sha1', 'SHA-1 collisions have been demonstrated'],
  ['sha-1', 'SHA-1 collisions have been demonstrated'],
  ['ripemd160', 'RIPEMD-160 has a 160-bit output and no modern review'],
  ['rmd160', 'RIPEMD-160 has a 160-bit output and no modern review'],
]);

const ALLOWED_ENCODINGS: readonly HashEncoding[] = ['hex', 'base64', 'base64url'];

const ALLOWED_ENCODING_SET: ReadonlySet<string> = new Set(ALLOWED_ENCODINGS);

/**
 * What this Node build can actually compute.
 *
 * The allowlist says what the library is willing to use; this says what OpenSSL
 * underneath it offers, which is not the same thing on a FIPS build, where
 * SHA-3 can be missing. Read once, on first use rather than at import, and
 * cached: `getHashes()` allocates an array of every digest name the build
 * knows.
 */
let availableAlgorithms: ReadonlySet<string> | undefined;

function isAvailable(algorithm: HashAlgorithm): boolean {
  availableAlgorithms ??= new Set(getHashes());
  return availableAlgorithms.has(algorithm);
}

/**
 * A validated set of options for one digest.
 *
 * Producing one requires no access to the raw value, so a rejected call is
 * refused before anything is read, charged or audited.
 */
export interface HashPlan {
  readonly operation: 'hash' | 'hmac';
  readonly algorithm: HashAlgorithm;
  readonly encoding: HashEncoding;
  /** The salt, as bytes. Always `undefined` for an HMAC, which has a key instead. */
  readonly salt: Uint8Array | undefined;
}

/**
 * Describe a rejected option without disclosing it.
 */
function describeType(value: unknown): string {
  return value === null ? 'null' : typeof value;
}

function requireAlgorithm(algorithm: unknown, operation: 'hash' | 'hmac'): HashAlgorithm {
  if (typeof algorithm !== 'string') {
    throw new TypeError(
      `SensitiveString.${operation}: algorithm must be a string, received ${describeType(algorithm)}`
    );
  }

  const normalized = algorithm.toLowerCase();
  const broken = BROKEN_ALGORITHMS.get(normalized);

  if (broken !== undefined) {
    throw new Error(
      `SensitiveString.${operation}: '${algorithm}' is not available because ${broken}; ` +
        `use one of ${ALLOWED_ALGORITHMS.join(', ')}`
    );
  }

  if (!ALLOWED_ALGORITHM_SET.has(normalized)) {
    throw new TypeError(
      `SensitiveString.${operation}: unknown algorithm '${algorithm}'; ` +
        `use one of ${ALLOWED_ALGORITHMS.join(', ')}`
    );
  }

  const known = normalized as HashAlgorithm;

  if (!isAvailable(known)) {
    throw new Error(
      `SensitiveString.${operation}: '${known}' is not available in this Node build's crypto ` +
        'provider, which a FIPS build is the usual reason for'
    );
  }

  return known;
}

function requireEncoding(encoding: unknown, operation: 'hash' | 'hmac'): HashEncoding {
  if (encoding === undefined) {
    return 'hex';
  }

  if (typeof encoding !== 'string' || !ALLOWED_ENCODING_SET.has(encoding)) {
    throw new TypeError(
      `SensitiveString.${operation}: encoding must be one of ${ALLOWED_ENCODINGS.join(', ')}, ` +
        `received ${typeof encoding === 'string' ? `'${encoding}'` : describeType(encoding)}`
    );
  }

  return encoding as HashEncoding;
}

/**
 * The salt as bytes.
 *
 * An empty salt is refused rather than ignored. It produces exactly the digest
 * of the unsalted value, so accepting it would let `salt: ''` read as salted
 * everywhere it appears, including in the audit record.
 */
function requireSalt(salt: unknown): Uint8Array | undefined {
  if (salt === undefined) {
    return undefined;
  }

  const bytes =
    typeof salt === 'string'
      ? new TextEncoder().encode(salt)
      : salt instanceof Uint8Array
        ? salt
        : undefined;

  if (bytes === undefined) {
    throw new TypeError(
      `SensitiveString.hash: salt must be a string or a Uint8Array, received ${describeType(salt)}`
    );
  }

  if (bytes.length === 0) {
    throw new RangeError(
      'SensitiveString.hash: salt must not be empty; a zero-length salt is the unsalted digest ' +
        'under another name'
    );
  }

  return bytes;
}

/**
 * Validate the options for a digest.
 *
 * @param operation - Which method is asking, for the error messages.
 * @param algorithm - The requested algorithm, unvalidated.
 * @param options - The caller's options, unvalidated.
 */
export function planHash(
  operation: 'hash' | 'hmac',
  algorithm: HashAlgorithm,
  options: HashOptions | HmacOptions
): HashPlan {
  if (options === null || typeof options !== 'object') {
    throw new TypeError(
      `SensitiveString.${operation}: options must be an object, received ${describeType(options)}`
    );
  }

  // In argument order, so a call that gets both the algorithm and an option
  // wrong reports the algorithm: it is the decision that matters, and the one
  // the caller is likelier to have copied from somewhere older.
  const checked = requireAlgorithm(algorithm, operation);
  const encoding = requireEncoding(options.encoding, operation);

  // An HMAC takes a key, not a salt. Silently ignoring one would leave a caller
  // believing a keyed digest was also salted.
  if (operation === 'hmac' && (options as HashOptions).salt !== undefined) {
    throw new Error(
      'SensitiveString.hmac: salt does not apply to a keyed digest; the key is what separates it'
    );
  }

  return {
    operation,
    algorithm: checked,
    encoding,
    salt: operation === 'hash' ? requireSalt((options as HashOptions).salt) : undefined,
  };
}

/**
 * An HMAC key as bytes.
 *
 * The floor is {@link MIN_DERIVATION_KEY_BYTES}, the same one `deriveKeyedToken`
 * applies and for the same reason: below it the key is enumerable alongside the
 * value, and a keyed digest that an attacker can recompute is an unkeyed one
 * that looks stronger in review.
 *
 * @param key - The caller's key, unvalidated. A protected key has already been
 *              read through the gate by the time it arrives here.
 */
export function requireHmacKey(key: unknown): Uint8Array {
  const bytes =
    typeof key === 'string'
      ? new TextEncoder().encode(key)
      : key instanceof Uint8Array
        ? key
        : undefined;

  if (bytes === undefined) {
    throw new TypeError(
      'SensitiveString.hmac: key must be a string, a Uint8Array, or a SensitiveString, ' +
        `received ${describeType(key)}`
    );
  }

  if (bytes.length < MIN_DERIVATION_KEY_BYTES) {
    // The length is metadata about the key rather than the key, so naming it is
    // safe and it is the one thing that tells the caller what to fix.
    throw new RangeError(
      `SensitiveString.hmac: key must be at least ${MIN_DERIVATION_KEY_BYTES} bytes, received ` +
        `${bytes.length}; 32 bytes from randomBytes or a secrets manager is the recommendation`
    );
  }

  return bytes;
}

/**
 * The audit record for a plan.
 *
 * Derived from the options alone, so the hook runs at the same point in
 * `hash()` as it does in `reveal()`: before the digest exists, and early enough
 * that a sink which throws stops the operation.
 */
export function hashAuditDetails(plan: HashPlan): HashAuditDetails {
  return Object.freeze({
    operation: 'hash' as const,
    algorithm: plan.algorithm,
    encoding: plan.encoding,
    salted: plan.salt !== undefined,
  });
}

/** The same, for `hmac()`. */
export function hmacAuditDetails(plan: HashPlan, protectedKey: boolean): HmacAuditDetails {
  return Object.freeze({
    operation: 'hmac' as const,
    algorithm: plan.algorithm,
    encoding: plan.encoding,
    protectedKey,
  });
}

/**
 * Compute the digest.
 *
 * The salt is prepended rather than appended: appending it leaves the digest
 * open to a length extension, and prepending is also what every other
 * implementation of `hash(salt, value)` does, which is what makes the result
 * reproducible outside this library.
 *
 * @param value - The raw value, already authorized and audited by the caller.
 * @param plan - Validated options from {@link planHash}.
 */
export function applyHash(value: string, plan: HashPlan): string {
  const hash = createHash(plan.algorithm);

  if (plan.salt !== undefined) {
    hash.update(plan.salt);
  }

  hash.update(value, 'utf8');

  return hash.digest(plan.encoding);
}

/**
 * Compute the keyed digest.
 *
 * @param value - The raw value, already authorized and audited by the caller.
 * @param key - The key bytes from {@link requireHmacKey}.
 * @param plan - Validated options from {@link planHash}.
 */
export function applyHmac(value: string, key: Uint8Array, plan: HashPlan): string {
  const hmac = createHmac(plan.algorithm, key);
  hmac.update(value, 'utf8');

  return hmac.digest(plan.encoding);
}

/**
 * The label a digest carries.
 *
 * `${label}:hash` when the value has one, and the bare operation when it does
 * not. Never `undefined:hash`: a label appears in audit records and in
 * `inspect()` output, and a rendered `undefined` there reads as a bug in the
 * library rather than as a value nobody labelled.
 */
export function hashLabel(label: string | undefined, operation: 'hash' | 'hmac'): string {
  return label === undefined ? operation : `${label}:${operation}`;
}
