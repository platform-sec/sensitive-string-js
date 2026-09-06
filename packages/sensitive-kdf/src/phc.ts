import { UnknownStoredHashError } from './errors.js';
import type { ScryptPlan } from './options.js';

/**
 * The PHC string format, for scrypt.
 *
 * Argon2 and bcrypt encode their own output; scrypt is computed here from
 * `node:crypto`, so its parameters and salt have to be written down somewhere
 * or the hash cannot be verified again. The PHC string format is where the
 * rest of the world writes them, which is what makes a hash produced here
 * readable by something that is not this package.
 *
 * The one thing to know when comparing this with a naive implementation: PHC
 * records `ln`, the base-two logarithm of the cost parameter, not `N` itself.
 * A string carrying `N=16384` is not a PHC string and is not accepted.
 */

/** Base64 without padding, which is what PHC calls B64. */
export function encodeB64(bytes: Buffer): string {
  return bytes.toString('base64').replace(/=+$/, '');
}

/**
 * Read a B64 segment back.
 *
 * Node accepts a good deal that is not base64 and silently drops it, so the
 * segment is checked against the alphabet first and the round trip is verified
 * afterwards. A stored hash is untrusted input: it may have come from a
 * database column somebody else can write.
 */
export function decodeB64(segment: string, what: string): Buffer {
  if (!/^[A-Za-z0-9+/]+$/.test(segment)) {
    throw new UnknownStoredHashError(`its ${what} is not base64`);
  }

  const bytes = Buffer.from(segment, 'base64');

  if (bytes.length === 0 || encodeB64(bytes) !== segment) {
    throw new UnknownStoredHashError(`its ${what} is not base64`);
  }

  return bytes;
}

/** Parameters read back out of a stored scrypt hash. */
export interface ScryptParameters {
  readonly N: number;
  readonly r: number;
  readonly p: number;
  readonly salt: Buffer;
  readonly hash: Buffer;
  readonly maxmem: number;
}

const SCRYPT_PHC =
  /^\$scrypt\$ln=(\d{1,2}),r=(\d{1,3}),p=(\d{1,3})\$([A-Za-z0-9+/]{1,128})\$([A-Za-z0-9+/]{1,512})$/;

/**
 * Bounds on what a stored string may ask this process to compute.
 *
 * Verification takes its parameters from the stored hash, so those parameters
 * are input. `ln=30, r=32` is a request for 4 TiB of memory, and honouring it
 * because it arrived in a database column would make one row a denial of
 * service. The upper bounds match what {@link ScryptPlan} allows on the way
 * in; the lower ones are what the format can express rather than what this
 * package would produce today, so a hash written under older, weaker
 * parameters can still be verified and then rehashed.
 */
const MIN_LN = 1;
const MAX_LN = 22;
const MAX_R = 64;
const MAX_P = 16;
const MAX_MEMORY_BYTES = 1_073_741_824;

/** Write the PHC string for a computed scrypt hash. */
export function encodeScryptPhc(plan: ScryptPlan, salt: Buffer, hash: Buffer): string {
  const ln = Math.log2(plan.N);

  return `$scrypt$ln=${ln},r=${plan.r},p=${plan.p}$${encodeB64(salt)}$${encodeB64(hash)}`;
}

/**
 * Read a stored scrypt hash.
 *
 * @throws UnknownStoredHashError If the string is not a scrypt PHC string, or
 *         its parameters are outside the bounds above.
 */
export function parseScryptPhc(stored: string): ScryptParameters {
  const match = SCRYPT_PHC.exec(stored);

  if (match === null) {
    throw new UnknownStoredHashError('it is not a scrypt PHC string');
  }

  // Every group is guaranteed by the pattern above, which is why each is read
  // through a fixed index rather than a check.
  const ln = Number(match[1]);
  const r = Number(match[2]);
  const p = Number(match[3]);
  const saltText = match[4] ?? '';
  const hashText = match[5] ?? '';

  if (
    !Number.isInteger(ln) ||
    !Number.isInteger(r) ||
    !Number.isInteger(p) ||
    ln < MIN_LN ||
    ln > MAX_LN ||
    r < 1 ||
    r > MAX_R ||
    p < 1 ||
    p > MAX_P
  ) {
    throw new UnknownStoredHashError('its parameters are outside the range this package computes');
  }

  const N = 2 ** ln;
  const maxmem = 128 * N * r * p + 1_048_576;

  if (maxmem > MAX_MEMORY_BYTES) {
    throw new UnknownStoredHashError(
      'its parameters ask for more memory than this package will allocate for one hash'
    );
  }

  return {
    N,
    r,
    p,
    salt: decodeB64(saltText, 'salt'),
    hash: decodeB64(hashText, 'digest'),
    maxmem,
  };
}
