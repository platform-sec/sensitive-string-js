import { UnknownStoredHashError } from './errors.js';
import { decodeB64 } from './phc.js';

/**
 * Reading the parameters back out of a stored hash, without hashing anything.
 *
 * Verification needs a KDF and, for two of the three families, a native
 * module. Asking whether a stored hash is weaker than what this application
 * would produce today needs neither: every format writes its cost parameters
 * into the string, in the clear, ahead of the digest. So this module is
 * regular expressions and nothing else, which is what lets `needsRehash` run
 * on a row that arrived from a store hashed with an algorithm this process
 * cannot even compute.
 *
 * Everything here treats the string as untrusted. It comes from a database
 * column, and the answer to a malformed one is a refusal rather than a guess.
 */

/** Which family produced a stored hash, and what it cost. */
export interface StoredParameters {
  readonly algorithm: 'argon2id' | 'argon2i' | 'argon2d' | 'bcrypt' | 'scrypt';
  /**
   * The work each family measures, in its own units, with the fields absent
   * that the family does not have. Comparing across families is meaningless
   * and {@link needsRehash} does not try: a different family is already an
   * answer.
   */
  readonly memoryCost?: number;
  readonly timeCost?: number;
  readonly parallelism?: number;
  readonly rounds?: number;
  readonly N?: number;
  readonly r?: number;
  readonly p?: number;
  /** Bytes of digest, which is a parameter a caller can raise. */
  readonly hashLength: number;
}

/**
 * Argon2's encoding.
 *
 * `$argon2id$v=19$m=19456,p=1,t=2$<salt>$<hash>`, with the version optional
 * because Argon2 0x10 predates it, and with the parameters left as one segment
 * rather than pinned in order. PHC lists them as `m,t,p` and the `argon2`
 * package writes `m,p,t`, which is the kind of difference a rule written from
 * the specification gets wrong against every hash in production. The segment
 * is read by {@link readParameterList} instead, which also skips the `keyid`
 * and `data` parameters the format allows.
 */
const ARGON2 =
  /^\$argon2(id|i|d)\$(?:v=\d{1,3}\$)?([A-Za-z0-9+/=,]{1,256})\$([A-Za-z0-9+/]{1,128})\$([A-Za-z0-9+/]{1,512})$/;

/** Digits allowed in one parameter, so a pathological string is refused rather than parsed. */
const MAX_PARAMETER_DIGITS = 10;

/**
 * A PHC parameter segment, as a lookup.
 *
 * Anything that is not `name=<digits>` is dropped rather than refused: `keyid`
 * and `data` are base64 and are none of this module's business, and a
 * parameter this package does not read must not make a valid hash unreadable.
 * A numeric parameter longer than {@link MAX_PARAMETER_DIGITS} is a different
 * matter and refuses the whole string, since silently ignoring it would report
 * a cost the hash does not have.
 */
function readParameterList(segment: string): ReadonlyMap<string, number> {
  const parameters = new Map<string, number>();

  for (const entry of segment.split(',')) {
    const [name, value] = entry.split('=');

    if (name === undefined || value === undefined || !/^\d+$/.test(value)) {
      continue;
    }

    if (value.length > MAX_PARAMETER_DIGITS) {
      throw new UnknownStoredHashError(`its ${name} parameter is out of range`);
    }

    parameters.set(name, Number(value));
  }

  return parameters;
}

/** bcrypt's, where the two-digit cost is the whole of what is configurable. */
const BCRYPT = /^\$2[abxy]\$(\d{2})\$([./A-Za-z0-9]{53})$/;

/** This package's scrypt encoding. See `phc.ts` for why it records `ln`. */
const SCRYPT =
  /^\$scrypt\$ln=(\d{1,2}),r=(\d{1,3}),p=(\d{1,3})\$([A-Za-z0-9+/]{1,128})\$([A-Za-z0-9+/]{1,512})$/;

/** The digest bcrypt encodes: 23 bytes, in its own alphabet, after the salt. */
const BCRYPT_HASH_BYTES = 23;

function readArgon2(match: RegExpExecArray): StoredParameters {
  const variant = match[1] as 'id' | 'i' | 'd';
  const parameters = readParameterList(match[2] ?? '');
  const memoryCost = parameters.get('m');
  const timeCost = parameters.get('t');
  const parallelism = parameters.get('p');

  // All three are required by the format. A hash missing one is not one this
  // package can compare against anything.
  if (memoryCost === undefined || timeCost === undefined || parallelism === undefined) {
    throw new UnknownStoredHashError('its argon2 parameters are incomplete');
  }

  return {
    algorithm: `argon2${variant}`,
    memoryCost,
    timeCost,
    parallelism,
    hashLength: decodeB64(match[4] ?? '', 'digest').length,
  };
}

function readScrypt(match: RegExpExecArray): StoredParameters {
  return {
    algorithm: 'scrypt',
    N: 2 ** Number(match[1]),
    r: Number(match[2]),
    p: Number(match[3]),
    hashLength: decodeB64(match[5] ?? '', 'digest').length,
  };
}

/**
 * The parameters a stored hash was produced with.
 *
 * @throws UnknownStoredHashError If the string is not a hash this package can read.
 */
export function readStoredParameters(stored: string): StoredParameters {
  const argon2 = ARGON2.exec(stored);
  if (argon2 !== null) {
    return readArgon2(argon2);
  }

  const bcrypt = BCRYPT.exec(stored);
  if (bcrypt !== null) {
    return {
      algorithm: 'bcrypt',
      rounds: Number(bcrypt[1]),
      // Fixed by the format rather than read from it: bcrypt's own base64 is
      // not the alphabet `decodeB64` accepts, and the length is not a
      // parameter anyone can choose.
      hashLength: BCRYPT_HASH_BYTES,
    };
  }

  const scrypt = SCRYPT.exec(stored);
  if (scrypt !== null) {
    return readScrypt(scrypt);
  }

  throw new UnknownStoredHashError();
}
