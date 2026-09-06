import { MissingKdfModuleError, UnknownStoredHashError } from './errors.js';
import { loadKdfModule } from './module.js';
import { MAX_BCRYPT_PASSWORD_BYTES, type BcryptPlan } from './options.js';

/**
 * bcrypt, through the optional `bcrypt` package.
 *
 * Here because it is what is already in the database of most systems old
 * enough to need migrating, and it is still a sound choice. It is not the one
 * to pick for a new system: it is not memory-hard, and it hashes at most 72
 * bytes.
 */

interface BcryptModule {
  hash(value: string, rounds: number): Promise<string>;
  compare(value: string, stored: string): Promise<boolean>;
}

/**
 * What a bcrypt hash looks like: the variant tag, the two-digit cost, and 53
 * characters of bcrypt's own base64 alphabet holding the salt and the digest.
 *
 * Checked here rather than left to the module, which answers `false` for some
 * malformed strings and throws for others. A stored hash that cannot be read
 * is a fault to report, never a password that failed to match.
 */
const BCRYPT_HASH = /^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$/;

async function bcryptModule(): Promise<BcryptModule> {
  const loaded = await loadKdfModule('bcrypt', 'bcrypt');

  if (typeof loaded['hash'] !== 'function' || typeof loaded['compare'] !== 'function') {
    throw new MissingKdfModuleError('bcrypt', 'bcrypt');
  }

  return loaded as unknown as BcryptModule;
}

/**
 * Refuse a password bcrypt would silently truncate.
 *
 * bcrypt hashes the first 72 bytes and ignores the rest, so `passwordA` and
 * `passwordB` sharing a 72-byte prefix verify against each other's hash. The
 * `bcrypt` package does this without a word. Refusing is a deliberate
 * deviation: an error at registration is a bug report, and a silent truncation
 * is an authentication bypass nobody finds.
 *
 * Refused on the verifying side too, where the advice differs because the
 * algorithm is no longer the caller's to choose. Against a hash this package
 * produced, a password this long cannot be the right one, since hashing it
 * would have been refused; against a hash produced elsewhere, answering the
 * question at all means comparing a truncation, which is the bypass. Throwing
 * rather than answering `false` keeps that visible to the application, which
 * is the only place it can be resolved.
 *
 * The check counts bytes rather than characters, because that is what bcrypt
 * counts: 36 emoji are 144 bytes.
 */
export function assertBcryptLength(value: string, operation: 'hash' | 'verify'): void {
  const bytes = Buffer.byteLength(value, 'utf8');

  if (bytes <= MAX_BCRYPT_PASSWORD_BYTES) {
    return;
  }

  const advice =
    operation === 'hash'
      ? 'Use argon2id or scrypt, which have no such limit.'
      : 'No bcrypt hash from this package can correspond to a password this long, and matching ' +
        'one produced elsewhere would mean comparing only its first 72 bytes.';

  // The length is metadata about the password rather than the password, and it
  // is the one thing that tells the caller what happened.
  throw new RangeError(
    `bcrypt hashes at most ${MAX_BCRYPT_PASSWORD_BYTES} bytes and silently ignores the rest; ` +
      `this password is ${bytes} bytes. ${advice}`
  );
}

/** Hash a password. The result is bcrypt's own encoded form. */
export async function hashBcrypt(value: string, plan: BcryptPlan): Promise<string> {
  assertBcryptLength(value, 'hash');

  const module = await bcryptModule();

  return module.hash(value, plan.rounds);
}

/**
 * Verify a password against a stored bcrypt hash.
 *
 * @throws UnknownStoredHashError If `stored` is not a bcrypt hash.
 * @throws RangeError If the password is longer than bcrypt hashes.
 */
export async function verifyBcrypt(stored: string, value: string): Promise<boolean> {
  if (!BCRYPT_HASH.test(stored)) {
    throw new UnknownStoredHashError('it is not a bcrypt hash');
  }

  // Refused on the verifying side too. Accepting it here would authenticate a
  // password that differs from the registered one after byte 72, which is the
  // whole reason the hashing side refuses.
  assertBcryptLength(value, 'verify');

  const module = await bcryptModule();

  return module.compare(value, stored);
}
