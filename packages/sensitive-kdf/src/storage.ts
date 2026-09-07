import { SensitiveString } from '@platform-sec/sensitive-string-core';
import type { RevealContext, SensitivityClass } from '@platform-sec/sensitive-string-core';

import { hashArgon2, verifyArgon2 } from './argon2.js';
import { hashBcrypt, verifyBcrypt } from './bcrypt.js';
import { hashScrypt, verifyScrypt } from './scrypt.js';
import { UnknownStoredHashError } from './errors.js';
import { planStorageHash, type StoragePlan } from './options.js';
import { readStoredParameters, type StoredParameters } from './parameters.js';
import type { StorageHashOptions } from './types.js';

/**
 * Password hashing, which `core`'s `hash()` deliberately is not.
 *
 * `hash('sha256')` is fast, and speed is the property a stored password must
 * not have: a wordlist runs through SHA-256 at billions of guesses a second on
 * hardware anybody can rent, and a salt does nothing about that for the
 * attacker holding the record the salt is stored in. The functions here are
 * slow and memory-hard on purpose, which is why they need Argon2 or bcrypt and
 * why rule R7 puts them in this package instead of in `core`.
 *
 * One asymmetry with `core` is worth stating plainly, because it is the
 * opposite of what every other derivation in this library does. A digest from
 * `hash()` carries the deadline, the reveal budget and the revocation of the
 * value it came from, since a fast digest of a guessable value is that value
 * behind a lookup table. A hash from here does not: it is a fresh
 * `credential`, and its whole purpose is to outlive the password and be
 * written to a row that is read back on every login. A salted, memory-hard
 * hash is not a reversible copy of the value, which is the entire difference
 * between the two functions. The one case where that reasoning is thin is a
 * password an attacker can enumerate outright, a four-digit PIN, and no
 * choice of KDF rescues that.
 */

function storedLabel(label: string | undefined): string {
  return label === undefined ? 'stored' : `${label}:stored`;
}

/**
 * Read a value that may or may not be protected.
 *
 * A protected one goes through the ordinary gate, so the class policy, the
 * audit hook, the deadline, the reveal budget and any revocation all apply,
 * and hashing a password appears in the audit log as the exposure it is.
 */
function readValue(
  value: SensitiveString<SensitivityClass> | string,
  what: string,
  ctx?: RevealContext
): string {
  if (value instanceof SensitiveString) {
    return value.reveal(ctx);
  }

  if (typeof value !== 'string') {
    throw new TypeError(
      `${what} must be a string or a SensitiveString, received ${
        value === null ? 'null' : typeof value
      }`
    );
  }

  return value;
}

/**
 * Hash a password for storage.
 *
 * The result is a `SensitiveString<'credential'>` holding the encoded hash,
 * with the parameters and the salt inside it, which is what `verifyHash` reads
 * them back from. It is classed `credential` because a stored hash is worth
 * attacking offline: wrapping it is what keeps it out of a log line on the way
 * to the database.
 *
 * @param value - The password. A `SensitiveString` is revealed through the ordinary gate.
 * @param options - The algorithm and its parameters. `{ algorithm: 'argon2id' }` is the answer for a new system.
 * @param ctx - Optional reveal context for authorization and auditing.
 * @throws MissingKdfModuleError If the algorithm needs a native module that is not installed.
 * @throws TypeError If the options name no known algorithm, or a parameter has the wrong type.
 * @throws RangeError If a parameter is outside the documented bounds, or the password is longer than bcrypt hashes.
 *
 * @example
 * ```ts
 * const password = new SensitiveString(body.password, 'credential', 'password');
 * const stored = await hashForStorage(password, { algorithm: 'argon2id' });
 * await db.users.update({ where: { id }, data: { password: stored.reveal() } });
 * ```
 */
export async function hashForStorage(
  value: SensitiveString<SensitivityClass> | string,
  options: StorageHashOptions,
  ctx?: RevealContext
): Promise<SensitiveString<'credential'>> {
  // Validated before the password is read, so a call rejected on its
  // parameters leaves no audit record for a hash that was never taken.
  const plan = planStorageHash(options);
  const label = value instanceof SensitiveString ? storedLabel(value.label) : 'stored';
  const raw = readValue(value, 'hashForStorage: value', ctx);

  const hashed =
    plan.algorithm === 'bcrypt'
      ? await hashBcrypt(raw, plan)
      : plan.algorithm === 'scrypt'
        ? await hashScrypt(raw, plan)
        : await hashArgon2(raw, plan);

  return new SensitiveString(hashed, 'credential', label);
}

/**
 * Verify a password against a stored hash.
 *
 * The algorithm and its parameters are read from the stored hash rather than
 * from anything configured here, so a store written under older parameters
 * keeps verifying while new passwords are hashed under stronger ones.
 *
 * A password that does not match answers `false`. A stored hash that cannot be
 * read throws: it is a fault in the data, and reporting it as a failed login
 * would turn a corrupted column into an account nobody can sign in to and
 * nobody can explain.
 *
 * @param stored - The hash, as produced by {@link hashForStorage}.
 * @param input - The password to check.
 * @param ctx - Optional reveal context for authorization and auditing.
 * @throws UnknownStoredHashError If `stored` is not a hash this package can read.
 * @throws MissingKdfModuleError If reading it needs a native module that is not installed.
 * @throws RangeError If `stored` is a bcrypt hash and the input is longer than bcrypt hashes.
 *
 * @example
 * ```ts
 * const stored = new SensitiveString(row.password, 'credential', 'password:stored');
 * if (!(await verifyHash(stored, body.password))) {
 *   throw new UnauthorizedError();
 * }
 * ```
 */
export async function verifyHash(
  stored: SensitiveString<SensitivityClass> | string,
  input: SensitiveString<SensitivityClass> | string,
  ctx?: RevealContext
): Promise<boolean> {
  const encoded = readValue(stored, 'verifyHash: stored', ctx);

  // The family is settled before the password is read, so an unreadable stored
  // hash costs the password nothing.
  const verify = verifierFor(encoded);
  const raw = readValue(input, 'verifyHash: input', ctx);

  return verify(encoded, raw);
}

/**
 * Whether a stored hash is weaker than what these options would produce.
 *
 * The counterpart to a store that has outlived its parameters. `verifyHash`
 * reads the algorithm and cost out of the stored string, so a password hashed
 * years ago keeps working forever; this is how an application notices that it
 * should not, and rehashes on the next successful login while it briefly holds
 * the plaintext.
 *
 * ```ts
 * if (await verifyHash(stored, body.password)) {
 *   if (needsRehash(stored, PASSWORD_HASHING)) {
 *     await db.users.update({
 *       where: { id },
 *       data: { password: (await hashForStorage(body.password, PASSWORD_HASHING)).reveal() },
 *     });
 *   }
 * }
 * ```
 *
 * Weaker, not different. A parameter above what the options ask for does not
 * report: rolling a configuration back, or reading a store some other service
 * hashed more expensively, must not rehash a fleet of passwords down to the
 * lower setting. A different algorithm family always reports, because moving
 * from bcrypt to Argon2id is the migration this exists for.
 *
 * It hashes nothing and loads no native module. Every format writes its cost
 * parameters into the string ahead of the digest, so this reads them, which is
 * also what lets it answer for an algorithm this process could not compute.
 *
 * Reading a protected hash is an exposure of that hash, audited like any
 * other. It is not an exposure of the password, which this never sees.
 *
 * @param stored - The hash, as produced by {@link hashForStorage}.
 * @param options - The parameters this application would hash with today.
 * @param ctx - Optional reveal context for authorization and auditing.
 * @throws UnknownStoredHashError If `stored` is not a hash this package can read.
 * @throws TypeError If the options name no known algorithm, or a parameter has the wrong type.
 * @throws RangeError If a parameter is outside the documented bounds.
 */
export function needsRehash(
  stored: SensitiveString<SensitivityClass> | string,
  options: StorageHashOptions,
  ctx?: RevealContext
): boolean {
  const plan = planStorageHash(options);
  const parameters = readStoredParameters(readValue(stored, 'needsRehash: stored', ctx));

  if (parameters.algorithm !== plan.algorithm) {
    return true;
  }

  return isWeaker(parameters, plan);
}

/**
 * Whether a stored hash's own family parameters fall short of the plan's.
 *
 * Reached only once the two agree on the algorithm, so each branch compares
 * like with like. Argon2's `parallelism` is deliberately absent: lanes divide
 * the same memory rather than adding work, so a hash with fewer of them is not
 * a weaker hash, and reporting on it would rehash a store for nothing.
 */
function isWeaker(parameters: StoredParameters, plan: StoragePlan): boolean {
  if (plan.algorithm === 'bcrypt') {
    return (parameters.rounds ?? 0) < plan.rounds;
  }

  if (plan.algorithm === 'scrypt') {
    return (
      (parameters.N ?? 0) < plan.N ||
      (parameters.r ?? 0) < plan.r ||
      (parameters.p ?? 0) < plan.p ||
      parameters.hashLength < plan.keyLength
    );
  }

  return (
    (parameters.memoryCost ?? 0) < plan.memoryCost ||
    (parameters.timeCost ?? 0) < plan.timeCost ||
    parameters.hashLength < plan.hashLength
  );
}

/**
 * Which verifier reads this hash.
 *
 * Every format this package writes begins with its own tag, and the tags are
 * disjoint, so the choice is a prefix rather than a guess. A string matching
 * none of them is a fault rather than a password mismatch.
 */
function verifierFor(stored: string): (stored: string, value: string) => Promise<boolean> {
  if (stored.startsWith('$argon2')) {
    return verifyArgon2;
  }

  if (stored.startsWith('$2')) {
    return verifyBcrypt;
  }

  if (stored.startsWith('$scrypt$')) {
    return verifyScrypt;
  }

  throw new UnknownStoredHashError();
}
