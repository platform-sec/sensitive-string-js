import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * Constant-time equality of two raw values, including their lengths.
 *
 * This module holds the comparison and nothing else. It does not read a
 * `SensitiveString`, does not authorize and does not audit: the class reads
 * both operands through the ordinary gate and hands the raw strings here, so a
 * comparison costs exactly the exposures the gate recorded.
 *
 * The obvious implementation hands both values to `timingSafeEqual`, which
 * requires equal lengths and therefore needs a length check in front of it.
 * That check is a branch on the stored value's length, and it is observable:
 * a comparand of the wrong length answers before any byte is examined, so an
 * attacker who can time the call learns the length of the secret by finding
 * the length that costs more. A length is not the secret, but it bounds the
 * search for one.
 *
 * Comparing a wrong-length comparand against a zero-filled buffer of its own
 * length is the usual repair and is not the one used here. It moves the branch
 * rather than removing it: only the mismatch path allocates and fills that
 * buffer, so that path becomes the slower one and the signal survives with its
 * sign flipped.
 *
 * Hashing both sides first removes the branch instead of balancing it.
 * `timingSafeEqual` then always receives two 32-byte digests, so there is no
 * length to check and no path to choose between. What remains is the HMAC
 * itself, whose cost grows with its input one 64-byte block at a time, over
 * the stored value as well as over the comparand. That is not a branch and it
 * is not nothing: measured independently, stored values of 8 to 256 bytes were
 * indistinguishable within the timing analysis's noise floor, while 1024 bytes
 * cost about 460ns more than 8 and 4096 about 2.5us more. For a credential-sized
 * value the length is hidden to the resolution anyone has measured; for a value
 * hundreds of bytes long it is hidden at 64-byte granularity, which is a
 * weaker promise and is stated here rather than implied away.
 *
 * It is bought rather than free. Measured on Node 22.15 against 32-character
 * operands, a comparison went from about 130ns to about 5us, because two
 * `createHmac` calls dominate everything else in the function. Padding the
 * stored value into a buffer sized by the comparand and folding in a
 * branchless length check measures about 240ns and was not chosen: the copy
 * runs for `min(stored, comparand)` bytes, so the stored length still shows
 * through at memcpy granularity, and the argument that it does not matter is
 * exactly the kind of argument this function exists so that nobody has to
 * make. `equals()` is called once per authentication event, not per byte, and
 * a caller who needs to find a credential among many wants `hash()` and an
 * index rather than a linear scan of comparisons.
 */

/**
 * Ephemeral per-process key, never persisted, never exported and never
 * reachable from a public API.
 *
 * The digests it produces exist for the length of one comparison, so it needs
 * no agreement with any other process and must not have any: a key that
 * survives a restart or is shared between them would make these digests
 * durable identifiers of the values compared under it, which is the thing
 * `derive.ts` exists to do deliberately and this module has no business doing
 * as a side effect.
 *
 * It is keyed rather than a plain digest for the case where the operands are
 * guessable. An unkeyed SHA-256 of a four-digit PIN is the PIN, so a digest
 * that reached a heap dump or a core file would be worth attacking; with a key
 * the attacker does not hold, it is worth nothing.
 */
const COMPARISON_KEY = randomBytes(32);

/** A fixed-width stand-in for a value, equal exactly when the values are. */
function probe(value: string): Buffer {
  return createHmac('sha256', COMPARISON_KEY).update(value, 'utf8').digest();
}

/**
 * Whether two raw values are equal, in time that does not depend on either
 * value's contents, and that depends on the stored value's length only through
 * the HMAC's block count, as described above.
 *
 * Two distinct values collide only on an HMAC-SHA256 collision, which is not a
 * failure mode anyone has to plan around.
 *
 * @param a - One raw value.
 * @param b - The other raw value.
 * @returns true when the values are byte-for-byte equal.
 */
export function constantTimeEquals(a: string, b: string): boolean {
  return timingSafeEqual(probe(a), probe(b));
}

/**
 * The same stand-in, for a value already held as bytes.
 *
 * Identical to `probe` for the same value, because `update(text, 'utf8')` and
 * `update(Buffer.from(text, 'utf8'))` feed the HMAC the same octets. That is
 * what lets a sealed value be compared against an unsealed one without either
 * side converting to the other's representation.
 */
function probeBytes(value: Buffer): Buffer {
  return createHmac('sha256', COMPARISON_KEY).update(value).digest();
}

/**
 * Whether two raw values held as UTF-8 bytes are equal, under the same
 * guarantees `constantTimeEquals` gives and for the same reasons.
 *
 * It exists so a sealed value never has to become a string to be compared.
 * Decrypting into a `Buffer`, comparing here, and zeroing both operands leaves
 * nothing recoverable in process memory; the string path leaves one copy per
 * comparison that garbage collection does not remove.
 *
 * The obvious byte comparison, `a.equals(b)`, is not used and is not an
 * option: it is a length check followed by a `memcmp`, which is the exact
 * variable-time shape `compare.ts` exists to avoid. Hashing first costs about
 * 5us and removes both the length branch and the byte-position one.
 *
 * Neither operand is zeroed here. The caller owns both and knows which of them
 * it may write to.
 *
 * @param a - One raw value, as UTF-8 bytes.
 * @param b - The other raw value, as UTF-8 bytes.
 * @returns true when the values are byte-for-byte equal.
 */
export function constantTimeEqualsBytes(a: Buffer, b: Buffer): boolean {
  return timingSafeEqual(probeBytes(a), probeBytes(b));
}
