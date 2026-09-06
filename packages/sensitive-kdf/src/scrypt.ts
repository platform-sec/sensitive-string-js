import { randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { encodeScryptPhc, parseScryptPhc } from './phc.js';
import type { ScryptPlan } from './options.js';

/**
 * scrypt, from `node:crypto`.
 *
 * The algorithm that needs no native module, which is what makes it this
 * package's fallback: an application that cannot compile one still has a real
 * password hash rather than a fast digest. It is memory-hard, though less
 * resistant to a tuned attacker than Argon2id.
 */

/** 16 bytes, which is what every current recommendation says a salt should be. */
const SALT_BYTES = 16;

function scryptAsync(
  value: string,
  salt: Buffer,
  keyLength: number,
  parameters: { N: number; r: number; p: number; maxmem: number }
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(value, salt, keyLength, parameters, (error, derived) => {
      if (error) {
        reject(error);
      } else {
        resolve(derived);
      }
    });
  });
}

/** Hash a password. The result is a PHC string carrying the parameters and salt. */
export async function hashScrypt(value: string, plan: ScryptPlan): Promise<string> {
  const salt = randomBytes(SALT_BYTES);
  const { N, r, p, maxmem } = plan;
  const derived = await scryptAsync(value, salt, plan.keyLength, { N, r, p, maxmem });

  return encodeScryptPhc(plan, salt, derived);
}

/**
 * Verify a password against a stored scrypt hash.
 *
 * The output length is taken from the stored digest rather than from any
 * configured default, which is both how a hash written under a different
 * `keyLength` still verifies and why the two buffers handed to
 * `timingSafeEqual`, which throws on a length mismatch, are the same length by
 * construction.
 */
export async function verifyScrypt(stored: string, value: string): Promise<boolean> {
  const { N, r, p, maxmem, salt, hash } = parseScryptPhc(stored);
  const derived = await scryptAsync(value, salt, hash.length, { N, r, p, maxmem });

  return timingSafeEqual(derived, hash);
}
