import { createHmac } from 'node:crypto';

/**
 * Keyed derivation of a stable token from a raw value.
 *
 * One implementation, in `core`, because two callers want the same primitive
 * and a truncated keyed HMAC over a low-entropy value has exactly one correct
 * shape. Deterministic redaction (ROADMAP 6.1) correlates a value across log
 * lines; an LLM entity handle stands in for a value inside a prompt. Both
 * derive a short stable token from something an attacker can guess, and both
 * publish the result somewhere the attacker can see it.
 *
 * That is why there is no unkeyed mode. An email address under a plain
 * SHA-256 is recoverable from a wordlist in seconds, and the entire premise of
 * a derived token is that it appears where an offline attack can reach it.
 *
 * This module holds the derivation and nothing else. It does not read a
 * `SensitiveString`, does not authorize, and does not audit: a caller reveals
 * through the ordinary gate and hands the result here, so the audit record is
 * produced by the reveal rather than by a second, quieter path to the same
 * value.
 */

/**
 * Shortest token this function will produce, in hex characters.
 *
 * 12 hex characters is 48 bits. Under the birthday bound two distinct values
 * collide with probability around one in a million at roughly 24,000 distinct
 * values under one key and domain. 8 characters is 32 bits, where the same
 * bound falls at about 90 values and a one-in-a-thousand collision arrives at
 * about 3,000, which a support-ticket workload reaches in a week. A collision
 * merges two subjects into one, so the floor is a correctness guard as much as
 * a security one.
 */
export const MIN_DERIVED_TOKEN_LENGTH = 12;

/** The full SHA-256 digest in hex. Longer would be truncation of nothing. */
export const MAX_DERIVED_TOKEN_LENGTH = 64;

/** The default, which is the floor. Raise it before a workload grows past the bound above. */
export const DEFAULT_DERIVED_TOKEN_LENGTH = 12;

/**
 * Shortest accepted key, in bytes.
 *
 * A key of a few bytes is an unkeyed hash with extra steps: the search space
 * is small enough to enumerate alongside the wordlist the value came from. 16
 * bytes is the floor rather than a recommendation; 32 bytes of `randomBytes`
 * is the recommendation.
 */
export const MIN_DERIVATION_KEY_BYTES = 16;

/** How to derive a token. */
export interface KeyedDerivationOptions {
  /**
   * HMAC key. Required, and there is no way to configure the function without
   * one.
   *
   * A string is read as UTF-8. Prefer a `Uint8Array` from a secrets manager or
   * `randomBytes`, since a string key sits in the heap as an ordinary string.
   */
  readonly key: Uint8Array | string;
  /**
   * Domain components mixed in ahead of the value, so the same value in two
   * contexts derives two different tokens.
   *
   * Joined with a NUL byte, which is why a component may not contain one: with
   * an ordinary separator, `['a', 'b.c']` and `['a.b', 'c']` would hash
   * identically and two domains would silently share a token space.
   */
  readonly domain?: readonly string[];
  /** Hex characters retained. Default {@link DEFAULT_DERIVED_TOKEN_LENGTH}. */
  readonly length?: number;
}

/**
 * Derive a stable token from a raw value.
 *
 * `HMAC-SHA256(key, domain[0] || 0x00 || ... || domain[n] || 0x00 || value)`,
 * hex, truncated to `length`. Deterministic across processes for the same key,
 * domain and value, which is the property that makes a token usable as a
 * correlation key or a pseudonym.
 *
 * @param value - The raw value. The caller is responsible for having been
 *                authorized to hold it; this function performs no check.
 * @param options - The key, the domain separation, and the token length
 * @returns The truncated hex digest, with no prefix or delimiters
 *
 * @throws TypeError If the key is not bytes or a string, or a domain component
 *         is not a string or contains a NUL byte.
 * @throws RangeError If the key is shorter than {@link MIN_DERIVATION_KEY_BYTES},
 *         or `length` is not a whole number within the documented bounds.
 */
export function deriveKeyedToken(value: string, options: KeyedDerivationOptions): string {
  if (typeof value !== 'string') {
    throw new TypeError('deriveKeyedToken: value must be a string');
  }

  const key = normalizeKey(options.key);
  const length = normalizeLength(options.length);

  const hmac = createHmac('sha256', key);

  for (const component of options.domain ?? []) {
    assertDomainComponent(component);

    hmac.update(component, 'utf8');
    hmac.update(SEPARATOR);
  }

  hmac.update(value, 'utf8');

  return hmac.digest('hex').slice(0, length);
}

/**
 * Check the derivation options without deriving anything.
 *
 * For a caller who has to read a protected value to derive from it. Every
 * refusal `deriveKeyedToken` can raise for a malformed key, length or domain
 * is raised here instead, so the caller can settle them before the read rather
 * than after it.
 *
 * The read is the reason this exists. Core's rule in the raw-value gate is that
 * a denied read is not a reveal and must not be logged as one; a read whose
 * result is about to be thrown away for a caller's typo is the same thing one
 * step later. Without this, an audit sink records a reveal that produced
 * nothing, and an auditor reconciling reveals against derived tokens finds one
 * that does not balance.
 *
 * @param options - The same options {@link deriveKeyedToken} takes
 *
 * @throws TypeError For a key or domain component of the wrong type, or a
 *         domain component containing a NUL byte.
 * @throws RangeError For a key below the entropy floor or a length outside the
 *         documented bounds.
 */
export function assertKeyedDerivationOptions(options: KeyedDerivationOptions): void {
  normalizeKey(options.key);
  normalizeLength(options.length);

  for (const component of options.domain ?? []) {
    assertDomainComponent(component);
  }
}

function assertDomainComponent(component: string): void {
  if (typeof component !== 'string') {
    throw new TypeError('deriveKeyedToken: every domain component must be a string');
  }

  if (component.includes(NUL)) {
    throw new TypeError(
      'deriveKeyedToken: a domain component may not contain a NUL byte, which is the separator'
    );
  }
}

const NUL = String.fromCharCode(0);
const SEPARATOR = new Uint8Array([0]);

function normalizeKey(key: KeyedDerivationOptions['key']): Uint8Array {
  const bytes =
    typeof key === 'string'
      ? new TextEncoder().encode(key)
      : key instanceof Uint8Array
        ? key
        : undefined;

  if (bytes === undefined) {
    throw new TypeError('deriveKeyedToken: key must be a Uint8Array or a string');
  }

  if (bytes.length < MIN_DERIVATION_KEY_BYTES) {
    // The length is metadata about the key, not the key, so naming it is safe
    // and it is the one thing that tells the caller what to fix.
    throw new RangeError(
      `deriveKeyedToken: key must be at least ${MIN_DERIVATION_KEY_BYTES} bytes, received ${bytes.length}`
    );
  }

  return bytes;
}

function normalizeLength(length: number | undefined): number {
  if (length === undefined) {
    return DEFAULT_DERIVED_TOKEN_LENGTH;
  }

  if (!Number.isInteger(length)) {
    throw new RangeError('deriveKeyedToken: length must be a whole number of hex characters');
  }

  if (length < MIN_DERIVED_TOKEN_LENGTH || length > MAX_DERIVED_TOKEN_LENGTH) {
    throw new RangeError(
      `deriveKeyedToken: length must be between ${MIN_DERIVED_TOKEN_LENGTH} and ` +
        `${MAX_DERIVED_TOKEN_LENGTH} hex characters, received ${length}`
    );
  }

  return length;
}
