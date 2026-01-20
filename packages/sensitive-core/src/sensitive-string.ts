import { timingSafeEqual } from 'node:crypto';
import type {
  SensitivityClass,
  SensitivityPolicy,
  SensitiveEnvelope,
  RevealContext,
} from './types.js';
import { getPolicy, defaultCombineClasses } from './policy.js';
import { getCurrentRevealContext } from './context.js';

/**
 * Node.js custom inspect symbol for util.inspect() and console.log().
 */
const NODE_INSPECT_SYMBOL = Symbol.for('nodejs.util.inspect.custom');

/**
 * SensitiveString - A secure wrapper for sensitive string data.
 *
 * Features:
 * - True runtime encapsulation via ES2022 #private fields
 * - Automatic redaction in toString(), toJSON(), and util.inspect()
 * - Explicit reveal() for raw value access with audit hooks
 * - Constant-time comparison for credentials (timing attack prevention)
 * - Policy-based behavior per sensitivity class
 * - Optional label for finer-grained audit/compliance categorization
 *
 * @typeParam C - The sensitivity class for this instance
 *
 * @example
 * ```ts
 * // Basic usage - credential (API key, password, token)
 * const apiKey = new SensitiveString(process.env.API_KEY!, 'credential', 'api_key');
 *
 * // Sensitive data (PII, business data)
 * const email = new SensitiveString(user.email, 'sensitive', 'email');
 *
 * console.log(apiKey);           // SensitiveString<credential:api_key> { [REDACTED:credential] }
 * JSON.stringify({ key: apiKey }); // {"key":"[REDACTED:credential]"}
 *
 * // Explicit access with audit context
 * const raw = apiKey.reveal({ name: 'api-call', reason: 'authenticating' });
 * ```
 */
export class SensitiveString<C extends SensitivityClass = 'sensitive'> {
  /**
   * The raw value. Using ES2022 #private for true runtime encapsulation.
   * This field is inaccessible outside the class, even via reflection or type coercion.
   */
  #value: string;

  /**
   * The sensitivity classification for this value.
   */
  readonly klass: C;

  /**
   * Optional label for audit/compliance categorization.
   * Examples: 'api_key', 'email', 'ssn', 'session_token'
   */
  readonly label: string | undefined;

  /**
   * Create a new SensitiveString.
   *
   * @param value - The raw string value to protect
   * @param klass - The sensitivity classification ('credential' or 'sensitive')
   * @param label - Optional label for audit/compliance (e.g., 'api_key', 'email')
   */
  constructor(value: string, klass: C, label?: string) {
    this.#value = value;
    this.klass = klass;
    this.label = label;
  }

  /**
   * Get the policy for this instance's sensitivity class.
   */
  private get policy(): SensitivityPolicy {
    return getPolicy(this.klass);
  }

  /**
   * Returns the redacted form of this value.
   * Safe for logging and display.
   */
  toString(): string {
    return this.policy.redact(this.#value);
  }

  /**
   * Returns the redacted form for JSON serialization.
   * Automatically called by JSON.stringify().
   */
  toJSON(): string {
    return this.toString();
  }

  /**
   * Custom inspect for Node.js util.inspect() and console.log().
   * Displays the class, optional label, and redacted value.
   */
  [NODE_INSPECT_SYMBOL](): string {
    const klassLabel = this.label ? `${this.klass}:${this.label}` : this.klass;
    return `SensitiveString<${klassLabel}> { ${this.toString()} }`;
  }

  /**
   * Reveal the raw value.
   *
   * @param ctx - Optional explicit reveal context. If not provided, uses AsyncLocalStorage context.
   * @returns The raw (unredacted) string value
   * @throws If policy.checkRevealAllowed() rejects the context
   *
   * @remarks
   * If a RevealContext is active (via withRevealContext() or explicit parameter),
   * its auditReveal callback will be invoked.
   */
  reveal(ctx?: RevealContext): string {
    const effectiveCtx = ctx ?? getCurrentRevealContext();

    // Allow policy to reject the reveal
    this.policy.checkRevealAllowed?.(effectiveCtx);

    // Audit the reveal if context has an audit callback
    effectiveCtx?.auditReveal?.(this);

    return this.#value;
  }

  /**
   * Compare this value with another string or SensitiveString.
   *
   * For the 'credential' class, uses constant-time comparison
   * to prevent timing attacks.
   *
   * @param other - The value to compare against
   * @param ctx - Optional reveal context (needed if other is a SensitiveString)
   * @returns true if values are equal
   *
   * @remarks
   * Length differences are unavoidable information leakage in timing-safe comparisons.
   */
  equals(other: string | SensitiveString<SensitivityClass>, ctx?: RevealContext): boolean {
    const rawOther =
      other instanceof SensitiveString ? other.reveal(ctx) : other;

    if (this.policy.requireConstantTimeEquals) {
      const a = Buffer.from(this.#value, 'utf8');
      const b = Buffer.from(rawOther, 'utf8');

      // Length difference is unavoidable information leakage
      if (a.length !== b.length) {
        return false;
      }

      return timingSafeEqual(a, b);
    }

    return this.#value === rawOther;
  }

  /**
   * Concatenate this value with another string or SensitiveString.
   *
   * The result inherits the most restrictive sensitivity class.
   * Labels are combined with '/' separator if both exist.
   *
   * @param other - The value to append
   * @param ctx - Optional reveal context (needed if other is a SensitiveString)
   * @returns A new SensitiveString with the concatenated value
   */
  concat<D extends SensitivityClass>(
    other: string | SensitiveString<D>,
    ctx?: RevealContext
  ): SensitiveString<SensitivityClass> {
    const rawOther =
      other instanceof SensitiveString ? other.reveal(ctx) : other;
    const otherClass: SensitivityClass =
      other instanceof SensitiveString ? other.klass : 'sensitive';
    const otherLabel =
      other instanceof SensitiveString ? other.label : undefined;

    const combinedClass = this.policy.combineClasses
      ? this.policy.combineClasses(this.klass, otherClass)
      : defaultCombineClasses(this.klass, otherClass);

    // Combine labels if both exist
    const combinedLabel =
      this.label && otherLabel
        ? `${this.label}/${otherLabel}`
        : this.label ?? otherLabel;

    return new SensitiveString(this.#value + rawOther, combinedClass, combinedLabel);
  }

  /**
   * Get the length of the raw value.
   * Note: Length is generally not considered sensitive for most use cases.
   */
  get length(): number {
    return this.#value.length;
  }

  /**
   * Check if the raw value is empty.
   */
  isEmpty(): boolean {
    return this.#value.length === 0;
  }

  /**
   * Create a substring of this value.
   *
   * @param start - Start index
   * @param end - End index (optional)
   * @param ctx - Reveal context for audit
   * @returns A new SensitiveString with the same class and label
   */
  substring(start: number, end?: number, ctx?: RevealContext): SensitiveString<C> {
    // Audit this operation as it involves the raw value
    const effectiveCtx = ctx ?? getCurrentRevealContext();
    effectiveCtx?.auditReveal?.(this);

    return new SensitiveString(this.#value.substring(start, end), this.klass, this.label);
  }

  /**
   * Serialize for service-to-service transmission.
   *
   * The envelope contains the raw (unredacted) value and must be
   * transmitted over secure channels (mTLS, encrypted message buses, etc.).
   *
   * @param ctx - Reveal context for audit
   * @returns A SensitiveEnvelope containing the raw value
   *
   * @remarks
   * Use SensitiveString.fromEnvelope() on the receiving service to reconstruct.
   * This is separate from toJSON() which always redacts.
   */
  toEnvelope(ctx?: RevealContext): SensitiveEnvelope {
    const envelope: SensitiveEnvelope = {
      __sensitive: true as const,
      klass: this.klass,
      value: this.reveal(ctx),
    };
    if (this.label !== undefined) {
      envelope.label = this.label;
    }
    return envelope;
  }

  /**
   * Reconstruct a SensitiveString from an envelope.
   *
   * @param envelope - The envelope to parse
   * @returns A new SensitiveString
   * @throws If the envelope is invalid (missing __sensitive marker)
   *
   * @example
   * ```ts
   * // Receiving service
   * const token = SensitiveString.fromEnvelope(payload.token);
   * ```
   */
  static fromEnvelope<C extends SensitivityClass>(
    envelope: SensitiveEnvelope
  ): SensitiveString<C> {
    if (!envelope.__sensitive) {
      throw new Error('Invalid SensitiveEnvelope: missing __sensitive marker');
    }
    return new SensitiveString(envelope.value, envelope.klass as C, envelope.label);
  }

  /**
   * Create a SensitiveString if the input is truthy, otherwise return null.
   * Useful for optional fields.
   */
  static fromOptional<C extends SensitivityClass>(
    value: string | null | undefined,
    klass: C,
    label?: string
  ): SensitiveString<C> | null {
    if (value == null || value === '') {
      return null;
    }
    return new SensitiveString(value, klass, label);
  }

  /**
   * Map over the raw value, producing a new SensitiveString.
   * The transformation function receives the raw value.
   *
   * @param fn - Transformation function
   * @param ctx - Reveal context for audit
   * @returns A new SensitiveString with the transformed value, preserving class and label
   */
  map(fn: (value: string) => string, ctx?: RevealContext): SensitiveString<C> {
    const effectiveCtx = ctx ?? getCurrentRevealContext();
    effectiveCtx?.auditReveal?.(this);

    return new SensitiveString(fn(this.#value), this.klass, this.label);
  }

  /**
   * Reclassify this value with a different sensitivity class and/or label.
   * Creates a new SensitiveString with the same value but different class/label.
   *
   * @param newKlass - The new sensitivity class
   * @param newLabel - Optional new label (if undefined, preserves existing label)
   * @param ctx - Reveal context for audit
   * @returns A new SensitiveString with the new class
   *
   * @remarks
   * Use with caution - this bypasses the automatic class escalation logic.
   */
  reclassify<D extends SensitivityClass>(
    newKlass: D,
    newLabel?: string,
    ctx?: RevealContext
  ): SensitiveString<D> {
    const effectiveCtx = ctx ?? getCurrentRevealContext();
    effectiveCtx?.auditReveal?.(this);

    return new SensitiveString(this.#value, newKlass, newLabel ?? this.label);
  }
}
