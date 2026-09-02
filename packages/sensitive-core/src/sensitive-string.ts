import { timingSafeEqual } from 'node:crypto';
import type {
  SensitivityClass,
  SensitivityPolicy,
  SensitiveStringOptions,
  SerializedSensitiveString,
  RevealContext,
} from './types.js';
import { getPolicy, defaultCombineClasses, hasPolicy } from './policy.js';
import { getCurrentRevealContext } from './context.js';

/**
 * Node.js custom inspect symbol for util.inspect() and console.log().
 */
const NODE_INSPECT_SYMBOL = Symbol.for('nodejs.util.inspect.custom');

/**
 * How a caller uses the raw value determines authorization and auditing.
 * Safe reads only feed redaction or intentionally public metadata. Comparisons
 * are authorized but are not reveals. Exposing reads are authorized and audited.
 */
type RawValueAccess = 'safe' | 'compare' | 'expose';

/**
 * Shared by a value and all of its derivatives. Feature implementations add
 * constraint state (such as reveal counters) here rather than copying it.
 */
interface SensitiveStringState {
  readonly options: SensitiveStringOptions;
}

/**
 * Secure wrapper for sensitive string data.
 *
 * Features:
 * - Runtime encapsulation via ES2022 #private fields.
 * - Automatic redaction in `toString()`, `toJSON()`, and `util.inspect()`.
 * - Constant-time comparison for credentials.
 * - Audit hooks on access via `reveal()`.
 *
 * @typeParam C - Sensitivity class ('sensitive' | 'credential').
 *
 * @example
 * ```ts
 * const apiKey = new SensitiveString(process.env.API_KEY!, 'credential', 'api_key');
 * console.log(apiKey); // SensitiveString<credential:api_key> { [REDACTED:credential] }
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
   * State inherited from the values this instance was derived from. Multiple
   * sources are retained for concat so future constraints and counters remain
   * shared without dropping either parent.
   */
  #states: readonly SensitiveStringState[];

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
   * @param options - Shared options for access constraints and feature behavior
   */
  constructor(value: string, klass: C, label?: string, options?: SensitiveStringOptions) {
    this.#value = value;
    this.#states = [{ options: options ?? {} }];
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
   * The sole accessor for #value.
   *
   * Feature-level checks such as expiry, revocation, and environment
   * restrictions belong here so no operation can bypass them. Redaction and
   * documented metadata reads stay available even when access is denied.
   */
  #readRawValue(access: RawValueAccess, ctx?: RevealContext): string {
    if (access === 'safe') {
      return this.#value;
    }

    const effectiveCtx = ctx ?? getCurrentRevealContext();
    this.policy.checkRevealAllowed?.(effectiveCtx);

    if (access === 'expose') {
      effectiveCtx?.auditReveal?.(this);
    }

    return this.#value;
  }

  /**
   * Construct a derived instance while retaining every source state object.
   */
  static #derived<D extends SensitivityClass>(
    value: string,
    klass: D,
    label: string | undefined,
    sources: readonly SensitiveString<SensitivityClass>[]
  ): SensitiveString<D> {
    const derived = new SensitiveString(value, klass, label);
    const states = new Set<SensitiveStringState>();

    for (const source of sources) {
      for (const state of source.#states) {
        states.add(state);
      }
    }

    derived.#states = Array.from(states);
    return derived;
  }

  /**
   * Returns the redacted form of this value.
   * Safe for logging and display.
   */
  toString(): string {
    return this.policy.redact(this.#readRawValue('safe'));
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
   * Returns the raw (unredacted) value.
   *
   * Triggers audit logging if a RevealContext is active.
   *
   * @param ctx - Optional explicit reveal context.
   * @throws If policy checking fails.
   */
  reveal(ctx?: RevealContext): string {
    return this.#readRawValue('expose', ctx);
  }

  /**
   * Compare this value with another string or SensitiveString.
   *
   * For the 'credential' class, uses constant-time comparison
   * to prevent timing attacks.
   *
   * @param other - The value to compare against
   * @param ctx - Optional reveal context for policy checks
   * @returns true if values are equal
   *
   * @remarks
   * Length differences are unavoidable information leakage in timing-safe comparisons.
   */
  equals(other: string | SensitiveString<SensitivityClass>, ctx?: RevealContext): boolean {
    const value = this.#readRawValue('compare', ctx);
    const rawOther = other instanceof SensitiveString ? other.#readRawValue('compare', ctx) : other;

    if (this.policy.requireConstantTimeEquals) {
      const a = Buffer.from(value, 'utf8');
      const b = Buffer.from(rawOther, 'utf8');

      // Length difference is unavoidable information leakage
      if (a.length !== b.length) {
        return false;
      }

      return timingSafeEqual(a, b);
    }

    return value === rawOther;
  }

  /**
   * Concatenate with another string or SensitiveString.
   *
   * Inherits the most restrictive sensitivity class.
   * Labels are combined with '/' separator.
   *
   * @param other - The value to append.
   * @param ctx - Audit context for raw-value access.
   */
  concat<D extends SensitivityClass>(
    other: string | SensitiveString<D>,
    ctx?: RevealContext
  ): SensitiveString<SensitivityClass> {
    const value = this.#readRawValue('expose', ctx);
    const rawOther = other instanceof SensitiveString ? other.#readRawValue('expose', ctx) : other;
    const otherClass: SensitivityClass =
      other instanceof SensitiveString ? other.klass : 'sensitive';
    const otherLabel = other instanceof SensitiveString ? other.label : undefined;

    const combinedClass = this.policy.combineClasses
      ? this.policy.combineClasses(this.klass, otherClass)
      : defaultCombineClasses(this.klass, otherClass);

    // Combine labels if both exist
    const combinedLabel =
      this.label && otherLabel ? `${this.label}/${otherLabel}` : (this.label ?? otherLabel);

    const sources: SensitiveString<SensitivityClass>[] =
      other instanceof SensitiveString ? [this, other] : [this];

    return SensitiveString.#derived(value + rawOther, combinedClass, combinedLabel, sources);
  }

  /**
   * Get the length of the raw value.
   * Note: Length is generally not considered sensitive for most use cases.
   */
  get length(): number {
    return this.#readRawValue('safe').length;
  }

  /**
   * Check if the raw value is empty.
   */
  isEmpty(): boolean {
    return this.#readRawValue('safe').length === 0;
  }

  /**
   * Create a substring, preserving sensitivity class and label.
   *
   * @param start - Start index.
   * @param end - Optional end index.
   * @param ctx - Audit context.
   * @throws If policy checking fails (e.g., context required but not provided).
   */
  substring(start: number, end?: number, ctx?: RevealContext): SensitiveString<C> {
    const value = this.#readRawValue('expose', ctx);
    return SensitiveString.#derived(value.substring(start, end), this.klass, this.label, [this]);
  }

  /**
   * Serialize for secure service boundary transmission.
   *
   * ⚠️ RETURNS RAW VALUE - DO NOT LOG ⚠️
   *
   * Intended for mTLS/encrypted transmission only.
   *
   * @param ctx - Optional context for audit/permission checks
   */
  serialize(ctx?: RevealContext): SerializedSensitiveString {
    const value = this.#readRawValue('expose', ctx);

    if (this.label !== undefined) {
      return {
        __sensitive: true as const,
        klass: this.klass,
        value,
        label: this.label,
      };
    }

    return {
      __sensitive: true as const,
      klass: this.klass,
      value,
    };
  }

  /**
   * Reconstruct a SensitiveString from a serialized form.
   *
   * @param serialized - The serialized form (potentially untrusted data from external source).
   * @throws If the serialized form is invalid or missing required fields.
   * @throws If the klass is not a registered sensitivity class.
   */
  static deserialize<C extends SensitivityClass>(serialized: unknown): SensitiveString<C> {
    // Type guard for runtime validation of untrusted data
    if (
      typeof serialized !== 'object' ||
      serialized === null ||
      !('__sensitive' in serialized) ||
      serialized.__sensitive !== true
    ) {
      throw new Error('Invalid SerializedSensitiveString: missing __sensitive marker');
    }
    if (!('value' in serialized) || typeof serialized.value !== 'string') {
      throw new Error('Invalid SerializedSensitiveString: value must be a string');
    }
    if (!('klass' in serialized) || typeof serialized.klass !== 'string') {
      throw new Error('Invalid SerializedSensitiveString: klass must be a string');
    }

    // Validate that klass is a registered sensitivity class
    if (!hasPolicy(serialized.klass as SensitivityClass)) {
      throw new Error(
        `Invalid SerializedSensitiveString: unknown sensitivity class '${serialized.klass}'`
      );
    }

    if (
      'label' in serialized &&
      serialized.label !== undefined &&
      typeof serialized.label !== 'string'
    ) {
      throw new Error('Invalid SerializedSensitiveString: label must be a string or undefined');
    }

    const label =
      'label' in serialized && typeof serialized.label === 'string' ? serialized.label : undefined;

    return new SensitiveString(serialized.value, serialized.klass as C, label);
  }

  /**
   * Create a SensitiveString if the input is truthy, otherwise return null.
   * Useful for optional fields.
   */
  static fromOptional<C extends SensitivityClass>(
    value: string | null | undefined,
    klass: C,
    label?: string,
    options?: SensitiveStringOptions
  ): SensitiveString<C> | null {
    if (value == null || value === '') {
      return null;
    }
    return new SensitiveString(value, klass, label, options);
  }

  /**
   * Map over the raw value, producing a new SensitiveString.
   * The transformation function receives the raw value.
   *
   * @param fn - Transformation function
   * @param ctx - Reveal context for audit
   * @returns A new SensitiveString with the transformed value, preserving class and label
   * @throws If policy checking fails (e.g., context required but not provided).
   */
  map(fn: (value: string) => string, ctx?: RevealContext): SensitiveString<C> {
    const value = this.#readRawValue('expose', ctx);
    return SensitiveString.#derived(fn(value), this.klass, this.label, [this]);
  }

  /**
   * Reclassify this value with a different sensitivity class and/or label.
   * Creates a new SensitiveString with the same value but different class/label.
   *
   * @param newKlass - The new sensitivity class
   * @param newLabel - Optional new label (if undefined, preserves existing label)
   * @param ctx - Reveal context for audit
   * @returns A new SensitiveString with the new class
   * @throws If policy checking fails (e.g., context required but not provided).
   *
   * @remarks
   * Use with caution - this bypasses the automatic class escalation logic.
   */
  reclassify<D extends SensitivityClass>(
    newKlass: D,
    newLabel?: string,
    ctx?: RevealContext
  ): SensitiveString<D> {
    const value = this.#readRawValue('expose', ctx);
    return SensitiveString.#derived(value, newKlass, newLabel ?? this.label, [this]);
  }
}
