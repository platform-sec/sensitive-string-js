/**
 * Sensitivity classification for data protection.
 * Domain-agnostic - suitable for any vertical (payments, healthcare, internal tools, etc.)
 */
export type SensitivityClass =
  | 'generic' // basic sensitive data
  | 'secret' // secrets, passwords, tokens
  | 'token' // auth tokens, session tokens
  | 'pii_email' // email addresses
  | 'pii_generic'; // other PII

/**
 * Precedence ordering for combining sensitivity classes.
 * Higher index = more restrictive.
 */
export const SENSITIVITY_PRECEDENCE: readonly SensitivityClass[] = [
  'generic',
  'pii_generic',
  'pii_email',
  'token',
  'secret',
] as const;

/**
 * Advisory metadata for sensitivity policies.
 * NOT enforced by this library in MVP - use for documentation,
 * external policy engines, and future enforcement.
 */
export interface SensitivityAdvisory {
  /** Whether hashing is allowed for this data type */
  allowHash?: boolean;
  /** Whether plaintext persistence is allowed */
  allowPersistPlain?: boolean;
  /** Whether encrypted persistence is allowed */
  allowPersistEncrypted?: boolean;
  /** Whether sending to logs (redacted form only) is allowed */
  allowSendToLog?: boolean;
  /** Generic external sink flag */
  allowSendToExternal?: boolean;
  /** Risk level indicator */
  criticality?: 'low' | 'medium' | 'high';
}

/**
 * Forward declaration for SensitiveString to avoid circular deps.
 * The actual class is defined in sensitive-string.ts
 */
export interface ISensitiveString {
  readonly klass: SensitivityClass;
  toString(): string;
  reveal(ctx?: RevealContext): string;
}

/**
 * Context for tracking and auditing reveal operations.
 * Can be passed explicitly or set via AsyncLocalStorage.
 */
export interface RevealContext {
  /** Descriptive name for the context (e.g., "http-request", "migration-job") */
  name: string;
  /** Human-readable justification for the reveal */
  reason?: string;
  /** Freeform metadata (request ID, user ID, etc.) */
  tags?: Record<string, unknown>;
  /** Callback invoked when a sensitive value is revealed */
  auditReveal?(value: ISensitiveString): void;
}

/**
 * Policy definition for a sensitivity class.
 * Controls redaction, security behavior, and reveal authorization.
 */
export interface SensitivityPolicy {
  /** The sensitivity class this policy applies to */
  name: SensitivityClass;

  /**
   * Transform a raw value into its redacted form.
   * Called by toString(), toJSON(), and inspect.
   */
  redact(value: string): string;

  /** Use constant-time comparison for equals() operations */
  requireConstantTimeEquals?: boolean;

  /**
   * Hook to validate whether reveal is allowed in the given context.
   * Throw an error to deny the reveal.
   */
  checkRevealAllowed?(ctx: RevealContext | null): void;

  /**
   * Determine the resulting class when combining two sensitive values.
   * If not provided, defaultCombineClasses is used.
   */
  combineClasses?(a: SensitivityClass, b: SensitivityClass): SensitivityClass;

  /** Advisory metadata - not enforced in MVP */
  advisory?: SensitivityAdvisory;
}

/**
 * Envelope format for service-to-service transmission.
 * Contains the raw value and must be explicitly created via toEnvelope().
 */
export interface SensitiveEnvelope {
  /** Marker to identify this as a sensitive envelope */
  __sensitive: true;
  /** The sensitivity classification */
  klass: SensitivityClass;
  /** The raw (unredacted) value */
  value: string;
}
