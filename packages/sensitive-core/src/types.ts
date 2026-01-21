/**
 * Sensitivity classification for data protection.
 *
 * Simplified to two classes based on the only behavioral difference that matters:
 * - `credential`: Requires constant-time comparison (passwords, API keys, tokens)
 * - `sensitive`: Everything else that shouldn't leak (PII, business-sensitive data)
 *
 * For finer-grained categorization (compliance, audit logs), use the optional `label` field.
 */
export type SensitivityClass = 'credential' | 'sensitive';

/**
 * Precedence ordering for combining sensitivity classes.
 * Higher index = more restrictive.
 * credential > sensitive (credentials require constant-time comparison)
 */
export const SENSITIVITY_PRECEDENCE: readonly SensitivityClass[] = [
  'sensitive',
  'credential',
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
  /** Optional label for audit/compliance categorization (e.g., 'api_key', 'email', 'ssn') */
  readonly label: string | undefined;
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
 * Serialized format for secure service-to-service transmission.
 *
 * ⚠️ Contains RAW (UNREDACTED) value.
 * Created via `serialize()`.
 */
export interface SerializedSensitiveString {
  /** Marker to identify this as a serialized sensitive string */
  __sensitive: true;
  /** The sensitivity classification */
  klass: SensitivityClass;
  /** The raw (unredacted) value */
  value: string;
  /** Optional label for audit/compliance categorization */
  label?: string;
}
