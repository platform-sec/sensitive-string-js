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
 * Options shared by every SensitiveString feature.
 *
 * This interface is intentionally empty until an option-bearing feature is
 * implemented. It is defined centrally so features can add optional fields
 * without introducing competing constructor arguments. As an interface, it
 * can also be extended through declaration merging by integration packages.
 */
// eslint-disable-next-line @typescript-eslint/no-empty-interface
export interface SensitiveStringOptions {}

/**
 * Built-in masking strategies for well-known value formats, plus `custom` for a
 * caller-supplied one.
 */
export type MaskStrategy = 'email' | 'phone' | 'card' | 'ssn' | 'uuid' | 'custom';

/**
 * Options for `SensitiveString.mask()`.
 *
 * Positional options (`showFirst`, `showLast`) and `strategy` are mutually
 * exclusive: a strategy decides what it shows, so combining the two would
 * silently ignore a caller's attempt to narrow the result.
 */
export interface MaskOptions {
  /** Leading characters to leave visible. Positional masking only. */
  showFirst?: number;
  /** Trailing characters to leave visible. Positional masking only. */
  showLast?: number;
  /** Replacement character for hidden characters. Exactly one code point. Defaults to `'*'`. */
  maskChar?: string;
  /**
   * Minimum characters the result must hide.
   *
   * Defaults to 4 for `sensitive` and 8 for `credential`. A caller may raise
   * the floor but not lower it, and a rendering that cannot reach it falls back
   * to full redaction.
   */
  minMasked?: number;
  /** Format-aware strategy to apply instead of positional masking. */
  strategy?: MaskStrategy;
  /**
   * Formatter for `strategy: 'custom'`.
   *
   * ⚠️ Receives the RAW value. This is a reveal in all but name: the floor
   * cannot be measured against output the library did not produce.
   */
  customStrategy?: (value: string) => string;
}

/**
 * Audit record for a full reveal.
 */
export interface RevealAuditDetails {
  readonly operation: 'reveal';
}

/**
 * Audit record for a partial reveal through `mask()`.
 *
 * `customStrategy` is deliberately absent: an audit sink should not receive a
 * function whose source it might serialize into a log.
 */
export interface MaskAuditDetails {
  readonly operation: 'mask';
  /** The strategy applied, or `'positional'` for `showFirst` / `showLast` masking. */
  readonly strategy: MaskStrategy | 'positional';
  readonly showFirst: number;
  readonly showLast: number;
  readonly minMasked: number;
  readonly maskChar: string;
}

/**
 * What the audited operation was, so an audit sink can tell a full reveal from
 * a partial one.
 */
export type RevealDetails = RevealAuditDetails | MaskAuditDetails;

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
  /**
   * Callback invoked when a sensitive value is revealed.
   *
   * `details` distinguishes a full reveal from a partial one and carries the
   * mask options that produced it.
   */
  auditReveal?(value: ISensitiveString, details: RevealDetails): void;
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
   * Allow queries that disclose partial information about the raw value.
   * Defaults to true for sensitive values and false for credentials.
   */
  allowPartialQueries?: boolean;

  /**
   * Allow partially masked output from `mask()`.
   * Defaults to true for sensitive values and false for credentials.
   */
  allowMask?: boolean;

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
