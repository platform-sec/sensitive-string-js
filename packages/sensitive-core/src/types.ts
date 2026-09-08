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
 * There is one options object rather than a fourth constructor argument per
 * feature, so features compose instead of competing. As an interface, it can
 * also be extended through declaration merging by integration packages.
 */
export interface SensitiveStringOptions {
  /**
   * Lifetime in milliseconds, measured from construction.
   *
   * `0` means the value is already expired, which is the most conservative TTL
   * a caller can ask for. Mutually exclusive with `expiresAt`.
   */
  ttl?: number;

  /**
   * Absolute deadline. Mutually exclusive with `ttl`.
   *
   * Read once, at construction, so mutating the Date afterwards does not move
   * the deadline. A deadline in the past yields a value that is already expired.
   */
  expiresAt?: Date;

  /**
   * Whether `renew()` may extend the deadline.
   *
   * Defaults to `false` for `credential` and `true` for `sensitive`. A policy
   * that sets `allowRenewal: false` forbids renewal outright, and this option
   * cannot lift that.
   */
  allowRenewal?: boolean;

  /** Total number of renewals allowed. Unlimited when unset. */
  maxRenewals?: number;

  /**
   * Called once when expiry is first detected, on the value and on everything
   * derived from it. Errors thrown by it are swallowed.
   */
  onExpire?: () => void;

  /**
   * Total number of times this value may be exposed, over its whole life.
   *
   * `0` means it may never be exposed, which is the most conservative budget a
   * caller can ask for. The count is shared with everything derived from the
   * value, and nothing resets it.
   */
  maxReveals?: number;

  /**
   * Length of the sliding rate-limit window, in milliseconds.
   *
   * Must be given together with `maxRevealsPerWindow`: either alone is no rate
   * limit at all.
   */
  revealWindow?: number;

  /** Exposures allowed within `revealWindow`. Must be at least 1. */
  maxRevealsPerWindow?: number;

  /**
   * A revocation list consulted on every read of this value, in addition to the
   * process-global one that `revokeByLabel()` and `revokeByPattern()` write.
   *
   * It is matched against the label this value is constructed with. A value
   * with no label is still consulted for, with `undefined` as the label, so a
   * registry decides for itself whether it can refuse one; the built-in
   * `RevocationList` cannot, and answers false.
   */
  revocationRegistry?: RevocationRegistry;

  /**
   * Where this value may be read: an environment, a region, a datacenter, or a
   * predicate of the caller's own.
   *
   * Checked against the process-global {@link setEnvironmentInfo} declaration
   * on every read, in the same gate expiry and revocation sit in, so a
   * substring or a template result is restricted exactly as its source is.
   *
   * A list is accepted as well as a single set, and every set has to pass. That
   * is what lets a value derived from two restricted values carry both, and
   * what lets the wire format carry them back.
   */
  restrictions?: EnvironmentRestrictions | readonly EnvironmentRestrictions[];

  /**
   * Hold the value as AES-256-GCM ciphertext in a `Buffer` rather than as a
   * JavaScript string.
   *
   * This is not encryption at rest. The key is in this process, so it defends
   * against a heap snapshot taken while no reveal is in flight and against an
   * accidental disclosure of the stored bytes. It does not defend against a
   * core dump, and it does not defend against code running in this process.
   *
   * Two costs, and the second is the one that decides whether a value should be
   * sealed at all:
   *
   * - Every operation that runs a cipher gets slower, and the ones that do not
   *   are unchanged. Reading, constructing and deriving are one to two orders
   *   of magnitude slower than the same operation on an unsealed value, and
   *   deriving is the worst of the three because it decrypts and then seals the
   *   result. Comparing is much the mildest, a small single-digit multiple,
   *   because the constant-time path already hashes both operands. Redaction,
   *   `length` and `isEmpty()` show no measurable difference at all: they
   *   answer from what was captured at construction and never decrypt. No
   *   sharper figure is given here on purpose. Repeated runs of
   *   `__benchmarks__/sealing.bench.ts` on an idle machine moved these ratios
   *   by a factor of three, so run `pnpm bench` on your own hardware and read
   *   the gap between a group's members rather than any single number. Each
   *   value also costs a couple of hundred extra bytes, most of it the box,
   *   which lives outside the V8 heap.
   * - **Every string-returning reveal leaves one copy of the plaintext in
   *   process memory that garbage collection does not remove.** Measured across
   *   two processes: a thousand `reveal()` calls leave about 940 copies, where
   *   a thousand on an unsealed value leave two, because that returns the same
   *   string object each time. `revealBytes()` and `equals()` leave none, so a
   *   value read repeatedly should use those.
   *
   * Worth sealing: a credential loaded once at startup and held for the life of
   * the process. Not worth sealing: a value wrapped per request, whose
   * plaintext the caller's own parsed body still holds anyway.
   *
   * Two behaviours differ from an unsealed value, both deliberate. A sealed
   * value's redacted rendering is captured at construction, so a policy
   * registered afterwards does not change it. And rewriting `klass` or `label`
   * at runtime makes the value unreadable rather than reclassified, because
   * both are bound into the GCM additional data.
   *
   * Defaults to the process setting from `setSealing()`, which is off.
   */
  sealed?: boolean;
}

/**
 * Where the process believes it is running.
 *
 * Declared once at startup through {@link setEnvironmentInfo}. Every field is
 * copied when it is declared, so mutating the object afterwards does not move
 * the environment.
 */
export interface EnvironmentInfo {
  /**
   * Deployment environment: `development`, `staging`, `production`, `test`, or
   * whatever this deployment calls them. Compared literally, so the spelling
   * has to match what a restriction lists.
   */
  environment: string;

  /** Cloud region, such as `eu-west-1`. The only field a pattern may match. */
  region?: string | undefined;

  /** Datacenter identifier. Compared literally. */
  datacenter?: string | undefined;

  /**
   * Anything else this deployment wants a custom restriction to be able to read.
   * Copied and frozen when the environment is declared.
   */
  customTags?: Record<string, string> | undefined;
}

/**
 * Where a value may be read.
 *
 * Every field that is present has to pass. An allowlist and a denylist over the
 * same field are both applied, so a name on both lists is denied.
 *
 * A field the environment does not state is read differently by the two kinds
 * of list: an allowlist refuses, because "only here" is not satisfied by a
 * deployment that cannot say where it is, and a denylist passes, because "not
 * there" concludes nothing from silence.
 */
export interface EnvironmentRestrictions {
  /** Environments this value may be read in. Matched literally. */
  allowedEnvironments?: readonly string[] | undefined;

  /** Environments this value may not be read in. Matched literally. */
  deniedEnvironments?: readonly string[] | undefined;

  /**
   * Regions this value may be read in.
   *
   * An entry is a literal region name or a prefix ending in `*`, such as
   * `eu-*`. A `*` anywhere else is refused at construction rather than matched
   * as a literal, which would leave the list matching nothing.
   */
  allowedRegions?: readonly string[] | undefined;

  /** Regions this value may not be read in. Same pattern rule as the allowlist. */
  deniedRegions?: readonly string[] | undefined;

  /** Datacenters this value may be read in. Matched literally. */
  allowedDatacenters?: readonly string[] | undefined;

  /** Datacenters this value may not be read in. Matched literally. */
  deniedDatacenters?: readonly string[] | undefined;

  /**
   * A predicate of the caller's own, asked last and handed the frozen
   * environment.
   *
   * It must return `true` to allow the read. Anything else, including a
   * Promise from an `async` function, is a refusal, and so is a throw.
   *
   * A function is not data: a value carrying one cannot be serialized or
   * handed to a worker, because the far side would enforce the declarative
   * half and silently not this.
   */
  custom?: ((env: Readonly<EnvironmentInfo>) => boolean) | undefined;

  /** What to say when `custom` refuses. Requires `custom`. */
  customMessage?: string | undefined;
}

/**
 * The wire form of {@link EnvironmentRestrictions}.
 *
 * The declarative fields and nothing else. `custom` has no wire form, and a
 * value that carries one refuses to serialize rather than crossing without it.
 */
export interface SerializedEnvironmentRestrictions {
  allowedEnvironments?: string[];
  deniedEnvironments?: string[];
  allowedRegions?: string[];
  deniedRegions?: string[];
  allowedDatacenters?: string[];
  deniedDatacenters?: string[];
}

/**
 * Where a revocation came from.
 *
 * - `instance`: somebody called `revoke()` on the value or on something derived
 *   from it.
 * - `label`, `pattern`: the process-global lists.
 * - `registry`: the `revocationRegistry` the value was constructed with.
 * - `wire`: the value arrived from `deserialize()` already marked revoked.
 * - `unavailable`: the registry could not be reached, or did not answer the
 *   contract, so the read is refused because nothing could confirm it.
 */
export type RevocationScope =
  'instance' | 'label' | 'pattern' | 'registry' | 'wire' | 'unavailable';

/**
 * A revocation list a value consults, which may be backed by an external store.
 *
 * `isRevoked` must answer synchronously and must return a boolean. A read
 * happens in one call, so an implementation that returns a Promise has already
 * handed the value back by the time it resolves; the library refuses a
 * non-boolean answer rather than guessing which way to read it. An
 * implementation backed by a store therefore keeps a local cache and refreshes
 * it out of band, which is what `sync()` is for.
 *
 * Anything thrown from `isRevoked` denies the read. A store that cannot be
 * reached cannot confirm a value is usable.
 */
export interface RevocationRegistry {
  /** Whether this label is revoked. Must be synchronous and must return a boolean. */
  isRevoked(label: string | undefined): boolean;
  /** Why, for a revoked label. Anything it throws is swallowed. */
  getReason?(label: string): string | undefined;
  /** Record a revocation, for a registry that is writable from this process. */
  revoke?(label: string, reason: string): void;
  /** Refresh from the backing store. Never called by the library. */
  sync?(): Promise<void>;
}

/**
 * Options for `SensitiveString.renew()`.
 */
export interface RenewalOptions {
  /** Latest deadline this renewal may produce. The result is clamped to it. */
  maxExtension?: Date;
}

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
 * Digest algorithms `hash()` and `hmac()` accept.
 *
 * An allowlist, rather than whatever the Node build happens to support. MD5
 * and SHA-1 are absent because both are broken: a digest under either is a
 * recoverable copy of the value rather than a one-way derivative of it.
 */
export type HashAlgorithm = 'sha256' | 'sha384' | 'sha512' | 'sha3-256' | 'sha3-512';

/** How a digest is rendered. */
export type HashEncoding = 'hex' | 'base64' | 'base64url';

/**
 * Options for `SensitiveString.hash()`.
 */
export interface HashOptions {
  /**
   * Salt mixed in ahead of the value, so the same value under two salts gives
   * two digests and a precomputed table built for one does not answer for the
   * other.
   *
   * A string is read as UTF-8. It is prepended with no separator, which is what
   * makes the digest reproducible by anything else computing
   * `sha256(salt || value)`; the cost is that a variable-length salt is
   * ambiguous, since `('ab', 'c')` and `('a', 'bc')` hash alike. Use a
   * fixed-length salt, which is what a per-user salt from `randomBytes` is.
   *
   * A salt is not a key. It stops precomputation, and it does nothing at all
   * against an attacker who has the salt and guesses the value, which is every
   * attacker holding a digest and the record it came from. For a value an
   * attacker can enumerate, use `hmac()`.
   */
  salt?: string | Uint8Array;

  /** Digest rendering. Defaults to `'hex'`. */
  encoding?: HashEncoding;
}

/**
 * Options for `SensitiveString.hmac()`.
 */
export interface HmacOptions {
  /** Digest rendering. Defaults to `'hex'`. */
  encoding?: HashEncoding;
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
 * Audit record for a digest taken through `hash()`.
 *
 * The salt is deliberately absent. It is not the value and it is not secret,
 * but an audit sink is the one place a digest, the record it belongs to, and
 * the salt that produced it would all sit together, and a salt is only useful
 * to an attacker who has the other two.
 */
export interface HashAuditDetails {
  readonly operation: 'hash';
  readonly algorithm: HashAlgorithm;
  readonly encoding: HashEncoding;
  /** Whether a salt was mixed in. */
  readonly salted: boolean;
}

/**
 * Audit record for a digest taken through `hmac()`.
 *
 * A protected key produces a second record of its own, under this same
 * operation, because using a value as an HMAC key reads it.
 */
export interface HmacAuditDetails {
  readonly operation: 'hmac';
  readonly algorithm: HashAlgorithm;
  readonly encoding: HashEncoding;
  /** Whether the key was itself a protected value. */
  readonly protectedKey: boolean;
}

/**
 * Audit record for a deadline extension through `renew()`.
 *
 * Deadlines are ISO 8601 strings rather than Dates, so a sink receives a record
 * it can serialize directly and cannot use to move a deadline.
 */
export interface RenewAuditDetails {
  readonly operation: 'renew';
  /** The deadline before this renewal. */
  readonly previousExpiresAt: string;
  /** The deadline this renewal set. */
  readonly expiresAt: string;
  /** How many renewals this value has had, including this one. */
  readonly renewalCount: number;
}

/**
 * Audit record for a revocation through `revoke()`.
 *
 * Reported after the revocation has taken effect, not before it: nothing may
 * refuse a revocation, so a sink that throws is swallowed rather than allowed
 * to keep a value alive. That is the opposite of `renew()`, which is audited
 * first precisely so a sink can stop it.
 */
export interface RevokeAuditDetails {
  readonly operation: 'revoke';
  /** The caller-supplied reason. Developer text; it must not carry the value. */
  readonly reason: string;
  readonly revokedAt: string;
  readonly scope: RevocationScope;
}

/**
 * Audit record for a value leaving for another thread or process through
 * `toWorkerPayload()`.
 *
 * A handoff is authorized as an ordinary `expose`, since the raw value does
 * reach the caller, and is distinguished here rather than by a new access
 * kind: a policy that refuses `expose` today must keep refusing a handoff, and
 * a separate kind would route around every such policy. The caller's context
 * name is left alone, because that is the field an audit reader searches on;
 * where the value went is a field of this record instead.
 */
export interface WorkerHandoffAuditDetails {
  readonly operation: 'worker-handoff';
  /** The destination named to `toWorkerPayload()`. Recorded, never verified. */
  readonly worker: string | undefined;
  /** The key this value has in the payload. */
  readonly key: string;
  /**
   * Whether the authorizing context carried an `auditReveal` that cannot cross
   * the boundary. The receiving side is required to install its own.
   *
   * Always `true` in a record a sink actually receives, and deliberately still
   * a field rather than an assumption: a record is only delivered *through*
   * the hook this reports the loss of, so the sink reading it is the one being
   * dropped. Do not filter an audit log on `false` expecting to find handoffs
   * that kept their hook; there are none, because a context without a hook
   * records nothing at all.
   */
  readonly auditHookDropped: boolean;
}

/**
 * Audit record for a value destroyed through `clear()`.
 *
 * Reported after the value has been dropped, not before it, and with anything
 * the sink throws swallowed: nothing may refuse a clear, so a broken sink must
 * not make it look as though the destruction did not happen. That is the same
 * rule `revoke()` follows and the opposite of `renew()`, which audits first
 * precisely so a sink can stop it.
 */
export interface ClearAuditDetails {
  readonly operation: 'clear';
  /**
   * Whether the clear also refused every value derived from this one.
   *
   * True from an owner, which writes the shared state its derivatives read;
   * false from a derivative, which has no shared state of its own to write and
   * so destroys only its own copy.
   */
  readonly propagated: boolean;
}

/**
 * What the audited operation was, so an audit sink can tell a full reveal from
 * a partial one, and either from a lifetime extension, a revocation, a
 * destruction, or a handoff to another thread.
 */
export type RevealDetails =
  | RevealAuditDetails
  | MaskAuditDetails
  | HashAuditDetails
  | HmacAuditDetails
  | RenewAuditDetails
  | RevokeAuditDetails
  | ClearAuditDetails
  | WorkerHandoffAuditDetails;

/**
 * What a policy is being asked to authorize.
 *
 * - `compare`: `equals()`, which reads the value but never hands it to the
 *   caller and produces no audit record.
 * - `expose`: the value is read for the caller's benefit, whether in full
 *   through `reveal()` and `serialize()`, in part through `mask()` and the
 *   string and regex operations, or as a durable one-way derivative through
 *   `hash()` and `hmac()`. The last of those hands the caller nothing raw and
 *   is still an exposure: a digest of a value an attacker can enumerate is
 *   that value behind a lookup table.
 * - `renew`: not a read at all. The value's deadline is being extended.
 *
 * A read that only feeds redaction or documented metadata (`toString()`,
 * `length`) never reaches a policy and so has no kind here.
 */
export type RevealAccess = 'compare' | 'expose' | 'renew';

/**
 * Advisory metadata for sensitivity policies.
 *
 * Mostly not enforced: use it for documentation and for an external policy
 * engine. Two fields are read by code in this monorepo and each says so on
 * itself, with opposite defaults, because they answer opposite questions.
 */
export interface SensitivityAdvisory {
  /**
   * Whether a one-way digest of this class may be taken.
   *
   * Enforced by `hash()` and `hmac()`. `undefined` allows, unlike
   * `allowSendToExternal` below: hashing is the operation this library wants
   * used in place of holding a value, so the flag exists to forbid it for a
   * class where even a digest is too much, not to require permission for the
   * safe path.
   */
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
 * The context an audited operation ran under, as its audit sink sees it.
 *
 * The three descriptive fields, and no `auditReveal`: the sink reading this is
 * that hook, so the only use it has for its own hook is to call it, and the
 * gate the hook runs inside is not reentrant. It is the same trio that crosses
 * a thread boundary as a `PortableRevealContext`, for a different reason:
 * there because a function does not clone, here because a function is not
 * evidence.
 *
 * The narrowing is in the type and not in a copy. What arrives is the live
 * `RevealContext`, which is deliberate on both counts: a sink may compare it by
 * identity with the context it installed, and an audited reveal allocates
 * nothing to be recorded. A caller who casts can still reach the hook on it,
 * which is a contract being defeated rather than anything disclosed, since the
 * object is the one that caller built.
 *
 * Live also means read-only by convention. `tags` is the caller's own object,
 * shared by every reveal made under the context, so writing to it from a sink
 * changes what later reveals report. Copy out what a record needs to keep.
 */
export interface AuditContext {
  /** Descriptive name of the unit of work the operation ran under. */
  readonly name: string;
  /** Human-readable justification, when the context carried one. */
  readonly reason?: string;
  /** Freeform metadata: request ID, user ID, and whatever an integration tagged. */
  readonly tags?: Readonly<Record<string, unknown>>;
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
   *
   * `context` is the context the operation actually ran under: the one passed
   * to the call, or the ambient one when the call passed none, which is the
   * same context the policy's `checkRevealAllowed` was asked to authorize
   * against. It is not always the context this hook was installed on. A hook
   * inherited through `createChildContext()` is called with the child, so an
   * integration that tags a reveal with the table, the column or the argument
   * path reaches a sink here rather than through `getCurrentRevealContext()`,
   * which reports where the caller stood and not what the reveal was for.
   *
   * The return value is ignored. A sink that must stop the reveal throws
   * synchronously; a Promise it returns is not awaited, so a rejection after an
   * `await` cannot stop anything and surfaces as an unhandled rejection.
   *
   * ⚠️ The hook runs inside the raw-value gate, which is not reentrant. Reading
   * `value` from here, through `reveal()`, `mask()` or any operation that
   * derives from it, re-enters the gate and recurses until the stack is
   * exhausted; against a reveal budget it also charges the inner read before
   * the outer one has been charged. Read `klass` and `label`, and nothing else.
   */
  auditReveal?(value: ISensitiveString, details: RevealDetails, context: AuditContext): void;
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

  /**
   * How to recognize this policy's redacted output, for a policy whose
   * `redact` depends on the value.
   *
   * The guards that refuse to send a redaction onward, chiefly
   * `assertNoMarker` in `@platform-sec/sensitive-string-http`, learn a
   * policy's marker by redacting two probes of different lengths and keeping
   * the answer when both agree. A constant redaction gives itself away that
   * way; a value-dependent one cannot, so it declares its shape here instead.
   * Without it such a policy is recognized only by the default `[REDACTED:`
   * prefix, and a policy that does not use that prefix is not recognized at
   * all, which means a redaction leaves in a request body rather than being
   * refused.
   *
   * `deterministicRedaction()` sets it. A hand-written value-dependent policy
   * should set it too. Leave it unset for a constant redaction, which needs no
   * help.
   *
   * ⚠️ Must not carry the `g` flag. A global `RegExp` keeps `lastIndex`
   * between calls, so a shared one answers differently on every second scan.
   */
  readonly markerPattern?: RegExp;

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
   * Whether values of this class may be renewed.
   *
   * `false` is a prohibition that the `allowRenewal` construction option cannot
   * lift. `true` makes the class renewable by default. Unset leaves the class
   * default: credentials are not renewable, everything else is.
   */
  allowRenewal?: boolean;

  /**
   * Lifetime in milliseconds applied to values of this class that are
   * constructed without `ttl` or `expiresAt`.
   */
  defaultTtl?: number;

  /**
   * Longest lifetime, in milliseconds from construction, any value of this
   * class may have.
   *
   * It caps the deadline at construction, caps every renewal, and gives a
   * deadline to a value that would otherwise have none, so no value of the
   * class outlives it.
   */
  maxTtl?: number;

  /**
   * Reject construction of a value of this class that has no deadline.
   *
   * `defaultTtl` or `maxTtl` satisfy the requirement, so it only rejects a
   * class that sets neither and a caller who passes neither.
   */
  requireExpiration?: boolean;

  /**
   * Hook to validate whether reveal is allowed in the given context.
   * Throw an error to deny the reveal, and return nothing to allow it.
   *
   * ⚠️ The hook must be synchronous. The gate reads the value in the same call,
   * so an `async` hook cannot deny anything: it throws into a Promise after the
   * raw value has already been returned, which is the hook failing open on
   * exactly the reads it was written to refuse. The return type is `undefined`
   * rather than `void` so that an `async` function is rejected at compile time,
   * and the gate refuses at runtime any hook that returns a value at all, a
   * Promise included, since a hook that returns `false` meant to deny.
   *
   * `value` is the instance being read, so a policy can decide on the label or
   * the deadline rather than on the class alone, and `access` says what is
   * being authorized. Both were added after the context-only form, so a hook
   * that declares fewer parameters keeps working unchanged.
   *
   * ⚠️ The hook runs inside the raw-value gate, which is not reentrant. Reading
   * `value` from here, through `reveal()`, `equals()` or `mask()`, re-enters the
   * gate and recurses until the stack is exhausted. Read `klass` and `label`,
   * and nothing else.
   *
   * The policy for a class is process-global, so this hook sees every value of
   * that class. A rule that applies to one value belongs to the caller that
   * constructed it, not here.
   */
  checkRevealAllowed?(
    ctx: RevealContext | null,
    value: ISensitiveString,
    access: RevealAccess
  ): undefined;

  /**
   * Determine the resulting class when combining two sensitive values.
   * If not provided, defaultCombineClasses is used.
   */
  combineClasses?(a: SensitivityClass, b: SensitivityClass): SensitivityClass;

  /** Advisory metadata. Mostly not enforced; see `SensitivityAdvisory` for the two that are */
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
  /**
   * ISO 8601 deadline, when the value expires.
   *
   * A token with five minutes left still has five minutes left after crossing a
   * service boundary, so the deadline travels with the value and the receiver
   * enforces it against its own clock. Renewal permission and renewal counts
   * deliberately do not travel: a receiver must not take "you may extend this
   * credential's lifetime" from a payload.
   */
  expiresAt?: string;
  /**
   * Set when the sender is marking the value revoked.
   *
   * `serialize()` never emits it, because a revoked value cannot be read to be
   * serialized at all: the gate refuses. It exists for the other direction, so
   * a payload assembled by hand, or by a gateway that checked its own list, can
   * tell the receiver not to use what it is sending. Like every other field
   * here it may only tighten: there is no way to spell "not revoked" that
   * lifts a revocation the receiving process already holds.
   *
   * Only `true` is accepted. `false` is rejected rather than read as "not
   * revoked", so a payload that means to say nothing says nothing.
   */
  revoked?: true;
  /** Why, for a payload carrying `revoked`. Ignored without it. */
  revocationReason?: string;
  /**
   * Where the receiver may read this value.
   *
   * Restrictions travel, because a value that may only be read in the EU is
   * still a value that may only be read in the EU after it crosses a service
   * boundary, and the receiving process is exactly the one that might be
   * somewhere else. Like every other field here they may only tighten: a
   * deserialized value starts with none, so a payload can add restrictions and
   * has no way to spell the removal of one.
   *
   * A list, because a value derived from two restricted values carries both.
   * An entry with a key this receiver does not know is rejected rather than
   * ignored, since ignoring it would enforce part of a restriction and report
   * nothing about the rest.
   */
  restrictions?: SerializedEnvironmentRestrictions[];
}
