import { timingSafeEqual } from 'node:crypto';
import type {
  SensitivityClass,
  SensitivityPolicy,
  SensitiveStringOptions,
  SerializedSensitiveString,
  MaskOptions,
  RevealContext,
  RevealDetails,
} from './types.js';
import { getPolicy, defaultCombineClasses, hasPolicy } from './policy.js';
import { getCurrentRevealContext } from './context.js';
import { applyMask, maskAuditDetails, planMask } from './mask.js';

/**
 * Node.js custom inspect symbol for util.inspect() and console.log().
 */
const NODE_INSPECT_SYMBOL = Symbol.for('nodejs.util.inspect.custom');

const REGEXP_SOURCE_GETTER = Object.getOwnPropertyDescriptor(RegExp.prototype, 'source')?.get as (
  this: RegExp
) => string;
const REGEXP_FLAGS_GETTER = Object.getOwnPropertyDescriptor(RegExp.prototype, 'flags')?.get as (
  this: RegExp
) => string;

/**
 * Copy a caller-provided regular expression into a plain RegExp.
 *
 * RegExp subclasses and instances with overridden `exec` or symbol methods must
 * not receive a sensitive value. Taking a snapshot also prevents these methods
 * from mutating the caller's `lastIndex`.
 */
function snapshotRegExp(pattern: RegExp, operation: string): RegExp {
  try {
    // Calling the intrinsic getters verifies the RegExp internal slots, works
    // across realms, and bypasses an instance's overridden `source`/`flags`.
    const source = REGEXP_SOURCE_GETTER.call(pattern);
    const flags = REGEXP_FLAGS_GETTER.call(pattern);
    return new RegExp(source, flags);
  } catch {
    throw new TypeError(`SensitiveString.${operation} requires a regular expression`);
  }
}

/**
 * The audit record every operation but `mask()` reports. Shared and frozen: it
 * is handed to caller-supplied audit hooks.
 */
const REVEAL_AUDIT_DETAILS: RevealDetails = Object.freeze({ operation: 'reveal' as const });

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
 * Package-internal derivation of a value from one or more existing values.
 *
 * An operation that builds on protected values must retain the state of every
 * value it read, so a constraint such as a reveal counter is never dropped by
 * deriving from it. That logic lives in the private `SensitiveString.#derived`,
 * which is only reachable from inside the class body, so the class publishes it
 * here for the sibling modules that build derived values.
 *
 * This binding is deliberately absent from `index.ts`, and the package `exports`
 * map declares no deep entry, so it is not part of the published API.
 *
 * @internal
 */
export type DeriveSensitiveString = <D extends SensitivityClass>(
  value: string,
  klass: D,
  label: string | undefined,
  sources: readonly SensitiveString<SensitivityClass>[]
) => SensitiveString<D>;

/**
 * Assigned once, from the static block at the end of the class body.
 *
 * @internal
 */
export let deriveSensitiveString: DeriveSensitiveString;

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
  #readRawValue(
    access: RawValueAccess,
    ctx?: RevealContext,
    details: RevealDetails = REVEAL_AUDIT_DETAILS
  ): string {
    if (access === 'safe') {
      return this.#value;
    }

    const effectiveCtx = ctx ?? getCurrentRevealContext();
    this.policy.checkRevealAllowed?.(effectiveCtx);

    if (access === 'expose') {
      effectiveCtx?.auditReveal?.(this, details);
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

  static {
    // The private access is deferred to call time on purpose. A CommonJS emit
    // rewrites the class name inside the class body to a temporary that is only
    // assigned once the class definition completes, so reading `#derived` here
    // would fail the brand check.
    deriveSensitiveString = (value, klass, label, sources) =>
      SensitiveString.#derived(value, klass, label, sources);
  }

  /**
   * Apply an audited transformation and retain this instance's shared state.
   */
  #transform(transform: (value: string) => string, ctx?: RevealContext): SensitiveString<C> {
    const value = this.#readRawValue('expose', ctx);
    return SensitiveString.#derived(transform(value), this.klass, this.label, [this]);
  }

  /**
   * Read the raw value for a partial query after enforcing the class policy.
   */
  #readPartialQueryValue(ctx?: RevealContext): string {
    const policy = this.policy;
    const allowPartialQueries = policy.allowPartialQueries ?? this.klass === 'sensitive';

    if (!allowPartialQueries) {
      throw new Error(`Partial queries are not allowed for sensitivity class '${this.klass}'`);
    }

    return this.#readRawValue('expose', ctx);
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
   * Returns a partially masked rendering of the value, for display.
   *
   * This is a partial reveal: it runs the same authorization and audit hooks as
   * `reveal()`, and the audit record says `operation: 'mask'` so a log can tell
   * the two apart. The result is a plain string and is not protected; it is
   * meant for a support screen, a confirmation prompt, or a log line, not for
   * further processing.
   *
   * The rendering must hide at least `minMasked` characters, which defaults to
   * 4 for `sensitive` and 8 for `credential` and may only be raised. Positional
   * masking clamps what it shows to satisfy the floor; a strategy that cannot
   * reach it, including one applied to a value of the wrong shape, falls back
   * to the class's full redaction. Counts are code points, and the length of
   * the value is disclosed by construction.
   *
   * @param options - Positional bounds or a format strategy. Defaults to hiding everything.
   * @param ctx - Optional reveal context for authorization and auditing.
   * @throws Error If the class policy sets `allowMask: false`, as `credential` does by default.
   * @throws TypeError If an option has the wrong type or names an unknown strategy.
   * @throws RangeError If a count is not a whole number, or `minMasked` is below the class floor.
   *
   * @example
   * ```ts
   * const key = new SensitiveString('sk_live_abc123xyz9', 'sensitive', 'api_key');
   * key.mask({ showFirst: 2, showLast: 4 }); // 'sk************xyz9'
   *
   * const email = new SensitiveString('jane@example.com', 'sensitive', 'email');
   * email.mask({ strategy: 'email' }); // 'j***@e******.com'
   * ```
   */
  mask(options: MaskOptions = {}, ctx?: RevealContext): string {
    const policy = this.policy;

    if (!(policy.allowMask ?? this.klass === 'sensitive')) {
      const label = this.label !== undefined ? ` (${this.label})` : '';
      throw new Error(`Masking is not allowed for sensitivity class '${this.klass}'${label}`);
    }

    // Options are validated before the value is read, so a rejected call leaves
    // no audit record for a mask that was never rendered.
    const plan = planMask(options, this.klass);
    const value = this.#readRawValue('expose', ctx, maskAuditDetails(plan));

    return applyMask(value, plan, (raw) => policy.redact(raw));
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
    return this.#transform((value) => value.substring(start, end), ctx);
  }

  /**
   * Remove whitespace from both ends, preserving sensitivity and label.
   *
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  trim(ctx?: RevealContext): SensitiveString<C> {
    return this.#transform((value) => value.trim(), ctx);
  }

  /**
   * Remove leading whitespace, preserving sensitivity and label.
   *
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  trimStart(ctx?: RevealContext): SensitiveString<C> {
    return this.#transform((value) => value.trimStart(), ctx);
  }

  /**
   * Remove trailing whitespace, preserving sensitivity and label.
   *
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  trimEnd(ctx?: RevealContext): SensitiveString<C> {
    return this.#transform((value) => value.trimEnd(), ctx);
  }

  /**
   * Convert the value to lowercase, preserving sensitivity and label.
   *
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  toLowerCase(ctx?: RevealContext): SensitiveString<C> {
    return this.#transform((value) => value.toLowerCase(), ctx);
  }

  /**
   * Convert the value to uppercase, preserving sensitivity and label.
   *
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  toUpperCase(ctx?: RevealContext): SensitiveString<C> {
    return this.#transform((value) => value.toUpperCase(), ctx);
  }

  /**
   * Pad the start of the value to a target length.
   *
   * @param targetLength - Desired result length.
   * @param padString - String used for padding.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  padStart(targetLength: number, padString?: string, ctx?: RevealContext): SensitiveString<C> {
    return this.#transform((value) => value.padStart(targetLength, padString), ctx);
  }

  /**
   * Pad the end of the value to a target length.
   *
   * @param targetLength - Desired result length.
   * @param padString - String used for padding.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  padEnd(targetLength: number, padString?: string, ctx?: RevealContext): SensitiveString<C> {
    return this.#transform((value) => value.padEnd(targetLength, padString), ctx);
  }

  /**
   * Extract a section of the value, preserving sensitivity and label.
   *
   * @param start - Zero-based start index. Negative indices count from the end.
   * @param end - Optional exclusive end index.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  slice(start?: number, end?: number, ctx?: RevealContext): SensitiveString<C> {
    return this.#transform((value) => value.slice(start, end), ctx);
  }

  /**
   * Test whether the value begins with a string.
   *
   * Partial queries are disabled for credentials by default because their
   * results can be used as a character-by-character oracle.
   *
   * @param searchString - Prefix to find.
   * @param position - Position at which to begin searching.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  startsWith(searchString: string, position?: number, ctx?: RevealContext): boolean {
    return this.#readPartialQueryValue(ctx).startsWith(searchString, position);
  }

  /**
   * Test whether the value ends with a string.
   *
   * @param searchString - Suffix to find.
   * @param endPosition - End position to use for the search.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  endsWith(searchString: string, endPosition?: number, ctx?: RevealContext): boolean {
    return this.#readPartialQueryValue(ctx).endsWith(searchString, endPosition);
  }

  /**
   * Test whether the value contains a string.
   *
   * @param searchString - String to find.
   * @param position - Position at which to begin searching.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  includes(searchString: string, position?: number, ctx?: RevealContext): boolean {
    return this.#readPartialQueryValue(ctx).includes(searchString, position);
  }

  /**
   * Find the first index of a string in the value.
   *
   * @param searchString - String to find.
   * @param position - Position at which to begin searching.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  indexOf(searchString: string, position?: number, ctx?: RevealContext): number {
    return this.#readPartialQueryValue(ctx).indexOf(searchString, position);
  }

  /**
   * Find the last index of a string in the value.
   *
   * @param searchString - String to find.
   * @param position - Position at which to begin searching backward.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  lastIndexOf(searchString: string, position?: number, ctx?: RevealContext): number {
    return this.#readPartialQueryValue(ctx).lastIndexOf(searchString, position);
  }

  /**
   * Test whether a regular expression matches the value.
   *
   * Regex tests are partial queries and are disabled for credentials by default
   * because caller-controlled patterns can form a powerful content oracle.
   *
   * @param pattern - Regular expression to test.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  test(pattern: RegExp, ctx?: RevealContext): boolean {
    const regex = snapshotRegExp(pattern, 'test');
    return regex.test(this.#readPartialQueryValue(ctx));
  }

  /**
   * Find the index of the first regular-expression match.
   *
   * This is a partial query and is disabled for credentials by default.
   *
   * @param pattern - Regular expression to search for.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  search(pattern: RegExp, ctx?: RevealContext): number {
    const regex = snapshotRegExp(pattern, 'search');
    return this.#readPartialQueryValue(ctx).search(regex);
  }

  /**
   * Return regular-expression matches as protected values.
   *
   * Native match metadata such as `input` is intentionally omitted because it
   * contains the complete raw value. Unmatched optional captures are omitted.
   *
   * @param pattern - Regular expression to match.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  match(pattern: RegExp, ctx?: RevealContext): SensitiveString<C>[] | null {
    const regex = snapshotRegExp(pattern, 'match');
    const matches = this.#readRawValue('expose', ctx).match(regex);

    if (matches === null) {
      return null;
    }

    return matches
      .filter((match): match is string => match !== undefined)
      .map((match) => SensitiveString.#derived(match, this.klass, this.label, [this]));
  }

  /**
   * Return named regular-expression groups as protected values.
   *
   * A successful match without named groups returns an empty, null-prototype
   * object. Named groups that did not participate in the match are omitted.
   *
   * @param pattern - Regular expression containing optional named groups.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  matchGroups(pattern: RegExp, ctx?: RevealContext): Record<string, SensitiveString<C>> | null {
    const regex = snapshotRegExp(pattern, 'matchGroups');
    const match = regex.exec(this.#readRawValue('expose', ctx));

    if (match === null) {
      return null;
    }

    const groups = Object.create(null) as Record<string, SensitiveString<C>>;

    for (const [group, value] of Object.entries(match.groups ?? {})) {
      if (value === undefined) {
        continue;
      }

      const label = this.label !== undefined ? `${this.label}:${group}` : group;
      Object.defineProperty(groups, group, {
        value: SensitiveString.#derived(value, this.klass, label, [this]),
        enumerable: true,
        configurable: true,
        writable: true,
      });
    }

    return groups;
  }

  /**
   * Return every regular-expression match as an iterator of protected arrays.
   *
   * The pattern must have the global (`g`) flag, matching native String.matchAll
   * requirements. Match metadata containing the complete input is omitted.
   *
   * @param pattern - Global regular expression to match.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  matchAll(pattern: RegExp, ctx?: RevealContext): IterableIterator<SensitiveString<C>[]> {
    const regex = snapshotRegExp(pattern, 'matchAll');

    if (!regex.global) {
      throw new TypeError('SensitiveString.matchAll requires a global regular expression');
    }

    const matches = this.#readRawValue('expose', ctx).matchAll(regex);
    const protect = (match: RegExpMatchArray): SensitiveString<C>[] =>
      match
        .filter((part): part is string => part !== undefined)
        .map((part) => SensitiveString.#derived(part, this.klass, this.label, [this]));

    return (function* protectedMatches(): IterableIterator<SensitiveString<C>[]> {
      for (const match of matches) {
        yield protect(match);
      }
    })();
  }

  /**
   * Split the value into protected parts.
   *
   * @param separator - String or regular expression used to divide the value.
   * @param limit - Maximum number of results.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  split(separator: string | RegExp, limit?: number, ctx?: RevealContext): SensitiveString<C>[] {
    const safeSeparator =
      typeof separator === 'string' ? separator : snapshotRegExp(separator, 'split');
    const value = this.#readRawValue('expose', ctx);
    return value
      .split(safeSeparator, limit)
      .map((part) => SensitiveString.#derived(part, this.klass, this.label, [this]));
  }

  /**
   * Replace the first matching string or the matches selected by a regular expression.
   *
   * Replacement callbacks are intentionally unsupported because they receive raw
   * matched content.
   *
   * @param searchValue - String or regular expression to replace.
   * @param replaceValue - String replacement pattern.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  replace(
    searchValue: string | RegExp,
    replaceValue: string,
    ctx?: RevealContext
  ): SensitiveString<C> {
    if (typeof replaceValue !== 'string') {
      throw new TypeError('SensitiveString replacement value must be a string');
    }

    const safeSearchValue =
      typeof searchValue === 'string' ? searchValue : snapshotRegExp(searchValue, 'replace');
    return this.#transform((value) => value.replace(safeSearchValue, replaceValue), ctx);
  }

  /**
   * Replace every matching string or regular-expression match.
   *
   * Replacement callbacks are intentionally unsupported because they receive raw
   * matched content.
   *
   * @param searchValue - String or global regular expression to replace.
   * @param replaceValue - String replacement pattern.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  replaceAll(
    searchValue: string | RegExp,
    replaceValue: string,
    ctx?: RevealContext
  ): SensitiveString<C> {
    if (typeof replaceValue !== 'string') {
      throw new TypeError('SensitiveString replacement value must be a string');
    }

    const safeSearchValue =
      typeof searchValue === 'string' ? searchValue : snapshotRegExp(searchValue, 'replaceAll');

    if (safeSearchValue instanceof RegExp && !safeSearchValue.global) {
      throw new TypeError('SensitiveString.replaceAll requires a global regular expression');
    }

    return this.#transform((value) => value.replaceAll(safeSearchValue, replaceValue), ctx);
  }

  /**
   * Return the character at an index as a protected value.
   *
   * An out-of-range index returns a protected empty string, matching String.charAt().
   *
   * @param index - Zero-based character index.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  charAt(index: number, ctx?: RevealContext): SensitiveString<C> {
    return this.#transform((value) => value.charAt(index), ctx);
  }

  /**
   * Return the character at an index as a protected value.
   *
   * @param index - Character index. Negative indices count from the end.
   * @param ctx - Optional reveal context for authorization and auditing.
   */
  at(index: number, ctx?: RevealContext): SensitiveString<C> | undefined {
    const value = this.#readRawValue('expose', ctx).at(index);
    return value === undefined
      ? undefined
      : SensitiveString.#derived(value, this.klass, this.label, [this]);
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
