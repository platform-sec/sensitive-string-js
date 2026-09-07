import {
  assertKeyedDerivationOptions,
  DEFAULT_DERIVED_TOKEN_LENGTH,
  deriveKeyedToken,
  type KeyedDerivationOptions,
} from './derive.js';
import { SensitiveStringError } from './errors.js';
import { getPolicy } from './policy.js';
import type { SensitivityClass, SensitivityPolicy } from './types.js';

/**
 * Deterministic redaction: a redacted rendering that tells two values apart.
 *
 * Ordinary redaction answers every value with the same string, which is what
 * makes it safe and what makes a log unreadable. Three lines saying
 * `[REDACTED:sensitive]` may be one subject or three, and the difference is
 * usually the whole question being asked. This replaces the constant with
 * `[REDACTED:sensitive:a1b2c3d4e5f6]`, a stable tag derived from the value, so
 * the lines that share a subject look like they do.
 *
 * ⚠️ This changes the contract. Redacted output has until now carried no
 * information about the value at all, and under this policy it carries a keyed
 * fingerprint of it. Anyone who holds the key and a guess can confirm the
 * guess against a log line; anyone who holds neither still learns which lines
 * concern the same subject, which is itself disclosure and is the point.
 * Adopting it is a decision with a threat model behind it rather than a
 * formatting preference.
 *
 * The tag is an HMAC and there is no unkeyed mode, for the reason
 * {@link deriveKeyedToken} spells out: the values that get redacted are
 * low-entropy by definition, an email address under a plain SHA-256 is a
 * wordlist lookup, and a redacted log is exactly where an offline attack
 * happens. The factory therefore refuses without a key rather than defaulting
 * to a bare digest.
 *
 * Two things about the tag are worth settling before adopting it, and neither
 * is in the design sketch's threat model.
 *
 * The policy is process-global, so one registration tags every rendering the
 * process produces, including the ones bound for somewhere else. The error
 * tracking and APM integrations scrub through `redactCopy`, so an instance in a
 * Sentry event, a Bugsnag report, a Rollbar item or a Datadog span carries the
 * tag. What a vendor flattened into a plain object before the scrub ran does
 * not: `sensitive-rollbar`'s flattened path has no value left to derive from
 * and writes the constant. Correlating a subject across a log aggregator and a
 * third-party error tracker is usually the point, and it is worth deciding
 * rather than discovering.
 *
 * And the key is not the only way to confirm a guess. Anyone who can get a
 * value of their own choosing redacted into output they can read has an oracle:
 * they submit a guess, read its tag, and compare it with a tag from the log. A
 * request body echoed into a log line is the ordinary shape of that, and
 * `redactSerialized` is the sharpest one, because it takes both the class and
 * the value off an untrusted payload. HMAC-SHA256 is a PRF, so the oracle does
 * not recover the key, and it does reduce "an attacker who holds the key" to
 * "an attacker who can reach the service".
 *
 * Two things about where this runs are worth knowing before adopting it.
 * Redaction is not a reveal: it happens under `#readRawValue('safe')`, so it
 * produces no audit record, charges no reveal budget, and is not refused by an
 * expired deadline or a revocation, all of which are deliberate, because a log
 * line must keep redacting after a value dies. And it runs on every
 * `toString()`, so a log-heavy path pays one HMAC per rendering; there is no
 * cache, because a value-keyed cache is a table of plaintexts with the
 * lifetime of the process.
 */

/** The default tag prefix, which keeps the rendering greppable as `[REDACTED:...]`. */
const DEFAULT_PREFIX = 'REDACTED';

/**
 * What a prefix may contain.
 *
 * Wide enough for the `REDACTED:sensitive` form {@link deterministicRedaction}
 * builds, and narrow enough that the rendering stays one parseable token: no
 * whitespace, no brackets, nothing that would make `[prefix:tag]` ambiguous to
 * the log search that has to find it.
 */
const PREFIX_PATTERN = /^[A-Za-z0-9_.:-]{1,64}$/;

/**
 * The string the factory renders once to check the caller's `format`.
 *
 * Not a secret and not a canary: it exists so a `format` that throws or answers
 * with something other than a string fails at configuration time rather than
 * in the middle of the first log line that needed redacting.
 */
const FORMAT_PROBE = 'deterministic-redactor-format-probe';

/** How to derive and render a correlation tag. */
export interface DeterministicRedactorOptions {
  /**
   * HMAC key. Required, and there is no way to configure a redactor without
   * one.
   *
   * At least `MIN_DERIVATION_KEY_BYTES` bytes. Prefer a `Uint8Array` from
   * a secrets manager or `randomBytes`; a string key is read as UTF-8 and sits
   * in the heap as an ordinary string.
   *
   * Rotating it renders every tag minted before the rotation uncorrelatable
   * with every tag minted after, which is a feature when correlation should
   * expire and a surprise when an investigation spans the rotation.
   */
  readonly key: KeyedDerivationOptions['key'];

  /**
   * Domain components mixed in ahead of the value, so the same value under two
   * scopes gets two tags.
   *
   * This is the control for how far correlation reaches. With no scope, a tag
   * is stable for the life of the key, across every process and every restart,
   * and whoever holds two years of logs can count how often a subject appears
   * in them. A per-session or per-tenant scope narrows that to the session or
   * the tenant. A string is one component; an array is several, joined so they
   * cannot be reassociated.
   *
   * It is not a salt in the password sense and does not need to be secret. It
   * separates token spaces, and the key is what makes a tag unguessable.
   */
  readonly scope?: string | readonly string[];

  /**
   * Hex characters retained from the digest. Defaults to
   * `DEFAULT_DERIVED_TOKEN_LENGTH`, which is also the floor.
   *
   * The floor is a correctness guard: two values sharing a tag merge two
   * subjects into one in the log, which reads as a fact rather than as a
   * collision. See `MIN_DERIVED_TOKEN_LENGTH` for the arithmetic, and
   * raise this before a workload grows past it.
   */
  readonly length?: number;

  /** Tag prefix. Defaults to `'REDACTED'`. Must match `[A-Za-z0-9_.:-]{1,64}`. */
  readonly prefix?: string;

  /**
   * Renderer for the prefix and the tag. Defaults to `` `[${prefix}:${tag}]` ``.
   *
   * It receives the prefix and the derived tag and never the raw value, which
   * is what makes a caller-supplied renderer safe to accept here: there is no
   * argument it could leak. It is called once at construction with a probe, so
   * one that throws or answers with a non-string is refused before it can take
   * down a log line.
   */
  readonly format?: (prefix: string, tag: string) => string;
}

/**
 * Raised when a sensitivity class may not be given a correlation tag.
 *
 * Only `credential` is refused, and only by {@link deterministicRedaction}.
 * {@link createDeterministicRedactor} knows no class and refuses nothing.
 */
export class DeterministicRedactionNotAllowedError extends SensitiveStringError {
  override readonly name = 'DeterministicRedactionNotAllowedError';
  override readonly code = 'deterministic-redaction-refused';

  constructor(readonly klass: SensitivityClass) {
    super(
      `deterministicRedaction: a '${klass}' value does not get a correlation tag. A credential is ` +
        'guessable by construction, so a stable tag turns every log line into an oracle for ' +
        'confirming a guess against, for anyone who later obtains the key. Tag the sensitive ' +
        'value the credential belongs to instead. A deployment that has weighed this and still ' +
        'wants it assembles the policy itself around createDeterministicRedactor(), which is one ' +
        'line that shows up in review.'
    );
  }
}

/**
 * Build a redaction function that derives a stable tag from the value.
 *
 * The primitive, for a caller assembling a {@link SensitivityPolicy} by hand.
 * {@link deterministicRedaction} is the one-liner over it and is what most
 * callers want, because it keeps the rest of the class's policy intact.
 *
 * Everything that can be wrong with the options is settled at construction
 * rather than at the first redaction: a key below the entropy floor, a length
 * below the collision floor, a domain component carrying a NUL, a malformed
 * prefix, a `format` that does not answer with a string. A redaction runs on
 * the path a log line takes, and a configuration error discovered there is
 * discovered by a log line failing.
 *
 * The options are read once and the scope is copied, so mutating either
 * afterwards moves nothing. A redactor that answered differently on Tuesday
 * because a caller pushed onto the array they passed would break the one
 * property the feature exists for.
 *
 * @param options - The key, the scope, the tag length, and the rendering
 * @returns A function suitable as a policy's `redact`
 *
 * @throws TypeError For a missing or mistyped key, a malformed prefix, a
 *         domain component that is not a string or contains a NUL, or a
 *         `format` that does not return a string.
 * @throws RangeError If the key is shorter than `MIN_DERIVATION_KEY_BYTES`
 *         or `length` is outside the documented bounds.
 *
 * @example
 * ```ts
 * registerPolicy(
 *   { ...getPolicy('sensitive'), redact: createDeterministicRedactor({ key }) },
 *   { overwrite: true }
 * );
 * ```
 */
export function createDeterministicRedactor(
  options: DeterministicRedactorOptions
): (value: string) => string {
  return buildRedactor('createDeterministicRedactor', options).redact;
}

/** A redactor and the pattern that recognizes what it renders. */
interface BuiltRedactor {
  readonly redact: (value: string) => string;
  /** Absent when a caller's `format` does not embed the tag verbatim. */
  readonly markerPattern: RegExp | undefined;
}

/**
 * The shared body of both factories.
 *
 * `operation` is the name of the function the caller actually called, so a
 * malformed prefix passed to `deterministicRedaction` is not reported against
 * a function that appears nowhere in the caller's code. It is the same reason
 * `planHash` takes one. The refusals that come from `derive.ts` keep naming
 * `deriveKeyedToken`, which is exported and documented, and `entityHandle`
 * reports them the same way.
 */
function buildRedactor(
  operation: 'createDeterministicRedactor' | 'deterministicRedaction',
  options: DeterministicRedactorOptions
): BuiltRedactor {
  if (options === null || typeof options !== 'object') {
    throw new TypeError(`${operation}: options must carry at least a key`);
  }

  const prefix = requirePrefix(operation, options.prefix);
  const format = options.format ?? defaultFormat;

  if (typeof format !== 'function') {
    throw new TypeError(`${operation}: format must be a function`);
  }

  const derivation: KeyedDerivationOptions = {
    key: copyKey(options.key),
    domain: requireScope(operation, options.scope),
    ...(options.length === undefined ? {} : { length: options.length }),
  };

  assertKeyedDerivationOptions(derivation);

  const redact = (value: string): string => format(prefix, deriveKeyedToken(value, derivation));

  refuseNonString(operation, redact(FORMAT_PROBE));

  return {
    redact,
    markerPattern: deriveMarkerPattern(
      format,
      prefix,
      derivation.length ?? DEFAULT_DERIVED_TOKEN_LENGTH
    ),
  };
}

/**
 * A policy for `klass` whose redaction carries a correlation tag.
 *
 * The currently registered policy for the class with its `redact` replaced, so
 * `requireConstantTimeEquals`, `allowMask`, `checkRevealAllowed`, the advisory
 * flags and every deadline rule survive. Registering a hand-written policy
 * instead is how a class quietly loses one of those.
 *
 * The class is mixed into the derivation alongside the caller's scope, so the
 * same string classified two ways gets two tags. That matches how
 * `entityHandle` derives, and it means a `serialize()` payload caught by a
 * redaction walk renders the same tag as the instance it came from, since both
 * are redacted through the same class's policy.
 *
 * `credential` is refused. See {@link DeterministicRedactionNotAllowedError};
 * the refusal is hard-coded rather than read from an advisory flag, because
 * every existing flag answers a different question and overloading one would
 * make it mean two things.
 *
 * @param klass - The class whose redaction is being replaced
 * @param options - The key, the scope, the tag length, and the rendering
 * @returns A policy to hand to `registerPolicy(..., { overwrite: true })`
 *
 * @throws DeterministicRedactionNotAllowedError If `klass` is `credential`.
 * @throws Error If no policy is registered for `klass`.
 * @throws TypeError, RangeError As {@link createDeterministicRedactor}.
 *
 * @example
 * ```ts
 * registerPolicy(
 *   deterministicRedaction('sensitive', { key: process.env.REDACTION_HMAC_KEY! }),
 *   { overwrite: true }
 * );
 *
 * String(new SensitiveString('alice@example.com', 'sensitive'));
 * // '[REDACTED:sensitive:5f2a91c0b74e]'
 * ```
 */
export function deterministicRedaction(
  klass: SensitivityClass,
  options: DeterministicRedactorOptions
): SensitivityPolicy {
  if (klass === 'credential') {
    throw new DeterministicRedactionNotAllowedError(klass);
  }

  // Read before anything is validated, so a class with no policy is reported as
  // the missing registration it is rather than as a key problem.
  const base = getPolicy(klass);

  if (options === null || typeof options !== 'object') {
    throw new TypeError('deterministicRedaction: options must carry at least a key');
  }

  const { redact, markerPattern } = buildRedactor('deterministicRedaction', {
    ...options,
    prefix: options.prefix ?? `${DEFAULT_PREFIX}:${klass}`,
    // Scope first, then the class, so a caller cannot collide the two by naming
    // a scope after a class.
    scope: [...requireScope('deterministicRedaction', options.scope), klass],
  });

  return {
    ...base,
    name: klass,
    redact,
    // Declared so the guards that refuse to send a redaction onward can still
    // recognize one. Two probes of different lengths is how they learn a
    // constant policy's marker, and a value-dependent policy defeats that test
    // by construction. Dropped rather than guessed when a caller's `format`
    // does not embed the tag verbatim.
    ...(markerPattern === undefined ? {} : { markerPattern }),
  };
}

function defaultFormat(prefix: string, tag: string): string {
  return `[${prefix}:${tag}]`;
}

function requirePrefix(operation: string, prefix: string | undefined): string {
  if (prefix === undefined) {
    return DEFAULT_PREFIX;
  }

  if (typeof prefix !== 'string' || !PREFIX_PATTERN.test(prefix)) {
    throw new TypeError(
      `${operation}: prefix must match [A-Za-z0-9_.:-]{1,64}, so the rendering stays one token ` +
        'a log search can find'
    );
  }

  return prefix;
}

/**
 * The scope as domain components, copied.
 *
 * A bare string is one component rather than a character sequence, so
 * `scope: 'tenant-7'` and `scope: ['tenant-7']` are the same domain. Component
 * contents are checked by {@link assertKeyedDerivationOptions}, which owns the
 * NUL rule.
 *
 * The copy is the point, and it is the same rule `expiresAt` follows: the
 * redactor reads the components on every rendering, so keeping the caller's
 * array by reference would let a `push()` after construction move every tag
 * that followed it, and would let a component past the validation that ran here
 * once. A non-string pushed in later does not produce a wrong tag, it makes
 * `redact()` throw, which happens on the path a log line takes.
 */
function requireScope(
  operation: string,
  scope: DeterministicRedactorOptions['scope']
): readonly string[] {
  if (scope === undefined) {
    return [];
  }

  if (typeof scope === 'string') {
    return [scope];
  }

  // Checked through an `unknown` binding rather than on `scope` itself:
  // `Array.isArray` narrows to `any[]`, which would launder the element type
  // straight past the checker on the way out.
  const components: unknown = scope;

  if (!Array.isArray(components)) {
    throw new TypeError(`${operation}: scope must be a string or an array of strings`);
  }

  return [...scope];
}

/**
 * Refuse a rendering that is not a string.
 *
 * Typed `unknown` on purpose: `format` declares a string return and a JavaScript
 * caller is under no obligation to honour it, and a number reaching `toString()`
 * would be a redaction that fails the type it promised somewhere far from here.
 */
/**
 * The key as bytes this redactor owns.
 *
 * The same rule the scope follows, and it matters more here: the key is read on
 * every rendering, so keeping the caller's array by reference would let a
 * zeroize after construction move every tag afterwards, silently and with no
 * error, since a zeroed key is still a valid key. Copying also encodes a string
 * key once instead of once per rendering.
 *
 * Anything that is neither bytes nor a string is passed through untouched, so
 * `assertKeyedDerivationOptions` raises its own message for it rather than this
 * function inventing a second one.
 */
function copyKey(key: DeterministicRedactorOptions['key']): KeyedDerivationOptions['key'] {
  if (typeof key === 'string') {
    return new TextEncoder().encode(key);
  }

  return key instanceof Uint8Array ? new Uint8Array(key) : key;
}

/**
 * A pattern that recognizes what this redactor renders.
 *
 * Derived by rendering two probe tags and finding where they differ, rather
 * than assembled from the prefix, so it holds for a caller's `format` as well
 * as for the default one. A format that does not embed the tag verbatim, such
 * as one that upper-cases it, reconstructs to something else and yields no
 * pattern at all, which is the honest answer: a wrong pattern is worse than
 * none, because it reads as coverage.
 */
function deriveMarkerPattern(
  format: (prefix: string, tag: string) => string,
  prefix: string,
  length: number
): RegExp | undefined {
  const first = 'a'.repeat(length);
  const second = 'b'.repeat(length);
  const rendered = format(prefix, first);
  const other = format(prefix, second);

  if (typeof rendered !== 'string' || typeof other !== 'string') {
    return undefined;
  }

  // Every occurrence, because a prefix may itself be a run of the probe
  // character and the first match would then be the wrong one.
  for (let at = rendered.indexOf(first); at >= 0; at = rendered.indexOf(first, at + 1)) {
    const head = rendered.slice(0, at);
    const tail = rendered.slice(at + length);

    if (other === head + second + tail) {
      return new RegExp(`${escapeRegExp(head)}[0-9a-f]{${length}}${escapeRegExp(tail)}`);
    }
  }

  return undefined;
}

/** Every character with a meaning inside a pattern, taken literally. */
function escapeRegExp(literal: string): string {
  return literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function refuseNonString(operation: string, rendered: unknown): void {
  if (typeof rendered !== 'string') {
    throw new TypeError(
      `${operation}: format must return a string, received ` +
        (rendered === null ? 'null' : typeof rendered)
    );
  }
}
