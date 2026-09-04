import type {
  ClassificationRule,
  FieldClass,
  SensitiveString,
  SensitivityClass,
} from '@platform-sec/sensitive-string-core';

/**
 * What the caller asks for.
 *
 * `path` is provider-neutral and becomes the label, so it is the logical path
 * within the store and never the account-scoped identifier the provider prefers.
 */
export interface SecretRef {
  path: string;
  /** Provider version identifier. Omitted means the provider's notion of current. */
  version?: string;
}

/** Non-secret provider metadata: staging labels, content type, creation time. */
export type SecretMetadata = Readonly<Record<string, string | number | boolean | undefined>>;

/** What the provider resolved the request to. Contains no secret material. */
export interface ResolvedSecretRef extends SecretRef {
  /**
   * The concrete version the provider served, never the alias that was
   * requested. A provider that does not report one says so in its README and
   * uses `'unknown'`.
   */
  version: string;
  readonly metadata: SecretMetadata;
}

/**
 * A deadline or lease a provider attached to a secret, in the terms core uses.
 *
 * A rotation schedule is not a deadline and never arrives here: the current
 * version of a secret keeps working after its next rotation date, often
 * indefinitely, so deriving a deadline from one produces values that throw
 * while still being the correct live credential.
 */
export interface SecretLifetime {
  /** Lifetime in milliseconds from now. Mutually exclusive with `expiresAt`. */
  readonly ttl?: number;
  /** Absolute deadline. Mutually exclusive with `ttl`. */
  readonly expiresAt?: Date;
  /** Whether the value may be renewed. Credentials are not renewable by default. */
  readonly allowRenewal?: boolean;
  /** Total renewals allowed. Unlimited when unset. */
  readonly maxRenewals?: number;
}

export interface SecretRecord<C extends SensitivityClass = 'credential'> {
  readonly value: SensitiveString<C>;
  readonly ref: ResolvedSecretRef;
}

export interface GetOptions<C extends SensitivityClass = 'credential'> {
  /**
   * Defaults to `'credential'`, the more restrictive of the two classes.
   *
   * Passing `'sensitive'` is a construction-time choice rather than a
   * downgrade, so R5 is not engaged: there is no parent instance here. It is
   * still the one option that can only loosen, which is why it is explicit at
   * every call site and why the multi-value reads take a class per field.
   */
  klass?: C;
  /** Overrides the label derived from `ref.path`. Subject to the label rule either way. */
  label?: string;
  /** Lifetime for providers that supply none. Ignored where the provider supplies one. */
  ttl?: number;
}

/** A declared set of fields and the class each one gets. */
export type FieldMap = Readonly<Record<string, FieldClass>>;

/**
 * The typed half of a `getJson` result: a declared field arrives wrapped unless
 * it was declared `'plain'`.
 */
export type JsonFields<F extends FieldMap> = {
  readonly [K in keyof F]: F[K] extends 'plain'
    ? string
    : SensitiveString<Extract<F[K], SensitivityClass>>;
};

/** The two maps a discovered key set produces. Never one map of a union type. */
export interface FieldSets {
  readonly fields: ReadonlyMap<string, SensitiveString<SensitivityClass>>;
  readonly plain: ReadonlyMap<string, string>;
}

export interface GetJsonOptions<F extends FieldMap> {
  /** The fields this code knows about. Highest precedence in classification. */
  readonly fields: F;
  /** Tried in order for keys `fields` did not name. Patterns run on key names. */
  readonly rules?: readonly ClassificationRule[];
  /**
   * Everything unmatched. Defaults to `'credential'`: the caller named a
   * secret and declared its fields, a payload that grows a field is the common
   * case, and the failure that matters is a new secret arriving unwrapped.
   */
  readonly fallback?: FieldClass;
  /** Overrides the label prefix derived from `ref.path`. */
  readonly label?: string;
  /** Lifetime for providers that supply none. */
  readonly ttl?: number;
}

export interface GetAllOptions {
  readonly fields?: FieldMap;
  readonly rules?: readonly ClassificationRule[];
  /**
   * Required, with no default.
   *
   * Fail-closed is the wrong default for half of the stores that need
   * `getAll`, and it fails in a way that does not look like a security
   * control: a config store holds secrets next to ordinary configuration, and
   * wrapping `LOG_LEVEL` as a credential makes `config.LOG_LEVEL === 'debug'`
   * permanently false and `if (config.FEATURE_X)` permanently true, because an
   * instance is an object and objects are truthy. Fail-open is wrong for a
   * Kubernetes Secret or a Vault KV path, where everything is secret by
   * construction. Only the caller knows which kind of store this is.
   */
  readonly fallback: FieldClass;
  readonly label?: string;
  readonly ttl?: number;
}

export interface JsonSecretRecord<F extends FieldMap> {
  readonly ref: ResolvedSecretRef;
  /** The declared fields, typed by their declared class. */
  readonly fields: JsonFields<F>;
  /** Keys the payload carried that `fields` did not declare. */
  readonly extra: FieldSets;
  /** Every key the payload carried, declared or not. Key names are not secret. */
  readonly keys: readonly string[];
}

export interface MultiSecretRecord extends FieldSets {
  readonly ref: ResolvedSecretRef;
  readonly keys: readonly string[];
}

interface BaseLoadEvent {
  /** The provider package's own name: `'vault'`, `'aws-secrets'`, `'k8s'`. */
  readonly source: string;
  readonly ref: ResolvedSecretRef;
  readonly cached: boolean;
  readonly durationMs: number;
  /** ISO 8601, or undefined where nothing bounded the value's lifetime. */
  readonly expiresAt: string | undefined;
}

export interface SingleLoadEvent extends BaseLoadEvent {
  readonly kind: 'single';
  readonly klass: SensitivityClass;
  readonly label: string | undefined;
}

export interface BulkLoadEvent extends BaseLoadEvent {
  readonly kind: 'bulk';
  /** Key names. Not secret, and an audit record of "loaded 47 secrets" without them is useless. */
  readonly keys: readonly string[];
  readonly counts: Readonly<Record<FieldClass, number>>;
}

/**
 * One event per load.
 *
 * Deliberately not `auditReveal`. Loading a secret creates a `SensitiveString`
 * and does not call `reveal()`, so routing loads through the reveal hook would
 * have been less code and would make the audit trail lie: a sink counting
 * reveals to decide whether a credential is over-used would count every process
 * restart. A load and a reveal are different events and get different hooks.
 */
export type SecretLoadEvent = SingleLoadEvent | BulkLoadEvent;

export interface CacheOptions {
  /** Longest an entry may be served, in milliseconds. `0` disables the cache. */
  readonly ttl?: number;
  /**
   * Serve a value whose cache entry has expired but whose own TTL has not,
   * when the provider is unreachable.
   *
   * Off by default. Defaulting it on would make a provider outage invisible.
   * When it fires, the load event says `cached: true`.
   */
  readonly staleOnError?: boolean;
}

export interface SecretSourceOptions {
  /**
   * Called once per load.
   *
   * Errors thrown by it propagate rather than being swallowed, because a load
   * hook that fails silently is an audit gap. That is the opposite of core's
   * `onExpire`, which is a lifecycle callback rather than an audit one.
   */
  readonly onLoad?: (event: SecretLoadEvent) => void;
  readonly cache?: CacheOptions;
}

export interface SecretSource {
  get<C extends SensitivityClass = 'credential'>(
    ref: SecretRef | string,
    options?: GetOptions<C>
  ): Promise<SecretRecord<C>>;

  /** Returns null where the provider reports the secret or version as absent. */
  getOptional<C extends SensitivityClass = 'credential'>(
    ref: SecretRef | string,
    options?: GetOptions<C>
  ): Promise<SecretRecord<C> | null>;

  /** One fetch, a declared set of fields, a typed result. */
  getJson<F extends FieldMap>(
    ref: SecretRef | string,
    options: GetJsonOptions<F>
  ): Promise<JsonSecretRecord<F>>;

  /** One fetch, a discovered set of keys, a pair of maps. */
  getAll(ref: SecretRef | string, options: GetAllOptions): Promise<MultiSecretRecord>;

  /**
   * Drop any cached entry for the ref, so the next read reaches the provider.
   *
   * Instances handed out before a refresh keep working, because nothing can
   * reach them. After a rotation, in-flight requests holding the old credential
   * continue with the old credential until the far side stops accepting it.
   * Invalidating outstanding instances needs the revocation registry and is not
   * approximated here.
   */
  refresh(ref: SecretRef | string): void;
}

/**
 * What a provider hands back from one round trip.
 *
 * A payload is a string the shared decoder parses, or a map the provider
 * decoded itself. Both exist because the wire shapes differ: AWS returns a
 * string, a Vault KV read and a Kubernetes Secret are already maps.
 */
export type ProviderPayload =
  | { readonly kind: 'string'; readonly value: string }
  | { readonly kind: 'map'; readonly value: Readonly<Record<string, unknown>> };

/**
 * One provider round trip.
 *
 * The provider's own response object is not on it, is not attached to a thrown
 * error, and is not passed to a hook. That is the one invariant here that
 * cannot be added later without a breaking change, which is why there is no
 * `raw` escape hatch.
 */
export interface ProviderResult {
  readonly payload: ProviderPayload;
  readonly ref: ResolvedSecretRef;
  readonly lifetime?: SecretLifetime;
}
