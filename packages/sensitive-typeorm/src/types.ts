import type {
  ClassificationSpec,
  FieldClass,
  SensitivityClass,
} from '@platform-sec/sensitive-string-core';

/**
 * TypeORM's `ValueTransformer`, restated structurally.
 *
 * Declared here rather than imported so the built output carries no import of
 * `typeorm` at all. The interface is two methods and has not changed since the
 * 0.3 line, so restating it costs nothing and keeps the package correct in a
 * process that has loaded two copies of the ORM.
 */
export interface ValueTransformerLike {
  /** Applied on the way to the database. */
  to(value: unknown): unknown;
  /** Applied on the way back from it. */
  from(value: unknown): unknown;
}

/** A transformer this package made, recognisable to `schema.check()`. */
export const SENSITIVE_TRANSFORMER = Symbol.for(
  'platform-sec.sensitive-string.typeorm.transformer'
);

/**
 * What a transformer of this package's knows about itself.
 *
 * `schema.check()` reads it to answer both halves of the drift question: which
 * columns carry one of ours, and whether the one a column carries was built for
 * that column. The second half matters because `schema.column('users.email')`
 * pasted onto `api_key` produces a transformer that works, audits under the
 * wrong path, and is wrong in no other visible way.
 */
export interface TransformerBrand {
  readonly klass: SensitivityClass;
  readonly label: string | undefined;
  /** `table.column`, or just the column when the caller named no table. */
  readonly path: string;
  readonly table: string | undefined;
  readonly column: string | undefined;
}

/** A `ValueTransformer` built by `sensitiveColumn()` or `schema.column()`. */
export interface SensitiveTransformer extends ValueTransformerLike {
  readonly [SENSITIVE_TRANSFORMER]: TransformerBrand;
}

/** What was passed to `to()` when the transformer refused or warned. */
export interface PlainWriteInfo {
  /** `table.column` the transformer is bound to. */
  readonly path: string;
  readonly klass: SensitivityClass;
  /** `typeof` the value. Never the value. */
  readonly received: string;
}

/** How one classified column behaves. */
export interface SensitiveColumnOptions {
  /** Database table, used in audit tags and in every message. */
  readonly table?: string;
  /** Database column, used in audit tags and in every message. */
  readonly column?: string;
  /** Audit label for values read back. Defaults to the column name. */
  readonly label?: string;
  /**
   * Refuse a plain string on the write path instead of passing it through.
   *
   * Off by default, and that is measured rather than preferred:
   * `find({ where: { email: 'a@example.com' } })` with a literal hands `to()` a
   * plain string, and it is a legitimate query. What the default does instead
   * is report it once per path when development mode is on.
   *
   * A service whose property types are all `SensitiveString` and whose queries
   * all pass instances can turn this on and have the ORM enforce it.
   */
  readonly strictWrites?: boolean;
  /**
   * Require an ambient reveal context on the write path.
   *
   * Off by default. A row write happens on every request, so refusing one for
   * want of a context turns a security library into an availability incident.
   * A service that has already wired `withRevealContext()` at its request
   * boundary can turn it on and find the paths that escaped.
   */
  readonly strictContext?: boolean;
  /** Context name used when no ambient context supplies one. */
  readonly name?: string;
  /** Context reason used when no ambient context supplies one. */
  readonly reason?: string;
  /**
   * Called the first time a path is handed a plain string, when
   * `strictWrites` is off.
   *
   * Defaults to one `console.warn` per path, emitted only when core's
   * development mode is on. Production pays one property read for it.
   */
  readonly onPlainWrite?: (info: PlainWriteInfo) => void;
}

/**
 * Which database column carries which class.
 *
 * Core's `ClassificationSpec`, with the key fixed as `table.column` and the
 * fallback required. This is deliberately the same shape the other data-layer
 * integrations use, so the specification survives being handed to a shared
 * layer later without being rewritten.
 *
 * The bare column name is offered as an alias at every precedence level, so a
 * rule written as `/password/` matches `users.password_hash` without the author
 * anticipating the table it sits in.
 */
export interface DataSchemaSpec extends ClassificationSpec {
  /** Exact `table.column` matches. Highest precedence. */
  readonly fields?: Readonly<Record<string, FieldClass>>;
  /**
   * Everything `fields` and `rules` did not match.
   *
   * Required, and normally `'plain'`. A wrongly wrapped column is an object
   * where a string was, so `row.status === 'active'` becomes permanently false
   * and the application misbehaves in a way that reads as a bug rather than as
   * a security control.
   */
  readonly fallback: FieldClass;
}

/** Options for `schema.check()`. */
export interface CheckOptions {
  /**
   * Proceed with the query result cache enabled.
   *
   * Deliberately awkward to type. It means the deployment accepts that every
   * cached query writes the plaintext of the classified columns it selected,
   * and the plaintext of the values it filtered on, into a second table.
   */
  readonly allowCachedPlaintext?: boolean;
  /**
   * Accept exact `fields` entries that no column on this `DataSource` matches.
   *
   * Off by default, because an unmatched entry is normally a renamed table or a
   * mistyped column and it turns the guarantee off in the quietest way
   * available: the entry classifies nothing, the column stores plaintext, and
   * every read returns a plain string where the property type promises an
   * instance.
   *
   * Turn it on for a specification deliberately shared across `DataSource`s,
   * which is the one case where an entry with no column here is correct.
   */
  readonly allowUnmatchedFields?: boolean;
}

/** Options for `hydrateRaw()`. */
export interface HydrateRawOptions {
  /**
   * Entity alias TypeORM prefixed the raw keys with.
   *
   * `getRawMany()` on an entity selection returns `User_email` rather than
   * `email`. Pass `'User'` and the prefix is stripped before the key is
   * classified. Nothing is stripped by default: guessing at a separator would
   * classify `api_key` by its `key` suffix.
   */
  readonly aliasPrefix?: string;
}
