import type {
  ClassificationRule,
  FieldClass,
  SensitiveString,
  SensitivityClass,
} from '@platform-sec/sensitive-string-core';

/**
 * How one variable is classified, and where the classification comes from.
 *
 * `'plain'` is a decision rather than an absence of one. `process.env` is the
 * most mixed store this library meets: `PATH`, `HOME`, `NODE_ENV`, `TZ` and
 * several dozen names the runtime and the container platform put there sit
 * next to the two or three that are secret. Wrapping one of those does not
 * fail loudly, it fails as an application bug, because an instance is an
 * object and therefore always truthy, a wrapped `PORT` is never `=== '3000'`,
 * and anything handed on to a library that expects a string arrives as
 * `[REDACTED:...]`.
 */
export type { FieldClass };

/**
 * Which variables become which class.
 *
 * Precedence is `fields`, then `rules` in order, then `fallback`. Patterns run
 * on variable names and never on values: deciding by value would mean reading
 * every value to work out whether to protect it.
 */
export interface EnvSpec {
  /** Exact variable names. Highest precedence. */
  readonly fields?: Readonly<Record<string, FieldClass>>;
  /** Tried in order for names `fields` did not match. Patterns run on names, never on values. */
  readonly rules?: readonly ClassificationRule[];
  /**
   * Everything unmatched. Required, and there is no default.
   *
   * For the environment the answer is nearly always `'plain'`. Failing closed
   * over a store that holds `PATH` and `LOG_LEVEL` is not conservative, it is
   * broken.
   */
  readonly fallback: FieldClass;
  /** Label for a wrapped variable. Defaults to the variable's own name. */
  readonly label?: (name: string) => string;
}

/** A `.env` line the parser dropped, reported by position and never by content. */
export interface DroppedLine {
  /** The file the line came from. */
  readonly file: string;
  /** 1-based line number. */
  readonly line: number;
  /** Why the line produced no variable. Never derived from the line's text. */
  readonly reason: 'not-an-assignment' | 'unparsed-assignment';
}

/**
 * What a load reports, once per call.
 *
 * Names, classes, counts and line numbers. Never a value, and never a line's
 * content: this event is the one thing about a load that is designed to be
 * logged, so it has to be safe to log in full.
 */
export interface EnvLoadEvent {
  /** Every name the load saw, wrapped or not. */
  readonly names: readonly string[];
  /** The class each name received. */
  readonly classes: ReadonlyMap<string, FieldClass>;
  /** How many names landed in each class. */
  readonly counts: Readonly<Record<FieldClass, number>>;
  /** Files that were read, in the order they were read. */
  readonly files: readonly string[];
  /** Lines a file's parser produced nothing for. */
  readonly droppedLines: readonly DroppedLine[];
  /**
   * How many names the `.env` parser produced that no assignment line
   * declared.
   *
   * A count, never a list. `util.parseEnv` parses a quoted value containing
   * `=` a second time, so `A="x=y"` yields both `A` and a key named `"x`: the
   * extra key's *name* is a slice of the *value*, and listing it would
   * disclose part of a secret through the report that exists to prevent
   * exactly that. A non-zero count means a `.env` line needs looking at.
   */
  readonly unexpectedNames: number;
  /** Names deleted from `process.env`. */
  readonly removed: readonly string[];
  /** Names still in the kernel's copy, or `'unknown'` when the platform cannot say. */
  readonly kernelCopy: readonly string[] | 'unknown';
}

export interface LoadEnvOptions {
  /** Where to read. Defaults to `process.env`. */
  readonly source?: Readonly<Record<string, string | undefined>>;
  /**
   * Files to parse first, earlier entries losing to later ones and all of them
   * losing to `source`.
   *
   * A file that does not exist is skipped, matching every loader in this row.
   * A file that exists and cannot be read throws.
   */
  readonly files?: readonly string[];
  /**
   * Delete each wrapped name from `process.env` after wrapping. Off by default.
   *
   * This removes the copy JavaScript can see. It does not remove the copy the
   * kernel made at exec time; see `EnvRecord.kernelCopy`.
   */
  readonly removeFromProcessEnv?: boolean;
  /**
   * Compare against `/proc/self/environ` to find names deletion cannot reach.
   * Linux only, off by default.
   *
   * The check reads the whole environment into a `Buffer`, which is a copy this
   * package created, so it is opt-in.
   */
  readonly checkKernelCopy?: boolean;
  /** Called once per load with names and classes. Never with values. */
  readonly onLoad?: (event: EnvLoadEvent) => void;
}

/**
 * The result of a load.
 *
 * Two maps rather than one map of a union, so a caller iterating `fields`
 * cannot find a raw string in it. A single `Map<string, SensitiveString |
 * string>` would move that check to every call site, including the ones that
 * log the map.
 *
 * Plain `Map`s and arrays, deliberately. This is not a Proxy and it has no
 * getter that throws for an unknown name, because such an object breaks
 * anything that probes it, `util.inspect` and a logger's own walk included.
 */
export interface EnvRecord {
  /** Wrapped variables, by name. */
  readonly fields: ReadonlyMap<string, SensitiveString<SensitivityClass>>;
  /** Everything classified `plain`, by name. */
  readonly plain: ReadonlyMap<string, string>;
  /** Every name the load saw, wrapped or not. */
  readonly names: readonly string[];
  /** Names deleted from `process.env`. */
  readonly removed: readonly string[];
  /**
   * Names still present in the kernel's copy of the environment, or
   * `'unknown'` when the platform cannot answer.
   *
   * A non-empty array means those variables were exported before this process
   * was executed, so `/proc/<pid>/environ` holds them for the life of the
   * process no matter what was deleted from `process.env`. Load them from a
   * file or a secrets manager instead if that matters.
   *
   * Never an empty array on a platform with no `/proc`: reporting one there
   * would be a false all-clear.
   */
  readonly kernelCopy: readonly string[] | 'unknown';
}

/** What `explainEnv` reports: the classification, with nothing wrapped and no value read. */
export interface EnvExplanation {
  /** Every name the source would have offered. */
  readonly names: readonly string[];
  /** The class each name would receive. */
  readonly classes: ReadonlyMap<string, FieldClass>;
  /** How many names would land in each class. */
  readonly counts: Readonly<Record<FieldClass, number>>;
  /** Lines a file's parser produced nothing for. */
  readonly droppedLines: readonly DroppedLine[];
  /** How many names the `.env` parser invented. See `EnvLoadEvent`. */
  readonly unexpectedNames: number;
}

/**
 * A configuration value failed a check.
 *
 * **Nothing in this package throws this.** It is exported for your own checks
 * over a loaded record, and for an adapter built on this one, because the shape
 * is the thing worth sharing: every validator in this row puts its input in its
 * own error, so the reflex to write `Invalid PORT: "${value}"` is the reflex
 * this class exists to replace.
 *
 * @example
 * ```ts
 * const port = record.plain.get('PORT') ?? '';
 *
 * if (!/^\d+$/.test(port)) {
 *   throw new EnvValueError('PORT', 'plain', 'not an integer');
 * }
 * ```
 *
 * The message names the variable and its class and never the value. `detail` is
 * a fixed phrase you choose, never a string derived from the value.
 *
 * There is no `cause`. Chaining the original would satisfy the usual advice
 * about preserving errors and would undo the fix, because every error reporter
 * serializes the cause chain. Read that paragraph before adding one.
 *
 * The variable is on `variable` rather than on `name`, because `name` on an
 * `Error` is the error's own type name and an error whose `name` is
 * `'DB_PASSWORD'` breaks every `catch` that switches on it.
 */
export class EnvValueError extends Error {
  override readonly name: string = 'EnvValueError';

  constructor(
    /** The variable that failed. */
    readonly variable: string,
    /** Its class under the spec in force. */
    readonly klass: FieldClass,
    detail: string
  ) {
    super(`Environment variable '${variable}' (${klass}) failed validation: ${detail}`);
  }
}

/** Why a child environment was refused before any of it was returned. */
export type ChildEnvRefusal =
  /** A value about to cross the boundary contains a redaction marker. */
  | 'marker'
  /** A requested name is in neither map of the record. */
  | 'unknown-name'
  /** No `RevealContext` was supplied, and this path must not use an ambient one. */
  | 'no-context';

/**
 * A child environment was refused.
 *
 * `marker` is the refusal this class exists for. Anything assigned into an
 * environment object is coerced with `String()`, so a `SensitiveString` that
 * reaches `spawn`'s `env` arrives at the child as the literal text
 * `[REDACTED:credential]`. The child then authenticates with that string, and
 * the first symptom is an authentication failure in a process that is not the
 * one holding the bug.
 */
export class ChildEnvRefusedError extends Error {
  override readonly name: string = 'ChildEnvRefusedError';

  constructor(
    readonly reason: ChildEnvRefusal,
    message: string,
    /** The variable that caused the refusal, where one name is responsible. */
    readonly variable?: string
  ) {
    super(message);
  }
}
