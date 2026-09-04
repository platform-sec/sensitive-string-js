import type { FieldClass } from '@platform-sec/sensitive-string-env';

/**
 * The one error this package throws, and the rule it obeys.
 *
 * Every built-in envalid validator embeds the raw input in its message. From
 * envalid 8.2.0's own source:
 *
 * ```js
 * throw new EnvError(`Invalid bool input: "${input}"`);
 * throw new EnvError(`Invalid number input: "${input}"`);
 * throw new EnvError(`Not a string: "${input}"`);
 * throw new EnvError(`Invalid email address: "${x}"`);
 * throw new EnvError(`Invalid host (domain or ip): "${input}"`);
 * throw new EnvError(`Invalid port input: "${input}"`);
 * throw new EnvError(`Invalid url: "${x}"`);
 * throw new EnvError(`Invalid json: "${x}"`);
 * ```
 *
 * and the default reporter prints them and exits:
 *
 * ```
 * ================================
 *  Invalid environment variables:
 *     X: Invalid bool input: "LEAKED_SECRET_abc123xyz"
 * ================================
 *
 *  Exiting with error code 1
 * ```
 *
 * There is no hook at which the value has not yet been formatted: a custom
 * reporter receives the already-built message in `errors[name].message`, and
 * the default reporter's logger is `console.error.bind(console)` evaluated at
 * module load, so replacing `console.error` after importing envalid does not
 * intercept it. So the message is replaced rather than scrubbed. Scrubbing
 * looks safer and is not: it depends on the value appearing verbatim, and every
 * validator that truncates, quotes, escapes or JSON-encodes its input defeats
 * it silently.
 *
 * Nothing here sets `cause`. Chaining the original error would put the message
 * back, one `JSON.stringify` away, in every error reporter that walks a cause
 * chain. Read this paragraph before adding one.
 */

/** Whether a variable failed because it was rejected or because it was absent. */
export type EnvFailureKind = 'invalid' | 'missing';

/** One variable that failed validation. */
export interface EnvVariableFailure {
  /** The variable's name. */
  readonly variable: string;
  /** Its class under the validator that rejected it, or `'plain'` for a stock envalid one. */
  readonly klass: FieldClass;
  readonly kind: EnvFailureKind;
  /**
   * Why, in words this package chose.
   *
   * For `'missing'` this is envalid's own `EnvMissingError` message, which
   * `formatSpecDescription` builds from the caller's `desc`, `example` and
   * `docs` and from nothing the environment supplied. It is the one
   * third-party message this package passes through, and it is passed through
   * because dropping it would lose the half of envalid's output that is
   * actually actionable.
   *
   * For `'invalid'` it is a fixed phrase. Never a string derived from a value.
   */
  readonly detail: string;
}

/**
 * Validation failed for one or more variables.
 *
 * Carries every failure from a single run, because reporting one variable at a
 * time is envalid's `reporter: null` behaviour and it is the thing worth
 * keeping about the default reporter: a run that names all four misconfigured
 * variables saves three more deploys.
 */
export class EnvValidationError extends Error {
  override readonly name: string = 'EnvValidationError';

  constructor(readonly failures: readonly EnvVariableFailure[]) {
    super(formatFailures(failures));
  }
}

/** The report, in envalid's two sections and none of its colours. */
function formatFailures(failures: readonly EnvVariableFailure[]): string {
  const invalid = failures.filter((failure) => failure.kind === 'invalid');
  const missing = failures.filter((failure) => failure.kind === 'missing');
  const lines = ['Environment validation failed.'];

  if (invalid.length > 0) {
    lines.push('', 'Invalid environment variables:');
    for (const failure of [...invalid].sort(byVariable)) {
      lines.push(`    ${failure.variable} (${failure.klass}): ${failure.detail}`);
    }
  }

  if (missing.length > 0) {
    lines.push('', 'Missing environment variables:');
    for (const failure of [...missing].sort(byVariable)) {
      lines.push(`    ${failure.variable} (${failure.klass}): ${failure.detail}`);
    }
  }

  return lines.join('\n');
}

function byVariable(a: EnvVariableFailure, b: EnvVariableFailure): number {
  return a.variable < b.variable ? -1 : a.variable > b.variable ? 1 : 0;
}

/**
 * A value was rejected by a check this package ran.
 *
 * Thrown from a sensitive validator's own parse function, and distinguished
 * from an `EnvError` for one reason: this package wrote the message, so it
 * knows the message holds no value and can pass it through to the report
 * instead of replacing it with the uniform phrase.
 */
export class SensitiveFormatError extends Error {
  override readonly name: string = 'SensitiveFormatError';
}
