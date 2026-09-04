import { compileClassification } from '@platform-sec/sensitive-string-core';
import type {
  ClassificationRule,
  ClassificationSpec,
  CompiledClassification,
  FieldClass,
} from '@platform-sec/sensitive-string-core';

import type { EnvSpec } from './types.js';

/**
 * Name patterns for the variables that are usually secret.
 *
 * **This pack does not run unless you put it in your spec.** A pack that ran by
 * default would classify by guessing, and both directions of a wrong guess are
 * bad. A missed name is a leak the library would report as protected. A false
 * positive wraps an ordinary variable, and a wrapped ordinary variable does not
 * fail loudly: an instance is an object and therefore always truthy, so a
 * wrapped `DEBUG` read as `if (debug)` is permanently true even for an empty
 * string, and a wrapped `PORT` is never `=== '3000'`.
 *
 * Shipping it as a constant instead makes it reviewable, greppable, and one
 * line to adopt:
 *
 * @example
 * ```ts
 * const record = loadEnv({ rules: commonSecretNameRules, fallback: 'plain' });
 * ```
 *
 * Patterns run on variable names and never on values. `DATABASE_URL` is
 * classified whole, because the credential is inside the URL and splitting a
 * URL into wrapped and plain parts would mean parsing a value, and every parser
 * puts its input in its error.
 *
 * Your own patterns are your own responsibility. This package has no runtime
 * dependencies, so it cannot check a caller's `RegExp` for catastrophic
 * backtracking at load time; the patterns below are checked with `safe-regex2`
 * in this package's own test suite.
 *
 * **How the patterns are shaped, and what that costs.** Every rule requires its
 * keyword to end the name, and only some of them require a separator in front
 * of it. Ending the name is what keeps an ordinary variable out: a wrapped
 * `PASSWORD_POLICY` or `TOKEN_URL` would not fail loudly, it would fail as the
 * truthiness bug above. Not requiring a separator in front is what reaches
 * `PGPASSWORD`, which an earlier draft of this pack missed along with
 * `MYSQL_PWD`, `AWS_SECRET_ACCESS_KEY` and `REDIS_AUTH`. Those four are pinned
 * as matches in `classify.test.ts`, next to the names that must stay plain.
 *
 * **It still guesses, and a guess is not a substitute for `fields`.** Two shapes
 * it deliberately does not reach, because nothing in the name distinguishes
 * them from an ordinary variable:
 *
 * | Name | Why it is left plain |
 * |---|---|
 * | `PRIVATE_KEY_PEM` | a suffix after the keyword, and `PRIVATE_KEY_PATH` has the same shape and is a path |
 * | `PUBLIC_KEY` | a key, and not a secret one |
 *
 * Run `explainEnv` against a real environment before trusting the pack to have
 * covered it, and name anything it missed in `fields`.
 */
export const commonSecretNameRules: readonly ClassificationRule[] = Object.freeze([
  // The keyword ends the name, and whatever precedes it may run straight into
  // it: `PGPASSWORD` and `MYSQLPASSWORD` are as common as `DB_PASSWORD`, and an
  // anchor on `^` or `_` reaches none of them. Requiring the keyword to be last
  // is what keeps `PASSWORD_POLICY`, `TOKEN_URL` and `SECRET_NAME` out.
  { pattern: /(PASSWORD|PASSWD|SECRET|TOKEN|CREDENTIALS?)$/, klass: 'credential' },
  // `PWD` needs the separator, and only `PWD`. Without it this rule would wrap
  // `PWD` and `OLDPWD`, which every shell sets and which hold the working
  // directory, and a wrapped `PWD` is the truthiness bug in the one variable
  // most likely to be read as a string.
  { pattern: /_PWD$/, klass: 'credential' },
  // A key is only secret when something says which key. `KEY$` on its own would
  // take `PUBLIC_KEY`, and the qualifier list is what separates
  // `AWS_SECRET_ACCESS_KEY` from it. `KEY` still has to be last, which leaves
  // `PRIVATE_KEY_PATH` and `API_KEY_HEADER` alone.
  {
    pattern: /(^|_)(API|ACCESS|SECRET|PRIVATE|ENCRYPTION|SIGNING|CLIENT|MASTER)_?KEYS?$/,
    klass: 'credential',
  },
  // `REDIS_AUTH` and `BASIC_AUTH` carry the credential itself. The separator
  // keeps a bare `AUTH` flag out, and the end anchor keeps `AUTH_URL` and
  // `AUTH_ENABLED` out.
  { pattern: /_AUTH$/, klass: 'credential' },
  // A connection string holds a credential inside a URL, and the whole variable
  // is classified rather than a component of it: see the note above.
  { pattern: /_DSN$|^DATABASE_URL$|_CONNECTION_STRING$/, klass: 'credential' },
] as const);

/**
 * Compile an `EnvSpec` once for a whole load.
 *
 * @throws Error if `fallback` is missing. The option is typed as required and
 *   checked again here, because the reason it has no default is a runtime
 *   reason: `process.env` is the most mixed store this library meets, holding
 *   `PATH`, `HOME`, `NODE_ENV`, `TZ` and several dozen names the runtime and
 *   the container platform put there next to the two or three that are secret.
 *   Failing closed over that set is not conservative, it is broken, and it
 *   breaks in a way that looks like an application bug rather than a security
 *   control. The caller declares the fallback, and for the environment the
 *   answer is nearly always `'plain'`.
 */
export function compileEnvSpec(spec: EnvSpec): CompiledClassification {
  if (spec === null || typeof spec !== 'object') {
    throw new Error('loadEnv requires an EnvSpec object.');
  }

  if (spec.fallback === undefined) {
    throw new Error(
      'An EnvSpec requires an explicit fallback. Use `plain` for `process.env` and for any ' +
        'store that mixes configuration with secrets, and `credential` only for a source where ' +
        'every name is secret by construction.'
    );
  }

  const classification: ClassificationSpec = {
    ...(spec.fields === undefined ? {} : { fields: spec.fields }),
    ...(spec.rules === undefined ? {} : { rules: spec.rules }),
    fallback: spec.fallback,
  };

  return compileClassification(classification);
}

/**
 * The audit label for one variable.
 *
 * Defaults to the variable's own name. A name is not a value, and a label that
 * did not name the variable would make an audit record useless.
 */
export function envLabel(spec: EnvSpec, name: string): string {
  return spec.label === undefined ? name : spec.label(name);
}

/** An empty tally, so a report always has a number for every class. */
export function emptyCounts(): Record<FieldClass, number> {
  return { credential: 0, sensitive: 0, plain: 0 };
}
