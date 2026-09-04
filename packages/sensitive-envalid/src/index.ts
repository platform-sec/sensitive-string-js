/**
 * @platform-sec/sensitive-string-envalid
 *
 * envalid, with validators that produce a `SensitiveString` and a report that
 * never prints a value.
 *
 * envalid is the one library in the config and environment row with an
 * extension point that both survives and needs typed wiring. Its output is
 * otherwise well behaved: a validator that returns an instance yields an
 * instance through `cleanEnv`, the returned object is frozen and the instance
 * still reveals through it, `util.inspect` renders
 * `{ API_KEY: SensitiveString<credential:API_KEY> { [REDACTED:credential] } }`,
 * and `JSON.stringify` produces `{"API_KEY":"[REDACTED:credential]"}`.
 *
 * Four measured problems make it a package rather than a recipe: two options
 * that quietly do the wrong thing (`default` and its siblings bypass the
 * validator; `choices` compares against the wrapped value), an error path that
 * prints values and cannot be intercepted from outside, and a return value that
 * is a strict proxy.
 *
 * @example
 * ```ts
 * import { port } from 'envalid';
 * import { cleanEnvSafe, credential, sensitive } from '@platform-sec/sensitive-string-envalid';
 *
 * const env = cleanEnvSafe(process.env, {
 *   DB_PASSWORD: credential({ label: 'db_password' }),
 *   SUPPORT_EMAIL: sensitive(),
 *   PORT: port(),
 * });
 *
 * env.DB_PASSWORD; // SensitiveString<'credential'>
 * env.PORT;        // number
 * ```
 *
 * **Import `cleanEnv` from envalid directly and you get the leaking reporter
 * back.** That is why the validators below are re-exported from here: one
 * import site, and a lint rule can ban the other one. `cleanEnv` and
 * `customCleanEnv` are deliberately not re-exported, under any name.
 *
 * @packageDocumentation
 */

export { cleanEnvSafe } from './clean-env.js';
export type { CleanEnvSafeOptions } from './clean-env.js';

export { credential, makeSensitiveValidator, sensitive, sensitiveMeta } from './validators.js';
export type {
  SensitiveFormat,
  SensitiveMeta,
  SensitiveSpec,
  SensitiveValidator,
} from './validators.js';

export { EnvValidationError, SensitiveFormatError } from './errors.js';
export type { EnvFailureKind, EnvVariableFailure } from './errors.js';

export { toEnvRecord } from './record.js';

/**
 * envalid's own validators and makers, re-exported so one import covers a
 * schema.
 *
 * Everything here is safe to use: a validator only parses, and the makers only
 * build one. What is not re-exported is anything that reports: `cleanEnv` and
 * `customCleanEnv` run the default reporter, which prints the raw input and
 * calls `process.exit(1)`.
 */
export {
  bool,
  email,
  host,
  json,
  makeExactValidator,
  makeValidator,
  num,
  port,
  str,
  url,
} from 'envalid';
