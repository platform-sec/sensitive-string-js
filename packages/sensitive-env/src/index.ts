/**
 * @platform-sec/sensitive-string-env
 *
 * The shared loader under the config and environment integrations.
 *
 * Almost every Node service starts the same way:
 *
 * ```ts
 * const password = process.env.DB_PASSWORD!;
 * await pool.connect({ host: process.env.DB_HOST, user: process.env.DB_USER, password });
 * ```
 *
 * Three things are already true before the first line of application logic
 * runs, and none of them throws. The value is a plain string in a
 * process-global object every dependency can read, which
 * `JSON.stringify(process.env)` returns and every child process inherits.
 * Nothing distinguishes `DB_PASSWORD` from `LOG_LEVEL`: no class, no label, and
 * no record that a credential was read. And the layer people put in front of
 * `process.env` to fix the second problem is a validator, which is the
 * component that prints the value when it rejects it.
 *
 * This package is the one loader that produces a classified record, rather than
 * four library-shaped ones. dotenv, convict and node-config need no package of
 * their own: dotenv holds nothing to wrap, and convict and node-config both
 * clone their trees on read, so for those three the integration is `wrapFlat`
 * or `wrapTree` plus a few lines at the call site. envalid is the one library
 * with an extension point that both survives and needs typed wiring, and it has
 * its own package.
 *
 * @example
 * ```ts
 * import { commonSecretNameRules, loadEnv } from '@platform-sec/sensitive-string-env';
 *
 * const record = loadEnv({
 *   fields: { DB_PASSWORD: 'credential', SUPPORT_EMAIL: 'sensitive' },
 *   rules: commonSecretNameRules,
 *   fallback: 'plain',
 * });
 *
 * record.fields.get('DB_PASSWORD'); // SensitiveString<credential:DB_PASSWORD>
 * record.plain.get('PORT');         // '3000'
 * ```
 *
 * What it cannot do, stated here rather than only in the README: it removes the
 * copy JavaScript can see, and it cannot remove the copy the kernel made at
 * exec time. `EnvRecord.kernelCopy` is how a deployment finds out which
 * variables are in that position.
 *
 * @packageDocumentation
 */

export type {
  ChildEnvRefusal,
  DroppedLine,
  EnvExplanation,
  EnvLoadEvent,
  EnvRecord,
  EnvSpec,
  FieldClass,
  LoadEnvOptions,
} from './types.js';

export { ChildEnvRefusedError, EnvValueError } from './types.js';

export { commonSecretNameRules, compileEnvSpec, envLabel } from './classify.js';

export { explainEnv, loadEnv } from './load.js';

export { wrapFlat, wrapTree } from './wrap.js';
export type { FlatWrapResult, WrapTreeOptions } from './wrap.js';

export { parseEnvContent, readEnvFile } from './parse.js';
export type { ParsedEnvFile } from './parse.js';

export { kernelCopyNames, removeFromProcessEnv } from './remove.js';

export { carriesRedactionMarker, toChildEnv } from './child.js';

export { assertSensitiveFlags } from './convict.js';

// Guarded reads, exported because the `envalid` adapter walks an object that
// throws for any name it was not given and should not carry a third copy of
// four lines that `core` and this package already have.
export { probeKeys, probeProperty } from './probe.js';
