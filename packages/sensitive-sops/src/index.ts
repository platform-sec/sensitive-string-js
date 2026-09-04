/**
 * @platform-sec/sensitive-string-sops
 *
 * SOPS documents as a `SecretSource`.
 *
 * SOPS encrypts the values of a YAML, JSON, ENV or INI document and leaves the
 * keys in the clear, so it already recorded which values are secret. This
 * package derives the classification from that rather than asking the caller to
 * restate it, because a hand-written spec drifts from the file and the drift is
 * silent exactly where it matters: a newly encrypted field the spec does not
 * mention.
 *
 * It shells out to the `sops` binary and does not implement SOPS. The decrypt
 * is done by the tool the file was produced with.
 *
 * @example
 * ```ts
 * import { parse } from 'yaml';
 * import { SopsSecretSource } from '@platform-sec/sensitive-string-sops';
 *
 * const sops = new SopsSecretSource({ ageKey: ageIdentity, yamlParse: parse });
 *
 * const secrets = await sops.getDerived('/etc/app/secrets.enc.yaml');
 * secrets.fields.get('database.password');   // SOPS encrypted it
 * secrets.plain.get('database.host');        // SOPS did not
 * ```
 *
 * @packageDocumentation
 */

export { SopsSecretSource } from './source.js';
export type { SopsSecretSourceOptions } from './source.js';

export {
  ENC_MARKER,
  SOPS_BLOCK,
  deriveSpec,
  encryptedPaths,
  formatFor,
  parseCiphertext,
} from './derive.js';
export type { DeriveOptions, SopsFormat, YamlParser } from './derive.js';

export { SopsError, childEnv, decryptArgs, decryptContext, run } from './spawn.js';
export type { RunOptions, SpawnResult } from './spawn.js';
