/**
 * @platform-sec/sensitive-string-secrets
 *
 * The shared layer under the secrets manager integrations.
 *
 * A secret enters a Node process from a secrets manager as a plain `string` on
 * a response object and stays a plain string for the rest of its life. Four
 * things go wrong before the value is ever used, and none of them throws: the
 * response object holds the raw secret and reaches an error tracker or a debug
 * log, the parsed fields have no class and no label, a payload that is not JSON
 * puts part of the secret into a `SyntaxError`, and nothing records that a
 * secret was loaded, from where, or at which version.
 *
 * This package is the layer that fixes all four once rather than once per
 * provider. It holds the `SecretSource` interface, the classification policy,
 * the decode guard, the label rule, the instance cache, the file watcher, and
 * the write guard. A provider package supplies the client and the one API call.
 *
 * You do not normally install this directly. Install the package for your
 * store, which depends on this one.
 *
 * @example
 * ```ts
 * import { VaultSecretSource } from '@platform-sec/sensitive-string-vault';
 *
 * const vault = new VaultSecretSource({ endpoint, token, onLoad: (e) => audit.info(e) });
 *
 * const db = await vault.getJson('kv/prod/db', {
 *   fields: { username: 'sensitive', password: 'credential', port: 'plain' },
 * });
 *
 * db.fields.password; // SensitiveString<credential:kv/prod/db#password>
 * ```
 *
 * @packageDocumentation
 */

export type {
  BulkLoadEvent,
  CacheOptions,
  FieldMap,
  FieldSets,
  GetAllOptions,
  GetJsonOptions,
  GetOptions,
  JsonFields,
  JsonSecretRecord,
  MultiSecretRecord,
  ProviderPayload,
  ProviderResult,
  ResolvedSecretRef,
  SecretLifetime,
  SecretLoadEvent,
  SecretMetadata,
  SecretRecord,
  SecretRef,
  SecretSource,
  SecretSourceOptions,
  SingleLoadEvent,
} from './types.js';

export {
  ReferenceRefusedError,
  SecretError,
  SecretNotFoundError,
  SecretPayloadError,
  SecretWriteRefusedError,
} from './errors.js';
export type { ReferenceRefusal, WriteRefusal } from './errors.js';

export { BaseSecretSource, normalizeRef } from './source.js';

export { DECLARED_FALLBACK, allSpec, jsonSpec } from './classify.js';

export { asObject, decodeBase64, decodeBase64Map, guardDecode, parsePayload } from './decode.js';

export { materialize, lifetimeOptions } from './materialize.js';
export type { Materialized, MaterializeOptions, PlainFieldValue } from './materialize.js';

export { SecretCache, cacheKey, refPrefix } from './cache.js';

export {
  DISCLOSING_LABEL_PATTERNS,
  describeLabelDisclosure,
  fieldLabel,
  logicalLabel,
} from './label.js';

export { watchFile } from './watch.js';
export type { FileWatcher, WatchOptions } from './watch.js';

// The reference pattern: mint a pointer to a value a read returned, and resolve
// one against an allowlist. The wire format itself lives in core, which is
// where the walks that meet a payload on the way to a log line are.
export { createReferenceResolver, fieldReference, toReference } from './reference.js';
export type {
  Referenceable,
  ReferenceAllowEntry,
  ReferenceResolver,
  ReferenceResolverOptions,
  ResolveOptions,
  ToReferenceOptions,
} from './reference.js';
