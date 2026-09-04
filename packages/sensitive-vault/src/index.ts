/**
 * @platform-sec/sensitive-string-vault
 *
 * HashiCorp Vault and OpenBao as a `SecretSource`: every value arrives as a
 * `SensitiveString`, the provider response object never leaves this package,
 * and a lease becomes a deadline bound to the credential rather than metadata
 * nothing enforces.
 *
 * Vault is the reference implementation of the shared layer because it is the
 * only store in the category whose API supplies everything the lifetime and
 * revocation design needs: `lease_duration`, `renewable`, server-side
 * revocation, and response wrapping.
 *
 * @example
 * ```ts
 * import { VaultSecretSource } from '@platform-sec/sensitive-string-vault';
 *
 * const vault = new VaultSecretSource({
 *   endpoint: 'https://vault.internal:8200',
 *   token: vaultToken,                       // SensitiveString<'credential'>
 *   namespace: 'engineering',
 *   mounts: [{ path: 'kv', kv: 2 }],
 *   onLoad: (event) => audit.info('secret.load', event),
 * });
 *
 * const db = await vault.getJson('kv/prod/db', {
 *   fields: { username: 'sensitive', password: 'credential' },
 * });
 *
 * const lease = await vault.dynamic('database/creds/app-readonly');
 * lease.fields.get('password');   // SensitiveString<credential>, ttl from lease_duration
 * await lease.renew();
 * await lease.revoke();
 * ```
 *
 * @packageDocumentation
 */

export { VaultSecretSource } from './source.js';
export type { VaultSecretSourceOptions, WrappedSecret } from './source.js';

export { VaultLease, leaseTtlMs } from './lease.js';
export type { LeaseContext } from './lease.js';

export { FLAVOR_DIVERGENCE, VaultFlavorError, checkFlavor, tokenHeader } from './flavor.js';
export type { FlavorDivergence, VaultFlavor } from './flavor.js';

export {
  assertLogicalPath,
  kvMetadataPath,
  kvReadPath,
  kvResolvedRef,
  kvWriteBody,
  kvWritePath,
  kvWrittenVersion,
  parseKvResponse,
  splitMount,
} from './kv.js';
export type { KvRead, KvVersion, VaultMount } from './kv.js';

export { VaultRequestError, fetchTransport } from './transport.js';
export type {
  FetchTransportOptions,
  VaultRequest,
  VaultResponse,
  VaultTransport,
} from './transport.js';
