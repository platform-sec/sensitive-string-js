/**
 * @platform-sec/sensitive-string-oci-vault
 *
 * OCI Vault as a `SecretSource`, through the secret retrieval data plane.
 *
 * The first thing an implementer gets wrong here is the client. `oci-vault`'s
 * `VaultsClient` manages secrets, their metadata, and their versions, and does
 * not return secret contents. `oci-secrets`' `SecretsClient.getSecretBundle` is
 * the read path, and it is what this package takes. The package is named for
 * the product and depends on the data plane.
 *
 * @example
 * ```ts
 * import * as secrets from 'oci-secrets';
 * import { OciSecretSource } from '@platform-sec/sensitive-string-oci-vault';
 *
 * const oci = new OciSecretSource({
 *   client: new secrets.SecretsClient({ authenticationDetailsProvider }),
 *   vaultId: 'ocid1.vault.oc1.iad.abc...',
 * });
 *
 * const key = await oci.get('prod-stripe-key');
 * key.ref.version;   // the concrete versionNumber
 * ```
 *
 * @packageDocumentation
 */

export { OciSecretSource } from './source.js';
export type { OciSecretsClient, OciSecretSourceOptions } from './source.js';

export {
  STAGES,
  isOcid,
  isStage,
  ociLifetime,
  ociPayload,
  ociResolvedRef,
  versionFields,
} from './wire.js';
export type { SecretBundle, Stage } from './wire.js';
