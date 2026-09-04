/**
 * @platform-sec/sensitive-string-azure-keyvault
 *
 * Azure Key Vault as a `SecretSource`.
 *
 * Key Vault is the one source in this row that carries a real deadline an
 * operator set, so it is the one where a wrapped value can enforce something
 * the raw string never could: `properties.expiresOn` becomes the instance's
 * `expiresAt`, and a secret past it refuses to reveal.
 *
 * @example
 * ```ts
 * import { SecretClient } from '@azure/keyvault-secrets';
 * import { DefaultAzureCredential } from '@azure/identity';
 * import { AzureSecretSource } from '@platform-sec/sensitive-string-azure-keyvault';
 *
 * const azure = new AzureSecretSource({
 *   client: new SecretClient(vaultUrl, new DefaultAzureCredential()),
 * });
 *
 * const apiKey = await azure.get('payments-api-key');
 * apiKey.value.ttlRemaining();   // from properties.expiresOn
 * apiKey.ref.version;            // the concrete version, never an alias
 * ```
 *
 * @packageDocumentation
 */

export { AzureSecretSource } from './source.js';
export type { AzureSecretsClient, AzureSecretSourceOptions } from './source.js';

export {
  SecretNotYetValidError,
  assertActive,
  azureLifetime,
  azureMetadata,
  azureResolvedRef,
  parseSecretIdentifier,
} from './wire.js';
