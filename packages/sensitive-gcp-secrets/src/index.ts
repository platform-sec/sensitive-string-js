/**
 * @platform-sec/sensitive-string-gcp-secrets
 *
 * GCP Secret Manager as a `SecretSource`.
 *
 * This is the provider where the rule about resolved versions earns itself.
 * `latest` is an alias the server resolves, two reads of it a second apart can
 * legitimately return different versions, and an audit trail that records
 * `latest` for both cannot tell them apart. `ref.version` here is always the
 * number the API served.
 *
 * It is also the only provider in this row that ships an integrity check with
 * the secret. `payload.dataCrc32c` is verified on the bytes before anything is
 * wrapped, so the check is not a reveal.
 *
 * @example
 * ```ts
 * import { SecretManagerServiceClient } from '@google-cloud/secret-manager';
 * import { GcpSecretSource } from '@platform-sec/sensitive-string-gcp-secrets';
 *
 * const gcp = new GcpSecretSource({
 *   client: new SecretManagerServiceClient(),
 *   project: 'my-project',
 * });
 *
 * const key = await gcp.get('stripe-api-key');
 * key.ref.version;   // '7', never 'latest'
 * ```
 *
 * @packageDocumentation
 */

export { GcpSecretSource } from './source.js';
export type { GcpSecretsClient, GcpSecretSourceOptions } from './source.js';

export {
  gcpLabel,
  gcpResolvedRef,
  gcpSecretMetadata,
  parseResource,
  resourceName,
  timestampToDate,
  verifiedPayload,
} from './wire.js';
export type { AccessResponse, ParsedResource, Secret, Timestamp } from './wire.js';

export { crc32c, toChecksum } from './crc32c.js';
