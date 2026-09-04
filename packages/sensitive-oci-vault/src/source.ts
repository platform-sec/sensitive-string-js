import { BaseSecretSource, logicalLabel } from '@platform-sec/sensitive-string-secrets';
import type {
  ProviderResult,
  SecretRef,
  SecretSourceOptions,
} from '@platform-sec/sensitive-string-secrets';

import { isOcid, ociLifetime, ociPayload, ociResolvedRef, versionFields } from './wire.js';
import type { SecretBundle } from './wire.js';

/**
 * The two methods this package calls on the injected client.
 *
 * A real `SecretsClient` from `oci-secrets` satisfies it. Declaring it
 * structurally keeps the SDK a types-only dependency and keeps `oci-common`,
 * which the SDK's request types extend, out of this package's build.
 */
export interface OciSecretsClient {
  getSecretBundleByName(request: {
    secretName: string;
    vaultId: string;
    versionNumber?: number;
    secretVersionName?: string;
    stage?: string;
  }): Promise<{ secretBundle: SecretBundle }>;

  getSecretBundle(request: {
    secretId: string;
    versionNumber?: number;
    secretVersionName?: string;
    stage?: string;
  }): Promise<{ secretBundle: SecretBundle }>;
}

export interface OciSecretSourceOptions extends SecretSourceOptions {
  /** Injected, so the authentication provider stays with the application. */
  readonly client: OciSecretsClient;
  /**
   * The vault OCID a secret name is resolved against.
   *
   * Required for reads by name, which is the ergonomic path and the one
   * `SecretRef.path` maps to. A read by secret OCID needs no vault.
   */
  readonly vaultId?: string | undefined;
}

/**
 * OCI reports an absent secret as a 404.
 *
 * Read off the error's `statusCode` rather than through `instanceof`, for the
 * reason every provider in this row gives: two copies of a vendor package make
 * an `instanceof` against its error class miss. A 401 or 403 keeps throwing.
 */
function isAbsence(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    (error as { statusCode?: unknown }).statusCode === 404
  );
}

/**
 * OCI Vault, through the secret retrieval data plane.
 *
 * @example
 * ```ts
 * const oci = new OciSecretSource({
 *   client: new secrets.SecretsClient({ authenticationDetailsProvider }),
 *   vaultId: 'ocid1.vault.oc1.iad.abc...',
 * });
 *
 * const key = await oci.get('prod-stripe-key');
 * key.ref.version;   // the concrete versionNumber, never 'CURRENT'
 * ```
 */
export class OciSecretSource extends BaseSecretSource {
  protected readonly sourceName = 'oci-vault';

  readonly #client: OciSecretsClient;
  readonly #vaultId: string | undefined;

  constructor(options: OciSecretSourceOptions) {
    super(options);

    if (
      options.client === undefined ||
      typeof options.client.getSecretBundleByName !== 'function'
    ) {
      throw new TypeError(
        'OciSecretSource needs a client with a getSecretBundleByName() method. That is ' +
          "oci-secrets' SecretsClient, the data plane. oci-vault's VaultsClient manages " +
          'secrets and does not return their contents.'
      );
    }

    this.#client = options.client;
    this.#vaultId = options.vaultId;
  }

  /**
   * The secret name.
   *
   * A secret OCID encodes the tenancy, the region and the realm, so it cannot
   * be a label under the rule this row works to. There is nothing in an OCID
   * that identifies the secret without also identifying the tenancy, so a read
   * by OCID has no label to derive and this refuses rather than inventing one.
   * Pass a name, or pass `label` explicitly.
   */
  protected override deriveLabel(ref: SecretRef): string {
    if (!isOcid(ref.path)) {
      return logicalLabel(ref.path);
    }

    throw new TypeError(
      'A secret OCID encodes the tenancy, the region and the realm, so it cannot become a ' +
        'label: a label appears in every log line the value reaches. Read by name, or pass ' +
        '{ label } explicitly.'
    );
  }

  protected async fetchSecret(ref: SecretRef): Promise<ProviderResult | null> {
    const byOcid = isOcid(ref.path);

    if (!byOcid && (this.#vaultId === undefined || this.#vaultId === '')) {
      throw new TypeError(
        `OciSecretSource needs a vaultId to resolve the secret name '${ref.path}'. Pass ` +
          '{ vaultId } to the constructor, or read by secret OCID.'
      );
    }

    let bundle: SecretBundle;

    try {
      const response = byOcid
        ? await this.#client.getSecretBundle({
            secretId: ref.path,
            ...versionFields(ref.version),
          })
        : await this.#client.getSecretBundleByName({
            secretName: ref.path,
            vaultId: this.#vaultId ?? '',
            ...versionFields(ref.version),
          });

      bundle = response.secretBundle;
    } catch (error) {
      if (isAbsence(error)) {
        return null;
      }

      throw error;
    }

    // A read by OCID has no name to use, and the OCID cannot be one. The
    // resolved path is the secret's version identity in that case, which
    // discloses nothing on its own.
    const resolved = ociResolvedRef(bundle, byOcid ? 'oci-secret' : ref.path);
    const lifetime = ociLifetime(bundle);

    // The bundle stops here.
    return {
      payload: { kind: 'string', value: ociPayload(bundle, resolved) },
      ref: resolved,
      ...(lifetime === undefined ? {} : { lifetime }),
    };
  }
}
