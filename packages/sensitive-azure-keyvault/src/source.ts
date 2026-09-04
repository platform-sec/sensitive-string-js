import { BaseSecretSource } from '@platform-sec/sensitive-string-secrets';
import type {
  ProviderResult,
  SecretRef,
  SecretSourceOptions,
} from '@platform-sec/sensitive-string-secrets';
import type { GetSecretOptions, KeyVaultSecret } from '@azure/keyvault-secrets';

import { assertActive, azureLifetime, azureResolvedRef, parseSecretIdentifier } from './wire.js';

/**
 * The one method this package calls on the injected client.
 *
 * A real `SecretClient` satisfies it. Declaring it structurally rather than
 * importing the class keeps `@azure/keyvault-secrets` a types-only dependency:
 * nothing in this package imports a value from it, so the built output has no
 * vendor import at all and a caller who never constructs this source pays
 * nothing for it being installed.
 */
export interface AzureSecretsClient {
  getSecret(secretName: string, options?: GetSecretOptions): Promise<KeyVaultSecret>;
}

export interface AzureSecretSourceOptions extends SecretSourceOptions {
  /** Injected, so credential construction stays with the application. */
  readonly client: AzureSecretsClient;
  /**
   * Bind `properties.expiresOn` as a deadline. Defaults to true.
   *
   * This is the only place in this row where the library is more restrictive
   * than the provider, so it is opt-out rather than opt-in and the README says
   * so. An operator who set an expiry meant it.
   */
  readonly honorExpiresOn?: boolean | undefined;
  /**
   * Refuse a secret whose `notBefore` has not arrived. Defaults to true.
   *
   * Core has no not-yet-valid state, so the alternative is handing back a value
   * that is not supposed to work yet.
   */
  readonly honorNotBefore?: boolean | undefined;
}

/**
 * Azure reports an absent secret as a 404.
 *
 * Matched structurally rather than through `instanceof RestError`, for the same
 * reason the AWS package matches an exception name: two copies of the SDK in
 * `node_modules` make an `instanceof` against a vendor class miss, and a missed
 * absence check would report an absent secret as a failure. Nothing but a 404
 * is an absence, so a 403 keeps throwing.
 */
function isAbsence(error: unknown): boolean {
  if (typeof error !== 'object' || error === null) {
    return false;
  }

  const shaped = error as { statusCode?: unknown; code?: unknown };

  return shaped.statusCode === 404 || shaped.code === 'SecretNotFound';
}

/**
 * Azure Key Vault.
 *
 * @example
 * ```ts
 * const azure = new AzureSecretSource({
 *   client: new SecretClient(vaultUrl, new DefaultAzureCredential()),
 * });
 *
 * const apiKey = await azure.get('payments-api-key');
 * apiKey.value.expiresAt;   // from properties.expiresOn, when the secret has one
 * ```
 */
export class AzureSecretSource extends BaseSecretSource {
  protected readonly sourceName = 'azure-keyvault';

  readonly #client: AzureSecretsClient;
  readonly #honorExpiresOn: boolean;
  readonly #honorNotBefore: boolean;

  constructor(options: AzureSecretSourceOptions) {
    super(options);

    if (options.client === undefined || typeof options.client.getSecret !== 'function') {
      throw new TypeError(
        'AzureSecretSource needs a client with a getSecret() method, such as a SecretClient.'
      );
    }

    this.#client = options.client;
    this.#honorExpiresOn = options.honorExpiresOn ?? true;
    this.#honorNotBefore = options.honorNotBefore ?? true;
  }

  /**
   * The secret name.
   *
   * A caller may pass the full secret identifier, which is the vault URL with
   * the name and version on it, and the vault URL is the tenant's DNS name.
   */
  protected override deriveLabel(ref: SecretRef): string {
    return parseSecretIdentifier(ref.path).name;
  }

  protected async fetchSecret(ref: SecretRef): Promise<ProviderResult | null> {
    let secret: KeyVaultSecret;
    // An identifier that pins a version pins it. Reading the name off the URL
    // and ignoring the version on it would serve the current secret to a caller
    // who asked for a specific one, and nothing would say so.
    const { name, version } = parseSecretIdentifier(ref.path);
    const wanted = ref.version ?? version;

    try {
      secret = await this.#client.getSecret(name, {
        ...(wanted === undefined ? {} : { version: wanted }),
      });
    } catch (error) {
      if (isAbsence(error)) {
        return null;
      }

      throw error;
    }

    const resolved = azureResolvedRef(secret);

    if (this.#honorNotBefore) {
      assertActive(secret.properties, resolved, new Date());
    }

    // `value` is optional in the SDK's type, and an absent value on a
    // successful response is a real state rather than an impossible one: a
    // disabled or purged-but-recoverable secret can answer without one. It maps
    // to an absence rather than to a non-null assertion.
    if (secret.value === undefined) {
      return null;
    }

    const lifetime = azureLifetime(secret.properties, this.#honorExpiresOn);

    // The `KeyVaultSecret` stops here. Its `properties` bag has already been
    // reduced to non-secret metadata and the value is on the payload.
    return {
      payload: { kind: 'string', value: secret.value },
      ref: resolved,
      ...(lifetime === undefined ? {} : { lifetime }),
    };
  }
}
