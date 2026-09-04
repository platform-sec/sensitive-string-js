import type { GetSecretOptions, KeyVaultSecret, SecretProperties } from '@azure/keyvault-secrets';

import { AzureSecretSource } from '../source.js';
import type { AzureSecretsClient, AzureSecretSourceOptions } from '../source.js';

/**
 * A client driven by recorded `KeyVaultSecret` objects.
 *
 * The fixtures are typed as the SDK's own model types, so a field this package
 * reads has to exist on the real response. Nothing here calls Azure.
 */

export const VAULT_URL = 'https://contoso-prod.vault.azure.net';

/** A `RestError`-shaped failure. Matched structurally, so this is enough. */
export function azureError(
  statusCode: number,
  code: string,
  message = 'the request failed'
): Error {
  return Object.assign(new Error(message), { statusCode, code, name: 'RestError' });
}

export interface Fixture {
  readonly value?: string | undefined;
  readonly properties?: Partial<SecretProperties>;
  readonly error?: Error;
}

export class FakeSecretClient implements AzureSecretsClient {
  readonly calls: { readonly name: string; readonly version: string | undefined }[] = [];

  constructor(private readonly routes: Map<string, Fixture>) {}

  static of(routes: Readonly<Record<string, Fixture>>): FakeSecretClient {
    return new FakeSecretClient(new Map(Object.entries(routes)));
  }

  getSecret(secretName: string, options?: GetSecretOptions): Promise<KeyVaultSecret> {
    this.calls.push({ name: secretName, version: options?.version });

    const fixture = this.routes.get(secretName);

    if (fixture === undefined) {
      return Promise.reject(
        azureError(404, 'SecretNotFound', 'A secret with this name was not found')
      );
    }

    if (fixture.error !== undefined) {
      return Promise.reject(fixture.error);
    }

    return Promise.resolve(keyVaultSecret(secretName, fixture, options?.version));
  }
}

export function keyVaultSecret(
  name: string,
  fixture: Fixture,
  version = 'c81f2a1e5b2c4d3e9f0a1b2c3d4e5f60'
): KeyVaultSecret {
  const properties: SecretProperties = {
    vaultUrl: VAULT_URL,
    name,
    version,
    id: `${VAULT_URL}/secrets/${name}/${version}`,
    enabled: true,
    createdOn: new Date('2026-09-01T00:00:00Z'),
    updatedOn: new Date('2026-09-01T00:00:00Z'),
    ...fixture.properties,
  };

  return {
    name,
    properties,
    ...(fixture.value === undefined ? {} : { value: fixture.value }),
  };
}

export function source(
  client: AzureSecretsClient,
  options: Partial<AzureSecretSourceOptions> = {}
): AzureSecretSource {
  return new AzureSecretSource({ client, cache: { ttl: 0 }, ...options });
}
