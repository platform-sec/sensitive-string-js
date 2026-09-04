import { OciSecretSource } from '../source.js';
import type { OciSecretsClient, OciSecretSourceOptions } from '../source.js';
import type { SecretBundle } from '../wire.js';

/**
 * A client driven by recorded bundles.
 *
 * The fixtures are typed as `oci-secrets`' own `SecretBundle`, so a field this
 * package reads has to exist on the real model. Nothing here calls OCI.
 */

export const VAULT_ID = 'ocid1.vault.oc1.iad.aaaaaaaaexamplevault';
export const SECRET_OCID = 'ocid1.vaultsecret.oc1.iad.aaaaaaaaexamplesecret';
export const TENANCY = 'aaaaaaaaexamplevault';

/** An OCI SDK error, matched structurally by its status code. */
export function ociError(statusCode: number, message = 'the request failed'): Error {
  return Object.assign(new Error(message), { statusCode, opcRequestId: 'abc' });
}

export interface Fixture {
  readonly value?: string;
  /** Written straight through, for the cases where it is not valid base64. */
  readonly rawContent?: string;
  readonly contentType?: string;
  readonly omitContent?: boolean;
  readonly versionNumber?: number;
  readonly timeOfExpiry?: Date;
  readonly timeOfDeletion?: Date;
  readonly error?: Error;
}

export function bundle(fixture: Fixture): SecretBundle {
  const content = fixture.rawContent ?? Buffer.from(fixture.value ?? '', 'utf8').toString('base64');

  return {
    secretId: SECRET_OCID,
    versionNumber: fixture.versionNumber ?? 4,
    versionName: 'v4',
    timeCreated: new Date('2026-09-01T00:00:00Z'),
    stages: ['CURRENT', 'LATEST'] as NonNullable<SecretBundle['stages']>,
    ...(fixture.timeOfExpiry === undefined ? {} : { timeOfExpiry: fixture.timeOfExpiry }),
    ...(fixture.timeOfDeletion === undefined ? {} : { timeOfDeletion: fixture.timeOfDeletion }),
    ...(fixture.omitContent === true
      ? {}
      : {
          secretBundleContent: {
            contentType: fixture.contentType ?? 'BASE64',
            content,
          },
        }),
  };
}

export class FakeSecretsClient implements OciSecretsClient {
  readonly requests: Record<string, unknown>[] = [];

  constructor(private readonly routes: Map<string, Fixture>) {}

  static of(routes: Readonly<Record<string, Fixture>>): FakeSecretsClient {
    return new FakeSecretsClient(new Map(Object.entries(routes)));
  }

  getSecretBundleByName(request: {
    secretName: string;
    vaultId: string;
    versionNumber?: number;
    secretVersionName?: string;
    stage?: string;
  }): Promise<{ secretBundle: SecretBundle }> {
    this.requests.push({ ...request });

    return this.#reply(request.secretName);
  }

  getSecretBundle(request: {
    secretId: string;
    versionNumber?: number;
    secretVersionName?: string;
    stage?: string;
  }): Promise<{ secretBundle: SecretBundle }> {
    this.requests.push({ ...request });

    return this.#reply(request.secretId);
  }

  #reply(key: string): Promise<{ secretBundle: SecretBundle }> {
    const fixture = this.routes.get(key);

    if (fixture === undefined) {
      return Promise.reject(ociError(404, 'NotAuthorizedOrNotFound'));
    }

    if (fixture.error !== undefined) {
      return Promise.reject(fixture.error);
    }

    return Promise.resolve({ secretBundle: bundle(fixture) });
  }
}

export function source(
  client: OciSecretsClient,
  options: Partial<OciSecretSourceOptions> = {}
): OciSecretSource {
  return new OciSecretSource({ client, vaultId: VAULT_ID, cache: { ttl: 0 }, ...options });
}
