import { BaseSecretSource } from '@platform-sec/sensitive-string-secrets';
import type {
  ProviderResult,
  SecretLifetime,
  SecretMetadata,
  SecretRef,
  SecretSourceOptions,
} from '@platform-sec/sensitive-string-secrets';

import {
  gcpLabel,
  gcpResolvedRef,
  gcpSecretMetadata,
  resourceName,
  verifiedPayload,
} from './wire.js';
import type { AccessResponse, Secret } from './wire.js';

/**
 * The two methods this package calls on the injected client.
 *
 * A real `SecretManagerServiceClient` satisfies it. Declaring it structurally
 * keeps `@google-cloud/secret-manager` a types-only dependency: nothing here
 * imports a value from it, and gax pulls in a large dependency tree that an
 * application configuring its own client already has.
 *
 * gax returns a tuple whose first element is the response, so that shape is
 * part of the interface rather than something this package normalizes away.
 */
export interface GcpSecretsClient {
  accessSecretVersion(request: {
    name: string;
  }): Promise<readonly [AccessResponse, ...(readonly unknown[])]>;
  getSecret(request: { name: string }): Promise<readonly [Secret, ...(readonly unknown[])]>;
}

export interface GcpSecretSourceOptions extends SecretSourceOptions {
  /** Injected, so authentication and gax options stay with the application. */
  readonly client: GcpSecretsClient;
  /** Resolves a short name to `projects/<project>/secrets/<name>`. */
  readonly project?: string | undefined;
  /**
   * Read the secret resource as well, so `expireTime` can become a deadline.
   *
   * Off by default because it costs a `getSecret` call on top of
   * `accessSecretVersion`. What it buys is the one real deadline this provider
   * has; `rotation` is recorded either way and never becomes one.
   */
  readonly readExpiry?: boolean | undefined;
  /**
   * Fail a load whose payload arrives without a usable `dataCrc32c`.
   *
   * Off by default. Whether the API supplies one on every path is not something
   * this package has measured, and refusing a load over a field that may
   * legitimately be absent is the wrong way to find out. A present checksum is
   * always verified whatever this is set to.
   */
  readonly requireChecksum?: boolean | undefined;
}

/**
 * gRPC status 5, NOT_FOUND.
 *
 * Read off the error rather than through `instanceof`, for the reason the other
 * providers in this row give: two copies of a vendor package make an
 * `instanceof` against its error class miss. Nothing else is an absence, so
 * PERMISSION_DENIED (7) and FAILED_PRECONDITION (9), which is what a DISABLED
 * or DESTROYED version produces, both keep throwing.
 */
const NOT_FOUND = 5;

function isAbsence(error: unknown): boolean {
  return (
    typeof error === 'object' && error !== null && (error as { code?: unknown }).code === NOT_FOUND
  );
}

/**
 * GCP Secret Manager.
 *
 * @example
 * ```ts
 * const gcp = new GcpSecretSource({
 *   client: new SecretManagerServiceClient(),
 *   project: 'my-project',
 * });
 *
 * const key = await gcp.get('stripe-api-key');   // resolves 'latest'
 * key.ref.version;                               // the concrete version, never 'latest'
 * ```
 */
export class GcpSecretSource extends BaseSecretSource {
  protected readonly sourceName = 'gcp-secrets';

  readonly #client: GcpSecretsClient;
  readonly #project: string | undefined;
  readonly #readExpiry: boolean;
  readonly #requireChecksum: boolean;

  constructor(options: GcpSecretSourceOptions) {
    super(options);

    if (options.client === undefined || typeof options.client.accessSecretVersion !== 'function') {
      throw new TypeError(
        'GcpSecretSource needs a client with an accessSecretVersion() method, such as a ' +
          'SecretManagerServiceClient.'
      );
    }

    this.#client = options.client;
    this.#project = options.project;
    this.#readExpiry = options.readExpiry ?? false;
    this.#requireChecksum = options.requireChecksum ?? false;
  }

  /** The short name. The project number is on `metadata`. */
  protected override deriveLabel(ref: SecretRef): string {
    return gcpLabel(ref.path);
  }

  protected async fetchSecret(ref: SecretRef): Promise<ProviderResult | null> {
    const name = resourceName(ref, this.#project);
    let response: AccessResponse;

    try {
      [response] = await this.#client.accessSecretVersion({ name });
    } catch (error) {
      if (isAbsence(error)) {
        return null;
      }

      throw error;
    }

    const resolved = gcpResolvedRef(response, ref);
    const payload = response.payload;

    if (payload === null || payload === undefined) {
      return null;
    }

    // Verified and decoded before anything is wrapped, so the integrity check
    // is not a reveal of a value that does not exist yet.
    const value = verifiedPayload(payload, resolved, this.#requireChecksum);
    const { lifetime, metadata } = this.#readExpiry
      ? await this.#describe(resolved.metadata['project'], resolved.path)
      : { lifetime: undefined, metadata: {} };

    return {
      payload: { kind: 'string', value },
      ref: { ...resolved, metadata: { ...resolved.metadata, ...metadata } },
      ...(lifetime === undefined ? {} : { lifetime }),
    };
  }

  /**
   * The secret resource, for its `expireTime`.
   *
   * A failure here loses the metadata rather than the secret.
   * `secretmanager.secrets.get` is a separate permission from
   * `versions.access`, and an application that has one and not the other should
   * still get its secret.
   */
  async #describe(
    project: string | number | boolean | undefined,
    secret: string
  ): Promise<{ lifetime: SecretLifetime | undefined; metadata: SecretMetadata }> {
    if (typeof project !== 'string') {
      return { lifetime: undefined, metadata: {} };
    }

    try {
      const [resource] = await this.#client.getSecret({
        name: `projects/${project}/secrets/${secret}`,
      });

      return gcpSecretMetadata(resource);
    } catch {
      return { lifetime: undefined, metadata: { secretMetadata: 'unavailable' } };
    }
  }
}
