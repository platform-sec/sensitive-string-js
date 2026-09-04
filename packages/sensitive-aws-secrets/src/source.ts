import { DescribeSecretCommand, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import type {
  DescribeSecretCommandOutput,
  GetSecretValueCommandOutput,
} from '@aws-sdk/client-secrets-manager';
import { BaseSecretSource } from '@platform-sec/sensitive-string-secrets';
import type {
  ProviderResult,
  SecretMetadata,
  SecretRef,
  SecretSourceOptions,
} from '@platform-sec/sensitive-string-secrets';

import { awsLabel, awsPayload, awsResolvedRef, rotationMetadata, versionField } from './wire.js';
import type { BinaryEncoding, VersionSlot } from './wire.js';

/**
 * The one method this package calls on the injected client.
 *
 * Declared structurally rather than as `SecretsManagerClient`, so a caller can
 * pass a client this package has never heard of and a test can pass a fake
 * without constructing an SDK client. A real `SecretsManagerClient` satisfies
 * it, because its generic `send` instantiates to both signatures.
 *
 * The command classes are a real runtime import, which makes this the one
 * package in this row with a vendor dependency at run time rather than only at
 * build time. Constructing a command is the SDK's contract and reimplementing
 * its serialization to avoid the import would be a worse trade.
 */
export interface AwsSecretsClient {
  send(command: GetSecretValueCommand): Promise<GetSecretValueCommandOutput>;
  send(command: DescribeSecretCommand): Promise<DescribeSecretCommandOutput>;
}

export interface AwsSecretSourceOptions extends SecretSourceOptions {
  /** Injected, so credential providers, retries and endpoints stay yours. */
  readonly client: AwsSecretsClient;
  /**
   * Record rotation metadata on the resolved ref.
   *
   * Off by default because it costs a `DescribeSecret` call per load.
   * Whichever way it is set, nothing here becomes a deadline: see
   * `rotationMetadata`.
   */
  readonly readRotation?: boolean | undefined;
  /** How `SecretBinary` is decoded. Defaults to utf8. */
  readonly binaryEncoding?: BinaryEncoding | undefined;
  /** Whether a `version` is a staging label or a version id. Defaults to auto. */
  readonly versionIs?: VersionSlot | undefined;
}

/**
 * The exception name AWS uses for an absent secret or an absent version.
 *
 * Matched by name rather than by `instanceof`. The SDK exports the exception
 * class, and two copies of the SDK in `node_modules` make every `instanceof`
 * against it miss, which is the identity problem this library already has with
 * two copies of core. A missed check here would turn an absence into a throw,
 * which is the safe direction, but the reverse mistake is what matters: nothing
 * else is treated as an absence, so an authorization failure keeps throwing.
 */
const ABSENT = 'ResourceNotFoundException';

function isAbsence(error: unknown): boolean {
  return error instanceof Error && error.name === ABSENT;
}

/**
 * AWS Secrets Manager.
 *
 * @example
 * ```ts
 * const aws = new AwsSecretSource({
 *   client: new SecretsManagerClient({ region: 'us-east-1' }),
 *   onLoad: (event) => audit.info('secret.load', event),
 * });
 *
 * const db = await aws.getJson('prod/db', {
 *   fields: { username: 'sensitive', password: 'credential', host: 'plain', port: 'plain' },
 * });
 *
 * const previous = await aws.get({ path: 'prod/stripe', version: 'AWSPREVIOUS' });
 * ```
 */
export class AwsSecretSource extends BaseSecretSource {
  protected readonly sourceName = 'aws-secrets';

  readonly #client: AwsSecretsClient;
  readonly #readRotation: boolean;
  readonly #binaryEncoding: BinaryEncoding;
  readonly #versionIs: VersionSlot;

  constructor(options: AwsSecretSourceOptions) {
    super(options);

    if (options.client === undefined || typeof options.client.send !== 'function') {
      throw new TypeError(
        'AwsSecretSource needs a client with a send() method, such as a SecretsManagerClient.'
      );
    }

    this.#client = options.client;
    this.#readRotation = options.readRotation ?? false;
    this.#binaryEncoding = options.binaryEncoding ?? 'utf8';
    this.#versionIs = options.versionIs ?? 'auto';
  }

  /** The name, never the ARN. The account id is on `metadata` instead. */
  protected override deriveLabel(ref: SecretRef): string {
    return awsLabel(ref.path);
  }

  protected async fetchSecret(ref: SecretRef): Promise<ProviderResult | null> {
    let response: GetSecretValueCommandOutput;

    try {
      response = await this.#client.send(
        new GetSecretValueCommand({
          SecretId: ref.path,
          ...(ref.version === undefined ? {} : versionField(ref.version, this.#versionIs)),
        })
      );
    } catch (error) {
      // Absence only. `InvalidRequestException`, which is what a secret
      // scheduled for deletion produces, keeps throwing: that secret exists and
      // reporting it as missing would hide a deployment mistake.
      if (isAbsence(error)) {
        return null;
      }

      throw error;
    }

    const rotation = this.#readRotation ? await this.#describe(ref) : {};
    const resolved = awsResolvedRef(response, ref, rotation);

    // The response object stops here. What crosses the boundary is the payload
    // and the non-secret metadata, so nothing downstream can reach `response`
    // and no error can carry it.
    return { payload: awsPayload(response, resolved, this.#binaryEncoding), ref: resolved };
  }

  /**
   * Rotation metadata, on the load that asked for it.
   *
   * A failure here is swallowed rather than failing the read. The secret was
   * served; `secretsmanager:DescribeSecret` is a separate permission from
   * `GetSecretValue` and an application that has one and not the other should
   * get its secret and lose the metadata, not lose its secret.
   */
  async #describe(ref: SecretRef): Promise<SecretMetadata> {
    try {
      return rotationMetadata(
        await this.#client.send(
          new DescribeSecretCommand({
            SecretId: ref.path,
          })
        )
      );
    } catch {
      return { rotationMetadata: 'unavailable' };
    }
  }
}
