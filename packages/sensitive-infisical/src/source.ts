import { SensitiveString, createChildContext } from '@platform-sec/sensitive-string-core';
import type { RevealContext } from '@platform-sec/sensitive-string-core';
import { BaseSecretSource, SecretPayloadError } from '@platform-sec/sensitive-string-secrets';
import type {
  ProviderResult,
  ResolvedSecretRef,
  SecretRef,
  SecretSourceOptions,
} from '@platform-sec/sensitive-string-secrets';

import { InfisicalRequestError, fetchTransport } from './transport.js';
import type { InfisicalTransport } from './transport.js';

/** The context every request-time reveal of the token happens under. */
function tokenContext(): RevealContext {
  return createChildContext({
    name: 'infisical-request',
    reason: 'authenticating to Infisical',
  });
}

export interface InfisicalSecretSourceOptions extends SecretSourceOptions {
  /** A service token or a machine identity access token, as a credential. */
  readonly token: SensitiveString<'credential'>;
  /** The project the read is scoped to. Infisical also calls this the workspace id. */
  readonly projectId?: string | undefined;
  /** The environment slug a one-segment ref resolves against, such as `prod`. */
  readonly environment?: string | undefined;
  /** The API base. Defaults to Infisical Cloud; set it for a self-hosted instance. */
  readonly endpoint?: string | undefined;
  /** A transport of your own. */
  readonly transport?: InfisicalTransport | undefined;
  readonly fetch?: typeof globalThis.fetch | undefined;
  /**
   * Include secrets an imported folder contributes. Defaults to false.
   *
   * Off by default because an import is a second store's key set arriving under
   * this one's path, and a classification written for one folder has not seen
   * the other. Turning it on is a decision, not a default.
   */
  readonly includeImports?: boolean | undefined;
}

/** One entry of Infisical's `secrets` array, in the fields this package reads. */
interface RawSecret {
  readonly secretKey?: unknown;
  readonly secretValue?: unknown;
}

/**
 * Infisical.
 *
 * A folder in an Infisical environment mixes secrets with ordinary
 * configuration, the same shape Doppler has, so the shared layer's required
 * `fallback` applies for the same reason.
 *
 * The ref is `environment/path`, which is what Infisical scopes a read by:
 * `prod/backend` reads the `/backend` folder of the `prod` environment.
 *
 * @example
 * ```ts
 * const infisical = new InfisicalSecretSource({
 *   token: infisicalToken,
 *   projectId: 'a1b2c3',
 *   environment: 'prod',
 * });
 *
 * const config = await infisical.getAll('/backend', {
 *   rules: [{ pattern: /KEY|TOKEN|SECRET|PASSWORD|DSN/i, klass: 'credential' }],
 *   fallback: 'plain',
 * });
 * ```
 */
export class InfisicalSecretSource extends BaseSecretSource {
  protected readonly sourceName = 'infisical';

  readonly #transport: InfisicalTransport;
  readonly #token: SensitiveString<'credential'>;
  readonly #projectId: string | undefined;
  readonly #environment: string | undefined;
  readonly #includeImports: boolean;

  constructor(options: InfisicalSecretSourceOptions) {
    super(options);

    if (!(options.token instanceof SensitiveString)) {
      throw new TypeError(
        'InfisicalSecretSource needs the token as a SensitiveString. A plain string would ' +
          'leave the one value that unlocks every other one uncovered.'
      );
    }

    this.#token = options.token;
    this.#projectId = options.projectId;
    this.#environment = options.environment;
    this.#includeImports = options.includeImports ?? false;
    this.#transport =
      options.transport ??
      fetchTransport({
        ...(options.endpoint === undefined ? {} : { endpoint: options.endpoint }),
        ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
      });
  }

  /**
   * `environment/path`.
   *
   * The project id is left off. It identifies the workspace the way an AWS
   * account id identifies an account, and it goes on `metadata` instead.
   */
  protected override deriveLabel(ref: SecretRef): string {
    const { environment, secretPath } = this.#split(ref);

    return `${environment}${secretPath === '/' ? '' : secretPath}`;
  }

  protected async fetchSecret(ref: SecretRef): Promise<ProviderResult | null> {
    const { environment, secretPath } = this.#split(ref);

    if (this.#projectId === undefined || this.#projectId === '') {
      throw new TypeError(
        `InfisicalSecretSource needs a projectId to read '${ref.path}'. Pass { projectId } ` +
          `to the constructor.`
      );
    }

    const resolved: ResolvedSecretRef = {
      path: this.deriveLabel(ref),
      // Infisical's raw read reports no version for the folder as a whole. The
      // rule is that a provider which reports none says so rather than
      // inventing one.
      version: 'unknown',
      metadata: { projectId: this.#projectId, environment, secretPath },
    };

    let body: unknown;

    try {
      const response = await this.#transport.request({
        path: 'api/v3/secrets/raw',
        query: {
          workspaceId: this.#projectId,
          environment,
          secretPath,
          expandSecretReferences: 'true',
          include_imports: String(this.#includeImports),
        },
        headers: { authorization: `Bearer ${this.#token.reveal(tokenContext())}` },
      });

      body = response.body;
    } catch (error) {
      // A 404 is an absence. A 401 or 403 keeps throwing, so `getOptional`
      // never turns a broken token into a missing folder.
      if (error instanceof InfisicalRequestError && error.status === 404) {
        return null;
      }

      throw error;
    }

    // The response object stops here: the entries are reduced to a plain map
    // and nothing downstream can reach the array they came from.
    return { payload: { kind: 'map', value: this.#toMap(body, resolved) }, ref: resolved };
  }

  /**
   * The `secrets` array as a map.
   *
   * A duplicate key is refused rather than resolved. Infisical can return the
   * same key twice when an import overlaps the folder, and picking one of them
   * would mean an application silently reads a value from a folder its
   * classification never described.
   */
  #toMap(body: unknown, ref: ResolvedSecretRef): Record<string, unknown> {
    if (body === null || typeof body !== 'object' || Array.isArray(body)) {
      throw new SecretPayloadError(
        `Infisical path '${ref.path}' did not return a secrets object.`,
        ref.path,
        ref.version
      );
    }

    const secrets = (body as { secrets?: unknown }).secrets;

    if (!Array.isArray(secrets)) {
      throw new SecretPayloadError(
        `Infisical path '${ref.path}' returned no 'secrets' array.`,
        ref.path,
        ref.version
      );
    }

    const map: Record<string, unknown> = {};

    for (const entry of secrets as readonly RawSecret[]) {
      const key = entry.secretKey;

      if (typeof key !== 'string' || key === '') {
        throw new SecretPayloadError(
          `Infisical path '${ref.path}' returned an entry with no secretKey.`,
          ref.path,
          ref.version
        );
      }

      if (key in map) {
        throw new SecretPayloadError(
          `Infisical path '${ref.path}' returned '${key}' twice, which happens when an ` +
            `import overlaps the folder. Picking one of them would mean reading a value ` +
            `from a folder this classification never described.`,
          ref.path,
          ref.version
        );
      }

      map[key] = entry.secretValue;
    }

    return map;
  }

  /** `environment/path`, or a path against the configured environment. */
  #split(ref: SecretRef): { environment: string; secretPath: string } {
    const trimmed = ref.path.replace(/^\/+/, '');
    const parts = trimmed.split('/').filter((part) => part !== '');

    if (this.#environment !== undefined && this.#environment !== '') {
      return { environment: this.#environment, secretPath: `/${parts.join('/')}` };
    }

    if (parts.length === 0) {
      throw new TypeError(
        `InfisicalSecretSource needs an environment. Pass { environment } to the ` +
          `constructor, or use an 'environment/path' ref.`
      );
    }

    return { environment: parts[0] ?? '', secretPath: `/${parts.slice(1).join('/')}` };
  }
}
