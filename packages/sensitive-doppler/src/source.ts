import { SensitiveString, createChildContext } from '@platform-sec/sensitive-string-core';
import type { RevealContext } from '@platform-sec/sensitive-string-core';
import { BaseSecretSource, SecretPayloadError } from '@platform-sec/sensitive-string-secrets';
import type {
  ProviderResult,
  ResolvedSecretRef,
  SecretRef,
  SecretSourceOptions,
} from '@platform-sec/sensitive-string-secrets';

import { DopplerRequestError, fetchTransport } from './transport.js';
import type { DopplerTransport } from './transport.js';

/**
 * The keys Doppler adds to every config.
 *
 * They are configuration rather than secrets, and they are the reason this
 * source ships a suggested spec rather than only a fallback: under
 * `fallback: 'credential'` an application that reads `DOPPLER_ENVIRONMENT` to
 * decide what to do would compare a `SensitiveString` against a string and get
 * `false` forever, which looks like a configuration bug rather than a security
 * control.
 */
export const DOPPLER_RESERVED_KEYS = [
  'DOPPLER_PROJECT',
  'DOPPLER_CONFIG',
  'DOPPLER_ENVIRONMENT',
] as const;

/** The context every request-time reveal of the token happens under. */
function tokenContext(): RevealContext {
  // A child of whatever is ambient, so the reveal names this package and still
  // reaches an application's audit sink.
  return createChildContext({ name: 'doppler-request', reason: 'authenticating to Doppler' });
}

export interface DopplerSecretSourceOptions extends SecretSourceOptions {
  /** A service token or a personal token, as a credential. */
  readonly token: SensitiveString<'credential'>;
  /** The project a one-segment ref resolves against. */
  readonly project?: string | undefined;
  /** The API base. Defaults to Doppler's. */
  readonly endpoint?: string | undefined;
  /** A transport of your own. */
  readonly transport?: DopplerTransport | undefined;
  readonly fetch?: typeof globalThis.fetch | undefined;
}

/**
 * Doppler.
 *
 * A Doppler config is a flat map that mixes secrets with ordinary
 * configuration, which is the case the shared layer's required `fallback`
 * exists for: neither fail-closed nor fail-open is right for a store like this
 * and only the caller knows which keys are which.
 *
 * @example
 * ```ts
 * const doppler = new DopplerSecretSource({ token: dopplerToken, project: 'payments' });
 *
 * const config = await doppler.getAll('prod', {
 *   rules: [{ pattern: /KEY|TOKEN|SECRET|PASSWORD|DSN/i, klass: 'credential' }],
 *   fallback: 'plain',
 * });
 *
 * config.fields.get('STRIPE_SECRET_KEY');
 * config.plain.get('LOG_LEVEL');
 * ```
 */
export class DopplerSecretSource extends BaseSecretSource {
  protected readonly sourceName = 'doppler';

  readonly #transport: DopplerTransport;
  readonly #token: SensitiveString<'credential'>;
  readonly #project: string | undefined;

  constructor(options: DopplerSecretSourceOptions) {
    super(options);

    if (!(options.token instanceof SensitiveString)) {
      throw new TypeError(
        'DopplerSecretSource needs the token as a SensitiveString. A plain string would ' +
          'leave the one value that unlocks every other one uncovered.'
      );
    }

    this.#token = options.token;
    this.#project = options.project;
    this.#transport =
      options.transport ??
      fetchTransport({
        ...(options.endpoint === undefined ? {} : { endpoint: options.endpoint }),
        ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
      });
  }

  /**
   * `project/config`.
   *
   * Both are names an operator chose inside Doppler and neither identifies an
   * account, a host or a tenancy, so the label keeps the container the secret
   * came from rather than reducing to the config alone, which two projects
   * could share.
   */
  protected override deriveLabel(ref: SecretRef): string {
    const { project, config } = this.#split(ref);

    return project === undefined ? config : `${project}/${config}`;
  }

  protected async fetchSecret(ref: SecretRef): Promise<ProviderResult | null> {
    const { project, config } = this.#split(ref);
    const resolved: ResolvedSecretRef = {
      path: project === undefined ? config : `${project}/${config}`,
      // A Doppler config has no version identifier on this endpoint. The rule
      // is that a provider which reports none says so rather than inventing
      // one, so this is the documented `'unknown'` rather than a timestamp
      // dressed up as a version.
      version: 'unknown',
      metadata: {
        config,
        ...(project === undefined ? {} : { project }),
      },
    };

    let body: unknown;

    try {
      const response = await this.#transport.request({
        path: 'v3/configs/config/secrets/download',
        query: {
          format: 'json',
          config,
          ...(project === undefined ? {} : { project }),
        },
        headers: { authorization: `Bearer ${this.#token.reveal(tokenContext())}` },
      });

      body = response.body;
    } catch (error) {
      // A 404 is an absence. A 401 is a bad token and a 403 is a token whose
      // scope does not cover this config, and both keep throwing so
      // `getOptional` never turns a broken token into a missing config.
      if (error instanceof DopplerRequestError && error.status === 404) {
        return null;
      }

      throw error;
    }

    if (body === null || typeof body !== 'object' || Array.isArray(body)) {
      throw new SecretPayloadError(
        `Doppler config '${resolved.path}' did not return a map of secrets.`,
        resolved.path,
        resolved.version
      );
    }

    // The response object stops here.
    return { payload: { kind: 'map', value: body as Record<string, unknown> }, ref: resolved };
  }

  /** `project/config`, or a bare config against the configured project. */
  #split(ref: SecretRef): { project: string | undefined; config: string } {
    const parts = ref.path.split('/').filter((part) => part !== '');

    if (parts.length >= 2) {
      return { project: parts[0], config: parts.slice(1).join('/') };
    }

    return { project: this.#project, config: parts[0] ?? ref.path };
  }
}
