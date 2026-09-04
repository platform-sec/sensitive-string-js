import {
  BaseSecretSource,
  SecretPayloadError,
  decodeBase64Map,
  parsePayload,
} from '@platform-sec/sensitive-string-secrets';
import type {
  ProviderResult,
  ResolvedSecretRef,
  SecretLifetime,
  SecretRef,
  SecretSourceOptions,
} from '@platform-sec/sensitive-string-secrets';
import type { V1Secret } from '@kubernetes/client-node';

import { k8sMetadata } from './metadata.js';
import { jwtExpiry } from './token.js';

/**
 * The one method this package calls on the injected API client.
 *
 * A `CoreV1Api` from `kc.makeApiClient(CoreV1Api)` satisfies it. Declaring it
 * structurally keeps `@kubernetes/client-node` a types-only dependency, which
 * matters more here than elsewhere: that package carries a large dependency
 * tree and an application already has a configured client.
 */
export interface K8sCoreApi {
  readNamespacedSecret(request: { name: string; namespace: string }): Promise<V1Secret>;
}

export interface K8sSecretSourceOptions extends SecretSourceOptions {
  /** Injected, so cluster configuration and authentication stay with the application. */
  readonly api: K8sCoreApi;
  /** The namespace a bare name is read from. A `namespace/name` path overrides it. */
  readonly namespace?: string | undefined;
  /**
   * Bind the `exp` claim of a `token` field as a deadline.
   *
   * Off by default. It only applies where a `token` field holds a JWT, and a
   * legacy service account token Secret holds one with no `exp`, which binds
   * nothing.
   */
  readonly readTokenExpiry?: boolean | undefined;
  /**
   * Decode `.dockerconfigjson` and expand it into nested keys.
   *
   * Off by default, and deliberately a caller's decision rather than something
   * a payload triggers. Expansion changes the key set a `getAll` returns, so a
   * caller running it under `fallback: 'plain'` would turn one
   * credential-classified string into several plain ones. Pass it together with
   * `k8sSecretTypeSpec('kubernetes.io/dockerconfigjson')`, which classifies the
   * expanded leaves.
   */
  readonly expandDockerConfigJson?: boolean | undefined;
}

/**
 * `stringData` is write-only.
 *
 * It is absent from every read, so a package that looks there finds nothing and
 * reports an empty Secret. That is a confusing enough failure to be worth its
 * own message.
 */
const WRITE_ONLY = 'stringData';

/** Kubernetes reports an absent Secret as a 404, through more than one client shape. */
function isAbsence(error: unknown): boolean {
  if (typeof error !== 'object' || error === null) {
    return false;
  }

  const shaped = error as {
    code?: unknown;
    statusCode?: unknown;
    response?: { statusCode?: unknown };
  };

  return shaped.code === 404 || shaped.statusCode === 404 || shaped.response?.statusCode === 404;
}

/** The keys a pull secret can arrive under. */
const DOCKER_KEYS = ['.dockerconfigjson', '.dockercfg'];

/**
 * Kubernetes Secrets, through the API server.
 *
 * Reading through the API server needs the pod's service account token and an
 * RBAC rule granting `get` on secrets, which is what puts it in this row rather
 * than in the configuration loaders one. Reading a mounted volume needs
 * nothing; `K8sMountedSource` is here anyway, because a user who thinks of it
 * as "reading a Secret" will look here first.
 *
 * @example
 * ```ts
 * const k8s = new K8sSecretSource({
 *   api: kc.makeApiClient(CoreV1Api),
 *   namespace: 'payments',
 * });
 *
 * const creds = await k8s.getAll('db-creds', { fallback: 'credential' });
 * creds.fields.get('password');   // label 'payments/db-creds#password'
 * ```
 */
export class K8sSecretSource extends BaseSecretSource {
  protected readonly sourceName = 'k8s';

  readonly #api: K8sCoreApi;
  readonly #namespace: string | undefined;
  readonly #readTokenExpiry: boolean;
  readonly #expandDockerConfigJson: boolean;

  constructor(options: K8sSecretSourceOptions) {
    super(options);

    if (options.api === undefined || typeof options.api.readNamespacedSecret !== 'function') {
      throw new TypeError(
        'K8sSecretSource needs an API client with a readNamespacedSecret() method, such as ' +
          'kc.makeApiClient(CoreV1Api).'
      );
    }

    this.#api = options.api;
    this.#namespace = options.namespace;
    this.#readTokenExpiry = options.readTokenExpiry ?? false;
    this.#expandDockerConfigJson = options.expandDockerConfigJson ?? false;
  }

  /**
   * `namespace/name`.
   *
   * Both halves are ordinary Kubernetes identifiers and neither discloses
   * anything about the cluster, which is why this is the one provider in the
   * row whose label keeps the container it came from.
   */
  protected override deriveLabel(ref: SecretRef): string {
    const { namespace, name } = this.#split(ref);

    return `${namespace}/${name}`;
  }

  protected async fetchSecret(ref: SecretRef): Promise<ProviderResult | null> {
    const { namespace, name } = this.#split(ref);
    let secret: V1Secret;

    try {
      secret = await this.#api.readNamespacedSecret({ name, namespace });
    } catch (error) {
      if (isAbsence(error)) {
        return null;
      }

      throw error;
    }

    const resolved: ResolvedSecretRef = {
      path: `${namespace}/${name}`,
      // A Secret has no versions. `resourceVersion` is the closest thing and is
      // a real, concrete identifier of the state that was served, which is what
      // the resolved-version rule asks for.
      version: secret.metadata?.resourceVersion ?? 'unknown',
      metadata: k8sMetadata(secret),
    };

    const data = secret.data;

    if (data === undefined || Object.keys(data).length === 0) {
      if (secret[WRITE_ONLY] !== undefined) {
        throw new SecretPayloadError(
          `Secret '${resolved.path}' came back with only 'stringData', which is write-only ` +
            `and absent from every read. This is a fixture or a fake, not a live Secret.`,
          resolved.path,
          resolved.version
        );
      }

      // An existing Secret with no data is an empty Secret rather than an
      // absent one, and reporting it as absent would hide the difference.
      return { payload: { kind: 'map', value: {} }, ref: resolved };
    }

    // Base64 through the shared guard, which validates the alphabet and the
    // round trip first. `Buffer.from(value, 'base64')` skips characters outside
    // the alphabet rather than failing, so a damaged Secret value would decode
    // to plausible-looking garbage, get wrapped as a credential, and fail at
    // the far side as an authentication error with nothing pointing back here.
    const decoded = decodeBase64Map(data, resolved);
    const payload = this.#expandDockerConfigJson ? expandDockerConfig(decoded, resolved) : decoded;
    const lifetime = this.#readTokenExpiry ? tokenLifetime(decoded, resolved) : undefined;

    // The `V1Secret` stops here, annotations included.
    return {
      payload: { kind: 'map', value: payload },
      ref: resolved,
      ...(lifetime === undefined ? {} : { lifetime }),
    };
  }

  /** `namespace/name`, or the configured namespace and a bare name. */
  #split(ref: SecretRef): { namespace: string; name: string } {
    const parts = ref.path.split('/').filter((part) => part !== '');

    if (parts.length >= 2) {
      return { namespace: parts[0] ?? '', name: parts.slice(1).join('/') };
    }

    if (this.#namespace === undefined || this.#namespace === '') {
      throw new TypeError(
        `K8sSecretSource needs a namespace to read '${ref.path}'. Pass { namespace } to the ` +
          `constructor, or use a 'namespace/name' path.`
      );
    }

    return { namespace: this.#namespace, name: parts[0] ?? ref.path };
  }
}

/**
 * Replace a pull secret's JSON string with its parsed shape.
 *
 * Nested JSON inside a base64 value inside a Secret, so it goes through the
 * shared JSON guard and inherits the rule that a decoder does not report its
 * input. A malformed pull secret is common enough that the guard earns itself
 * here on its own.
 *
 * The raw string is replaced rather than kept alongside, so exactly one copy of
 * the credential is classified and wrapped.
 */
export function expandDockerConfig(
  decoded: Readonly<Record<string, string>>,
  ref: ResolvedSecretRef
): Record<string, unknown> {
  const expanded: Record<string, unknown> = { ...decoded };

  for (const key of DOCKER_KEYS) {
    const raw = decoded[key];

    if (raw === undefined) {
      continue;
    }

    delete expanded[key];
    Object.assign(expanded, parsePayload(raw, ref));
  }

  return expanded;
}

/** The deadline a projected service account token carries, where it has one. */
function tokenLifetime(
  decoded: Readonly<Record<string, string>>,
  ref: ResolvedSecretRef
): SecretLifetime | undefined {
  const token = decoded['token'];

  if (token === undefined) {
    return undefined;
  }

  const expiresAt = jwtExpiry(token, ref);

  return expiresAt === undefined ? undefined : { expiresAt };
}
