import { SensitiveString, createChildContext } from '@platform-sec/sensitive-string-core';
import type { RevealContext } from '@platform-sec/sensitive-string-core';
import {
  BaseSecretSource,
  SecretPayloadError,
  allSpec,
  materialize,
  normalizeRef,
} from '@platform-sec/sensitive-string-secrets';
import type {
  GetAllOptions,
  MultiSecretRecord,
  ProviderResult,
  ResolvedSecretRef,
  SecretRef,
  SecretSourceOptions,
} from '@platform-sec/sensitive-string-secrets';
import type { WritePayload } from '@platform-sec/sensitive-string-secrets/write';

import { checkFlavor, tokenHeader } from './flavor.js';
import type { VaultFlavor } from './flavor.js';
import { VaultLease, leaseTtlMs } from './lease.js';
import {
  assertLogicalPath,
  assertUnversioned,
  kvResolvedRef,
  kvReadPath,
  kvWriteBody,
  kvWritePath,
  kvWrittenVersion,
  parseKvResponse,
  splitMount,
} from './kv.js';
import type { KvVersion, VaultMount } from './kv.js';
import { VaultRequestError, fetchTransport } from './transport.js';
import type { VaultTransport } from './transport.js';

/**
 * The context every request-time reveal of the client token happens under.
 *
 * The token is the most sensitive value in the configuration, so it is a
 * `SensitiveString` like everything else this package produces. Accepting a
 * plain string as well would be convenient and would mean the one value that
 * unlocks every other one is the one value not covered.
 */
function tokenContext(): RevealContext {
  // A child of whatever context is ambient, so the reveal carries this
  // package's name and still reaches an application's audit sink. An explicit
  // context object would name the operation correctly and make the most
  // security-relevant reveal in the process the one nobody's `auditReveal`
  // sees.
  return createChildContext({ name: 'vault-request', reason: 'authenticating to Vault' });
}

export interface VaultSecretSourceOptions extends SecretSourceOptions {
  /** The API base, such as `https://vault.internal:8200`. Ignored when `transport` is given. */
  readonly endpoint?: string;
  /** A transport of your own, with retries, mTLS or a proxy already configured. */
  readonly transport?: VaultTransport;
  /** The client token. A credential, revealed per request under this package's context. */
  readonly token: SensitiveString<'credential'>;
  /** Vault Enterprise namespace. Rejected at construction under `flavor: 'openbao'`. */
  readonly namespace?: string;
  /** Required rather than detected. See the flavor module for why. */
  readonly flavor?: VaultFlavor;
  /** Which mounts run which KV engine version. */
  readonly mounts?: readonly VaultMount[];
  /** The engine version for a mount that is not listed. Defaults to 2. */
  readonly defaultKv?: KvVersion;
  /** Injected `fetch`, for the default transport. */
  readonly fetch?: typeof globalThis.fetch;
  /**
   * Called when a token renewal fails.
   *
   * A long-lived process holding a token from AppRole or Kubernetes auth has to
   * renew it, and a renewal failure retried silently until the token dies is
   * how a working deployment stops working at three in the morning.
   */
  readonly onAuthError?: (error: unknown) => void;
  /** Renew the client token on a timer. Off unless configured. */
  readonly tokenRenewal?: { readonly intervalMs: number; readonly incrementMs?: number };
}

export interface WrappedSecret {
  /** The single-use wrapping token, with the wrap TTL bound to it. */
  readonly token: SensitiveString<'credential'>;
  readonly accessor: string | undefined;
  readonly ttlSeconds: number | undefined;
}

/**
 * Vault and OpenBao.
 *
 * @example
 * ```ts
 * const vault = new VaultSecretSource({
 *   endpoint: 'https://vault.internal:8200',
 *   token: vaultToken,
 *   mounts: [{ path: 'kv', kv: 2 }],
 *   onLoad: (event) => audit.info('secret.load', event),
 * });
 *
 * const db = await vault.getJson('kv/prod/db', {
 *   fields: { username: 'sensitive', password: 'credential' },
 * });
 * ```
 */
export class VaultSecretSource extends BaseSecretSource {
  protected readonly sourceName: string;

  readonly flavor: VaultFlavor;

  readonly #transport: VaultTransport;
  readonly #token: SensitiveString<'credential'>;
  readonly #namespace: string | undefined;
  readonly #mounts: Map<string, KvVersion>;
  readonly #defaultKv: KvVersion;
  readonly #onAuthError: ((error: unknown) => void) | undefined;
  #renewalTimer: NodeJS.Timeout | undefined;

  constructor(options: VaultSecretSourceOptions) {
    super(options);

    this.flavor = options.flavor ?? 'vault';
    this.sourceName = this.flavor;

    checkFlavor(this.flavor, options.namespace);

    if (options.transport === undefined && options.endpoint === undefined) {
      throw new TypeError('VaultSecretSource needs either an endpoint or a transport.');
    }

    if (!(options.token instanceof SensitiveString)) {
      throw new TypeError(
        'VaultSecretSource needs the client token as a SensitiveString. A plain string ' +
          'would leave the one value that unlocks every other one uncovered.'
      );
    }

    this.#transport =
      options.transport ??
      fetchTransport({
        endpoint: options.endpoint ?? '',
        ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
      });
    this.#token = options.token;
    this.#namespace = options.namespace;
    this.#mounts = new Map((options.mounts ?? []).map((mount) => [mount.path, mount.kv]));
    this.#defaultKv = options.defaultKv ?? 2;
    this.#onAuthError = options.onAuthError;

    if (options.tokenRenewal !== undefined) {
      this.startTokenRenewal(options.tokenRenewal.intervalMs, options.tokenRenewal.incrementMs);
    }
  }

  /** The KV engine version configured for the mount a path sits under. */
  kvVersion(path: string): KvVersion {
    return this.#mounts.get(splitMount(path).mount) ?? this.#defaultKv;
  }

  // There is no `deriveLabel` override. A ref's path is already the logical
  // path within the store, because `assertLogicalPath` refuses anything that
  // carries an endpoint, and the `data/` segment KV v2 needs is inserted when
  // the request path is built rather than being part of the ref. An override
  // that rewrote the label would make it disagree with what was requested: a
  // caller who wrote `kv/data/prod/db` would see the label `kv/prod/db` while
  // the request went to `kv/data/data/prod/db` and 404ed.

  protected async fetchSecret(ref: SecretRef): Promise<ProviderResult | null> {
    assertLogicalPath(ref.path);

    const kv = this.kvVersion(ref.path);

    if (kv === 1) {
      assertUnversioned(ref.path, ref.version);
    }

    const response = await this.#read(kvReadPath(ref.path, kv), ref.version);

    if (response === null) {
      return null;
    }

    const read = parseKvResponse(response, kv, ref);
    const resolved = kvResolvedRef(ref, read);

    // A KV read binds no deadline, whatever `lease_duration` says. Measured on
    // Vault 1.21.4 and OpenBao 2.6.2, a KV v2 read reports 0 and a KV v1 read
    // reports the mount's default TTL, 2764800 seconds, and neither is an
    // expiry of the secret: `lease_id` is empty for both, so there is no lease
    // to renew or revoke and nothing stops working when the number runs out.
    // Binding the v1 number would expire a perfectly valid credential after 32
    // days for no reason. The number is kept on metadata, where an audit trail
    // can have it without anything enforcing it, which is the same treatment a
    // rotation schedule gets. `dynamic()` is where a lease is real.
    return {
      payload: { kind: 'map', value: read.data },
      ref: {
        ...resolved,
        metadata: {
          ...resolved.metadata,
          flavor: this.flavor,
          lease_duration: read.leaseDurationSeconds,
        },
      },
    };
  }

  /**
   * Read a dynamic secret, with its lease.
   *
   * This is where Vault's lifetime metadata earns the design: `lease_duration`
   * becomes a deadline bound to the credential, and `renewable` becomes the
   * permission to extend it, which for a credential has to be set explicitly
   * since the class default is that credentials are not renewable.
   */
  async dynamic(path: string, options: Partial<GetAllOptions> = {}): Promise<VaultLease> {
    const ref = normalizeRef(path);
    assertLogicalPath(ref.path);

    const response = await this.#read(ref.path, ref.version);

    if (response === null) {
      throw new SecretPayloadError(
        `Dynamic secret '${ref.path}' returned nothing. Check the backend and the role name.`,
        ref.path,
        'current'
      );
    }

    const envelope = response as {
      data?: unknown;
      lease_id?: unknown;
      lease_duration?: unknown;
      renewable?: unknown;
    };
    const data = envelope.data;

    if (data === null || typeof data !== 'object' || Array.isArray(data)) {
      throw new SecretPayloadError(
        `Dynamic secret '${ref.path}' returned no credential fields.`,
        ref.path,
        'current'
      );
    }

    const leaseId = typeof envelope.lease_id === 'string' ? envelope.lease_id : '';
    const renewable = envelope.renewable === true;
    // The lease id is what says a lease exists, not the duration. A response
    // carrying a duration and no lease id is reporting a cache hint, which is
    // what a KV v1 read does, and binding it would expire a credential nothing
    // is going to revoke.
    const ttl = leaseId === '' ? undefined : leaseTtlMs(envelope.lease_duration);
    const resolved: ResolvedSecretRef = {
      path: ref.path,
      version: leaseId === '' ? 'current' : leaseId,
      metadata: { flavor: this.flavor, renewable },
    };

    const materialized = materialize({
      payload: data as Record<string, unknown>,
      ref: resolved,
      spec: allSpec({ fallback: 'credential', ...options }),
      label: this.deriveLabel(ref),
      ...(ttl === undefined ? {} : { lifetime: { ttl, allowRenewal: renewable } }),
    });

    return new VaultLease(leaseId, renewable, resolved, materialized.fields, {
      transport: this.#transport,
      flavor: this.flavor,
      headers: () => this.#headers(),
      invalidate: () => {
        this.refresh(ref);
      },
    });
  }

  /**
   * Read a path with response wrapping, so Vault returns a single-use token
   * instead of the value.
   *
   * The token is a credential with the wrap TTL bound to it. Modelling the
   * single use itself needs the access counting core does not have yet; until
   * then this is a normal credential with the right deadline and the wrong
   * number of permitted reads, and that gap is in the README rather than
   * papered over.
   */
  async getWrapped(path: SecretRef | string, wrapTtlSeconds: number): Promise<WrappedSecret> {
    const ref = normalizeRef(path);
    assertLogicalPath(ref.path);

    const kv = this.kvVersion(ref.path);

    if (kv === 1) {
      assertUnversioned(ref.path, ref.version);
    }

    const response = await this.#transport.request({
      method: 'GET',
      path: kvReadPath(ref.path, kv),
      ...(ref.version === undefined ? {} : { query: { version: ref.version } }),
      headers: { ...this.#headers(), 'X-Vault-Wrap-TTL': String(wrapTtlSeconds) },
    });

    const info = (response.body as { wrap_info?: Record<string, unknown> } | undefined)?.wrap_info;

    if (info === undefined || typeof info['token'] !== 'string') {
      throw new SecretPayloadError(
        `Secret '${ref.path}' did not come back wrapped. Check that response wrapping is ` +
          `permitted for this path.`,
        ref.path,
        'current'
      );
    }

    const ttlSeconds = typeof info['ttl'] === 'number' ? info['ttl'] : undefined;
    const ttl = leaseTtlMs(ttlSeconds);

    return {
      token: new SensitiveString(
        info['token'],
        'credential',
        `${this.deriveLabel(ref)}#wrapping-token`,
        ttl === undefined ? undefined : { ttl }
      ),
      accessor: typeof info['wrapped_accessor'] === 'string' ? info['wrapped_accessor'] : undefined,
      ttlSeconds,
    };
  }

  /**
   * Exchange a wrapping token for the value it wraps.
   *
   * The token authenticates the unwrap, so it is revealed here and not
   * elsewhere, and the exchange is single-use server-side whatever this process
   * believes about it.
   */
  async unwrap(
    token: SensitiveString<'credential'>,
    options: GetAllOptions,
    label = 'unwrapped'
  ): Promise<MultiSecretRecord> {
    const response = await this.#transport.request({
      method: 'POST',
      path: 'sys/wrapping/unwrap',
      headers: {
        ...this.#baseHeaders(),
        [tokenHeader(this.flavor)]: token.reveal(tokenContext()),
      },
    });

    const ref: ResolvedSecretRef = {
      path: 'sys/wrapping/unwrap',
      version: 'unwrapped',
      metadata: { flavor: this.flavor },
    };
    const data = (response.body as { data?: unknown } | undefined)?.data;

    if (data === null || data === undefined || typeof data !== 'object' || Array.isArray(data)) {
      throw new SecretPayloadError('The unwrap response carried no data.', ref.path, ref.version);
    }

    const materialized = materialize({
      payload: data as Record<string, unknown>,
      ref,
      spec: allSpec(options),
      label,
    });

    return {
      ref,
      fields: materialized.fields,
      plain: materialized.plain,
      keys: materialized.keys,
    };
  }

  /**
   * The write half.
   *
   * A Vault KV path holds named fields, so a single-value write would have to
   * invent a field name. `putJson` from the write entry point is the surface;
   * this refuses a string payload rather than guessing.
   */
  async writeSecret(ref: SecretRef, payload: WritePayload): Promise<ResolvedSecretRef> {
    assertLogicalPath(ref.path);

    if (payload.kind === 'string') {
      throw new TypeError(
        `A Vault KV path holds named fields, so '${ref.path}' cannot take a single value. ` +
          `Use putJson().`
      );
    }

    const kv = this.kvVersion(ref.path);
    const response = await this.#transport.request({
      method: 'POST',
      path: kvWritePath(ref.path, kv),
      headers: this.#headers(),
      body: kvWriteBody(payload.value, kv),
    });

    return {
      path: ref.path,
      version: kvWrittenVersion(response.body, kv),
      metadata: { flavor: this.flavor },
    };
  }

  /**
   * Renew the client token on a timer.
   *
   * The timer is unreferenced, so it does not hold the process open, and
   * `close()` stops it.
   */
  startTokenRenewal(intervalMs: number, incrementMs?: number): void {
    this.stopTokenRenewal();

    this.#renewalTimer = setInterval(() => {
      void this.renewToken(incrementMs).catch((error: unknown) => {
        this.#onAuthError?.(error);
      });
    }, intervalMs);
    this.#renewalTimer.unref?.();
  }

  stopTokenRenewal(): void {
    if (this.#renewalTimer !== undefined) {
      clearInterval(this.#renewalTimer);
      this.#renewalTimer = undefined;
    }
  }

  /** Renew the client token once. */
  async renewToken(incrementMs?: number): Promise<number | undefined> {
    const response = await this.#transport.request({
      method: 'POST',
      path: 'auth/token/renew-self',
      headers: this.#headers(),
      ...(incrementMs === undefined
        ? {}
        : { body: { increment: Math.round(incrementMs / 1_000) } }),
    });

    const auth = (response.body as { auth?: { lease_duration?: unknown } } | undefined)?.auth;

    return leaseTtlMs(auth?.lease_duration);
  }

  /** Stop the renewal timer and drop every cached entry. */
  close(): void {
    this.stopTokenRenewal();
    this.clearCache();
  }

  /** A read that reports a 404 as absence and lets every other failure through. */
  async #read(path: string, version: string | undefined): Promise<unknown> {
    try {
      const response = await this.#transport.request({
        method: 'GET',
        path,
        headers: this.#headers(),
        ...(version === undefined ? {} : { query: { version } }),
      });

      return response.body;
    } catch (error) {
      // A 404 is an absence. A 403 is an authorization failure and keeps
      // throwing, so `getOptional` never turns a broken policy into a missing
      // secret.
      if (error instanceof VaultRequestError && error.status === 404) {
        return null;
      }

      throw error;
    }
  }

  #baseHeaders(): Record<string, string> {
    return this.#namespace === undefined ? {} : { 'X-Vault-Namespace': this.#namespace };
  }

  #headers(): Record<string, string> {
    return {
      ...this.#baseHeaders(),
      [tokenHeader(this.flavor)]: this.#token.reveal(tokenContext()),
    };
  }
}
