import { RenewalNotAllowedError, SensitiveString } from '@platform-sec/sensitive-string-core';
import type { SensitivityClass } from '@platform-sec/sensitive-string-core';
import type { ResolvedSecretRef } from '@platform-sec/sensitive-string-secrets';

import { tokenHeader } from './flavor.js';
import type { VaultFlavor } from './flavor.js';
import type { VaultTransport } from './transport.js';

/**
 * Lease handling.
 *
 * Vault is the only provider in this row whose API supplies everything the
 * lifetime and revocation design needs, which is why it is the reference
 * implementation and the others are subsets of it.
 */

/** Seconds to milliseconds. */
const MS_PER_SECOND = 1_000;

/**
 * A Vault `lease_duration` as a `SensitiveStringOptions.ttl`.
 *
 * The conversion happens here, once, in a named function with a test that pins
 * the factor. A silent factor-of-1000 error produces credentials that expire a
 * thousand times too early, or too late, and the too-late direction fails open.
 *
 * `lease_duration: 0` means no lease rather than already expired. A KV read
 * returns zero, and mapping it to `ttl: 0` would produce a value that is
 * expired on arrival, because `ttl: 0` in core means exactly the opposite: the
 * most conservative lifetime a caller can ask for.
 */
export function leaseTtlMs(leaseDurationSeconds: unknown): number | undefined {
  if (typeof leaseDurationSeconds !== 'number' || !Number.isFinite(leaseDurationSeconds)) {
    return undefined;
  }

  if (leaseDurationSeconds <= 0) {
    return undefined;
  }

  return leaseDurationSeconds * MS_PER_SECOND;
}

export interface LeaseContext {
  readonly transport: VaultTransport;
  readonly flavor: VaultFlavor;
  /** Produces the request headers, revealing the client token under this package's context. */
  headers(): Record<string, string>;
  /** Drops any cached entry for the lease's ref. */
  invalidate(): void;
}

/**
 * A dynamic secret and the lease behind it.
 *
 * The fields are wrapped with the lease duration bound to them, so a credential
 * that Vault will stop honouring in an hour is a value that stops revealing in
 * an hour rather than one whose deadline sits in provider metadata that nothing
 * enforces.
 */
export class VaultLease {
  /**
   * The transport and the flavor, in a private field rather than a parameter
   * property.
   *
   * A parameter property is an own enumerable property, so a lease that reached
   * a log line or `JSON.stringify` would carry the client with it. Nothing on a
   * lease should serialize except the lease id, the ref, and the wrapped
   * fields, all of which redact themselves.
   */
  readonly #context: LeaseContext;

  constructor(
    readonly leaseId: string,
    readonly renewable: boolean,
    readonly ref: ResolvedSecretRef,
    readonly fields: ReadonlyMap<string, SensitiveString<SensitivityClass>>,
    context: LeaseContext
  ) {
    this.#context = context;
  }

  /** Milliseconds left on the shortest-lived field, or undefined where nothing bounded them. */
  ttlRemaining(): number | undefined {
    let shortest: number | undefined;

    for (const value of this.fields.values()) {
      const remaining = value.ttlRemaining();

      if (remaining !== undefined && (shortest === undefined || remaining < shortest)) {
        shortest = remaining;
      }
    }

    return shortest;
  }

  /**
   * Extend the lease, server-side and then locally.
   *
   * A deployment whose policy forbids renewal and whose Vault leases are
   * renewable has a configuration conflict, and this is where it becomes
   * visible: the refusal is surfaced with its `RenewalRefusal` reason rather
   * than swallowed, and it is raised before the server call so a lease is not
   * extended upstream while the local values refuse to follow.
   *
   * @param increment - Requested extension in milliseconds. Vault may return less.
   */
  async renew(increment?: number): Promise<number | undefined> {
    if (!this.renewable) {
      throw new RenewalNotAllowedError('policy', this.ref.path);
    }

    for (const value of this.fields.values()) {
      if (!value.isRenewable()) {
        throw new RenewalNotAllowedError('policy', value.label ?? this.ref.path);
      }
    }

    const body =
      increment === undefined
        ? { lease_id: this.leaseId }
        : { lease_id: this.leaseId, increment: Math.round(increment / MS_PER_SECOND) };

    const response = await this.#context.transport.request({
      method: 'PUT',
      path: 'sys/leases/renew',
      headers: this.#context.headers(),
      body,
    });

    const granted = leaseTtlMs(
      (response.body as { lease_duration?: unknown } | undefined)?.lease_duration
    );

    if (granted === undefined) {
      return undefined;
    }

    for (const value of this.fields.values()) {
      value.renew(granted);
    }

    return granted;
  }

  /**
   * Revoke the lease.
   *
   * The order is local first, then server. Reversing it leaves a window where
   * the credential is dead upstream but this process still hands it out.
   *
   * Local here means the cache entry, which is all this package can reach:
   * invalidating the instances already handed out needs the revocation registry
   * that is designed and not built. Until it lands, an in-flight request
   * holding one of these values continues with it until Vault stops accepting
   * it. Vault's server-side revocation is stronger than anything local anyway,
   * which is why the gap is smaller here than for the providers without it.
   */
  async revoke(): Promise<void> {
    this.#context.invalidate();

    await this.#context.transport.request({
      method: 'PUT',
      path: 'sys/leases/revoke',
      headers: this.#context.headers(),
      body: { lease_id: this.leaseId },
    });
  }

  /** The header name this lease's requests authenticate with, for a caller that logs it. */
  get authHeader(): string {
    return tokenHeader(this.#context.flavor);
  }
}
