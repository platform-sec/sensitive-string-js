import { SensitiveString } from '@platform-sec/sensitive-string-core';

import { VaultRequestError } from '../transport.js';
import type { VaultRequest, VaultResponse, VaultTransport } from '../transport.js';
import { VaultSecretSource } from '../source.js';
import type { VaultSecretSourceOptions } from '../source.js';

/**
 * A transport driven by recorded response bodies.
 *
 * No test in this package calls a live Vault. The container matrix in CI is a
 * second tier and is not required for the unit suite to pass, so the fixtures
 * here are what the wire-shape assertions run against, and every secret-bearing
 * field in them carries a canary.
 *
 * A fixture is only as good as the recording behind it. The KV v1 body here
 * once said `lease_duration: 0`, which is the KV v2 answer, and that invented
 * number hid a bug: both servers actually send the mount's default TTL there,
 * and the package was binding it as a deadline. Every number in these fixtures
 * is one a real server sent.
 */

export interface Recorded {
  readonly status?: number;
  readonly body?: unknown;
  /** Vault's own `errors` array, for a failure fixture. */
  readonly errors?: readonly string[];
}

export class FakeTransport implements VaultTransport {
  readonly requests: VaultRequest[] = [];

  constructor(private readonly routes: Map<string, Recorded>) {}

  static of(routes: Readonly<Record<string, Recorded>>): FakeTransport {
    return new FakeTransport(new Map(Object.entries(routes)));
  }

  set(key: string, recorded: Recorded): void {
    this.routes.set(key, recorded);
  }

  request(request: VaultRequest): Promise<VaultResponse> {
    this.requests.push(request);

    const recorded =
      this.routes.get(`${request.method} ${request.path}`) ?? this.routes.get(request.path);

    if (recorded === undefined) {
      return Promise.reject(new VaultRequestError(404, request.path, []));
    }

    const status = recorded.status ?? 200;

    if (status >= 400) {
      return Promise.reject(new VaultRequestError(status, request.path, recorded.errors ?? []));
    }

    return Promise.resolve({ status, body: recorded.body });
  }
}

export const TEST_TOKEN = 'hvs.TESTTOKEN_abc123';

export function vaultToken(): SensitiveString<'credential'> {
  return new SensitiveString(TEST_TOKEN, 'credential', 'vault-token');
}

export function source(
  transport: VaultTransport,
  options: Partial<VaultSecretSourceOptions> = {}
): VaultSecretSource {
  return new VaultSecretSource({
    transport,
    token: vaultToken(),
    mounts: [{ path: 'kv', kv: 2 }],
    cache: { ttl: 0 },
    ...options,
  });
}

/** A KV v2 read response, as Vault shapes it. */
export function kvV2Body(
  data: Readonly<Record<string, unknown>>,
  metadata: Readonly<Record<string, unknown>> = {}
): unknown {
  return {
    request_id: 'a1b2',
    lease_id: '',
    renewable: false,
    lease_duration: 0,
    data: {
      data,
      metadata: {
        created_time: '2026-09-01T00:00:00Z',
        deletion_time: '',
        destroyed: false,
        version: 7,
        ...metadata,
      },
    },
  };
}

/**
 * A KV v1 read response.
 *
 * `lease_duration` is 2764800, the mount's default TTL, because that is what
 * Vault 1.21.4 and OpenBao 2.6.2 both actually send for a KV v1 read. It looks
 * like a 32-day lease and is not one: `lease_id` is empty, so there is nothing
 * to renew or revoke and nothing about the secret expires. An earlier fixture
 * here said 0, which is the KV v2 answer, and hid a bug.
 */
export function kvV1Body(data: Readonly<Record<string, unknown>>): unknown {
  return {
    request_id: 'a1b2',
    lease_id: '',
    renewable: false,
    lease_duration: 2_764_800,
    data,
  };
}

/** A dynamic secret response, where the lease is real. */
export function dynamicBody(
  data: Readonly<Record<string, unknown>>,
  overrides: { leaseId?: string; leaseDuration?: number; renewable?: boolean } = {}
): unknown {
  return {
    request_id: 'c3d4',
    lease_id: overrides.leaseId ?? 'database/creds/app-readonly/abc123',
    renewable: overrides.renewable ?? true,
    lease_duration: overrides.leaseDuration ?? 3_600,
    data,
  };
}
