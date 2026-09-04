import { describe, it, expect } from 'vitest';
import {
  RenewalNotAllowedError,
  registerPolicy,
  resetPolicies,
} from '@platform-sec/sensitive-string-core';

import { leaseTtlMs } from './lease.js';
import { FakeTransport, dynamicBody, source } from './__tests__/fake-transport.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

describe('leaseTtlMs', () => {
  it('converts seconds to milliseconds', () => {
    // The factor is pinned here on purpose. A silent factor-of-1000 error
    // produces credentials that expire a thousand times too early, or too
    // late, and the too-late direction fails open.
    expect(leaseTtlMs(1)).toBe(1_000);
    expect(leaseTtlMs(3_600)).toBe(3_600_000);
    expect(leaseTtlMs(86_400)).toBe(86_400_000);
  });

  it('treats zero as no lease rather than as an expired value', () => {
    // A KV read returns `lease_duration: 0`. Mapping it to `ttl: 0` would
    // produce a value that is expired on arrival, because `ttl: 0` in core
    // means exactly the opposite.
    expect(leaseTtlMs(0)).toBeUndefined();
  });

  it('treats a negative duration as no lease', () => {
    expect(leaseTtlMs(-5)).toBeUndefined();
  });

  it('treats a missing or non-numeric duration as no lease', () => {
    expect(leaseTtlMs(undefined)).toBeUndefined();
    expect(leaseTtlMs('3600')).toBeUndefined();
    expect(leaseTtlMs(Number.NaN)).toBeUndefined();
    expect(leaseTtlMs(Number.POSITIVE_INFINITY)).toBeUndefined();
  });
});

describe('dynamic secrets', () => {
  function leased(overrides: Parameters<typeof dynamicBody>[1] = {}) {
    const transport = FakeTransport.of({
      'database/creds/app-readonly': {
        body: dynamicBody({ username: 'v-token-app-abc', password: CANARY }, overrides),
      },
      'sys/leases/renew': { body: { lease_duration: 7_200, renewable: true } },
      'sys/leases/revoke': { status: 204 },
    });

    return { transport, vault: source(transport) };
  }

  it('binds the lease duration to every field', async () => {
    const { vault } = leased();

    const lease = await vault.dynamic('database/creds/app-readonly');

    expect(lease.fields.get('password')?.ttlRemaining()).toBeGreaterThan(3_590_000);
    expect(lease.fields.get('password')?.ttlRemaining()).toBeLessThanOrEqual(3_600_000);
  });

  it('exposes the lease id, which is not a secret', async () => {
    const { vault } = leased();

    const lease = await vault.dynamic('database/creds/app-readonly');

    expect(lease.leaseId).toBe('database/creds/app-readonly/abc123');
  });

  it('wraps every field as a credential by default', async () => {
    const { vault } = leased();

    const lease = await vault.dynamic('database/creds/app-readonly');

    expect(lease.fields.get('username')?.klass).toBe('credential');
    expect(lease.fields.get('password')?.klass).toBe('credential');
    expect(String(lease.fields.get('password'))).not.toContain(CANARY);
  });

  it('takes a classification when the fields are not all credentials', async () => {
    const { vault } = leased();

    const lease = await vault.dynamic('database/creds/app-readonly', {
      fields: { username: 'sensitive' },
      fallback: 'credential',
    });

    expect(lease.fields.get('username')?.klass).toBe('sensitive');
  });

  describe('renewal', () => {
    it('extends the deadline and reports what Vault granted', async () => {
      const { vault, transport } = leased();

      const lease = await vault.dynamic('database/creds/app-readonly');
      const before = lease.ttlRemaining() ?? 0;
      const granted = await lease.renew();

      expect(granted).toBe(7_200_000);
      expect(lease.ttlRemaining()).toBeGreaterThan(before);
      expect(transport.requests.some((request) => request.path === 'sys/leases/renew')).toBe(true);
    });

    it('sends the increment in seconds, since the API takes seconds', async () => {
      const { vault, transport } = leased();

      const lease = await vault.dynamic('database/creds/app-readonly');
      await lease.renew(1_800_000);

      const renew = transport.requests.find((request) => request.path === 'sys/leases/renew');

      expect(renew?.body).toEqual({
        lease_id: 'database/creds/app-readonly/abc123',
        increment: 1_800,
      });
    });

    it('refuses a lease Vault says is not renewable, before any request', async () => {
      const { vault, transport } = leased({ renewable: false });

      const lease = await vault.dynamic('database/creds/app-readonly');
      transport.requests.length = 0;

      await expect(lease.renew()).rejects.toBeInstanceOf(RenewalNotAllowedError);
      expect(transport.requests).toHaveLength(0);
    });

    it('reports the refusal reason rather than swallowing it', async () => {
      const { vault } = leased({ renewable: false });

      const lease = await vault.dynamic('database/creds/app-readonly');

      try {
        await lease.renew();
        expect.unreachable('renew should have thrown');
      } catch (error) {
        expect((error as RenewalNotAllowedError).reason).toBe('policy');
      }
    });

    it('surfaces a policy that forbids renewal outright, which the lease cannot lift', async () => {
      registerPolicy(
        {
          name: 'credential',
          redact: () => '[REDACTED:credential]',
          requireConstantTimeEquals: true,
          allowRenewal: false,
        },
        { overwrite: true }
      );

      try {
        const { vault, transport } = leased();
        const lease = await vault.dynamic('database/creds/app-readonly');
        transport.requests.length = 0;

        await expect(lease.renew()).rejects.toBeInstanceOf(RenewalNotAllowedError);
        // A deployment that has forbidden renewal and is using renewable
        // leases has a configuration conflict. The error is where it becomes
        // visible, and nothing was extended upstream on the way there.
        expect(transport.requests).toHaveLength(0);
      } finally {
        resetPolicies();
      }
    });
  });

  describe('revocation', () => {
    it('invalidates locally before calling the server', async () => {
      const { vault, transport } = leased();

      const lease = await vault.dynamic('database/creds/app-readonly');
      await lease.revoke();

      const revoke = transport.requests.find((request) => request.path === 'sys/leases/revoke');

      expect(revoke?.body).toEqual({ lease_id: 'database/creds/app-readonly/abc123' });
    });

    it('leaves instances already handed out working, which is the documented gap', async () => {
      const { vault } = leased();

      const lease = await vault.dynamic('database/creds/app-readonly');
      const password = lease.fields.get('password');
      await lease.revoke();

      expect(password?.reveal({ name: 'test' })).toBe(CANARY);
    });
  });

  it('reports the header its requests authenticate with', async () => {
    const { vault } = leased();

    const lease = await vault.dynamic('database/creds/app-readonly');

    expect(lease.authHeader).toBe('X-Vault-Token');
  });
});
