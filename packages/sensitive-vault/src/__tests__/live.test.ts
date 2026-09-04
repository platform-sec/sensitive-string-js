import { describe, it, expect, beforeAll } from 'vitest';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { putJson } from '@platform-sec/sensitive-string-secrets/write';

import { VaultSecretSource } from '../source.js';
import { fetchTransport } from '../transport.js';
import type { VaultFlavor } from '../flavor.js';

/**
 * The second tier: the same assertions against a real server.
 *
 * A fork diverges, and a compatibility claim made once is a claim that rots.
 * The unit suite runs against recorded fixtures and proves this package reads
 * what it believes Vault sends; this file proves that is what Vault sends. CI
 * runs it as a matrix over a Vault container and an OpenBao container, and it
 * skips itself everywhere else, so nothing here is required for `pnpm test` to
 * pass locally.
 *
 * Point it at a dev-mode server:
 *
 * ```
 * docker run -d -p 8200:8200 -e VAULT_DEV_ROOT_TOKEN_ID=root \
 *   --cap-add=IPC_LOCK hashicorp/vault:latest
 * VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root VAULT_FLAVOR=vault pnpm test
 * ```
 */

const ADDR = process.env['VAULT_ADDR'];
const TOKEN = process.env['VAULT_TOKEN'];
const FLAVOR = (process.env['VAULT_FLAVOR'] ?? 'vault') as VaultFlavor;

const CANARY = 'LEAKED_SECRET_abc123xyz';

/** The dev-mode KV v2 mount, which both servers create at the same path. */
const MOUNT = 'secret';

function live(token = TOKEN ?? ''): VaultSecretSource {
  return new VaultSecretSource({
    endpoint: ADDR ?? '',
    token: new SensitiveString(token, 'credential', 'vault-token'),
    flavor: FLAVOR,
    mounts: [{ path: MOUNT, kv: 2 }],
    cache: { ttl: 0 },
  });
}

describe.skipIf(ADDR === undefined || TOKEN === undefined)(`${FLAVOR}, live`, () => {
  const path = `${MOUNT}/sensitive-string-live`;
  let version = 'unknown';

  beforeAll(async () => {
    // Recorded rather than asserted. The version is what turns the
    // compatibility table's empty column into a claim somebody checked.
    const transport = fetchTransport({ endpoint: ADDR ?? '' });
    const health = await transport.request({ method: 'GET', path: 'sys/health', headers: {} });
    const reported = (health.body as { version?: unknown }).version;
    version = typeof reported === 'string' ? reported : 'unknown';

    process.stdout.write(`\n[live] ${FLAVOR} reports version ${version}\n`);
  });

  it('accepts X-Vault-Token as the auth header', async () => {
    const vault = live();

    await putJson(
      vault,
      path,
      { username: 'app', password: new SensitiveString(CANARY, 'credential') },
      { context: { name: 'live-test', reason: 'seed the fixture' } }
    );

    // The write already went through with that header, and the read-back with
    // it too, so this asserts what the divergence table's token header row
    // claims for whichever server is running.
    expect(version).not.toBe('');
  });

  it('reads back what it wrote, through the KV v2 shape', async () => {
    const vault = live();

    const record = await vault.getJson(path, {
      fields: { username: 'sensitive', password: 'credential' },
    });

    expect(record.fields.password.reveal({ name: 'live-test' })).toBe(CANARY);
    expect(record.fields.username.klass).toBe('sensitive');
    expect(record.fields.password.label).toBe(`${path}#password`);
  });

  it('reports a concrete version rather than an alias', async () => {
    const vault = live();

    const record = await vault.getAll(path, { fallback: 'credential' });

    expect(record.ref.version).toMatch(/^\d+$/);
  });

  it('reports a KV read as having no lease, so nothing is bound', async () => {
    const vault = live();

    const record = await vault.getAll(path, { fallback: 'credential' });

    for (const value of record.fields.values()) {
      expect(value.expiresAt).toBeUndefined();
    }
  });

  it('reports an absent path as absence rather than as a failure', async () => {
    const vault = live();

    await expect(vault.getOptional(`${MOUNT}/definitely-not-here`)).resolves.toBeNull();
  });

  it('binds a real lease to a child token, converted from seconds', async () => {
    const transport = fetchTransport({ endpoint: ADDR ?? '' });
    const created = await transport.request({
      method: 'POST',
      path: 'auth/token/create',
      headers: { 'X-Vault-Token': TOKEN ?? '' },
      body: { ttl: '60s', renewable: true, policies: ['root'] },
    });

    const auth = (created.body as { auth: { client_token: string; lease_duration: number } }).auth;

    expect(auth.lease_duration).toBe(60);

    const granted = await live(auth.client_token).renewToken(120_000);

    // Seconds in, milliseconds out, through the one named converter.
    expect(granted).toBeGreaterThanOrEqual(60_000);
  });

  it('returns a wrapping token instead of the value, and unwraps it', async () => {
    const vault = live();

    const wrapped = await vault.getWrapped(path, 60);

    expect(wrapped.token.klass).toBe('credential');
    expect(wrapped.ttlSeconds).toBe(60);
    expect(wrapped.token.ttlRemaining()).toBeLessThanOrEqual(60_000);

    const unwrapped = await vault.unwrap(wrapped.token, { fallback: 'credential' }, path);
    const data = unwrapped.fields.get('data.password');

    expect(data?.reveal({ name: 'live-test' })).toBe(CANARY);
  });

  it('binds no deadline from a real KV v1 read, whose lease_duration is not one', async () => {
    // This is the case the fixtures got wrong until a real server was asked.
    // A KV v1 read reports the mount's default TTL with an empty lease id, so
    // it looks like a month-long lease and expires nothing.
    const transport = fetchTransport({ endpoint: ADDR ?? '' });
    const headers = { 'X-Vault-Token': TOKEN ?? '' };
    const v1Path = 'sensitive-string-kv1/prod';

    await transport
      .request({
        method: 'POST',
        path: 'sys/mounts/sensitive-string-kv1',
        headers,
        body: { type: 'kv', options: { version: '1' } },
      })
      .catch(() => undefined); // already mounted on a re-run

    await transport.request({ method: 'POST', path: v1Path, headers, body: { password: CANARY } });

    const raw = await transport.request({ method: 'GET', path: v1Path, headers });
    const envelope = raw.body as { lease_duration: number; lease_id: string };

    expect(envelope.lease_duration).toBeGreaterThan(0);
    expect(envelope.lease_id).toBe('');

    const vault = new VaultSecretSource({
      endpoint: ADDR ?? '',
      token: new SensitiveString(TOKEN ?? '', 'credential', 'vault-token'),
      flavor: FLAVOR,
      mounts: [{ path: 'sensitive-string-kv1', kv: 1 }],
      cache: { ttl: 0 },
    });

    const record = await vault.getAll(v1Path, { fallback: 'credential' });

    expect(record.ref.version).toBe('unversioned');

    for (const value of record.fields.values()) {
      expect(value.expiresAt).toBeUndefined();
    }

    // A KV v1 write reports no version, so a read-back that pinned one would
    // pin a placeholder. Reading the current version is what makes this work
    // against a store that overwrites in place.
    await putJson(
      vault,
      v1Path,
      { password: new SensitiveString(`${CANARY}-rotated`, 'credential') },
      { context: { name: 'live-test', reason: 'rotate' } }
    );

    const rotated = await vault.getAll(v1Path, { fallback: 'credential' });

    expect(rotated.fields.get('password')?.reveal({ name: 'live-test' })).toBe(`${CANARY}-rotated`);
  });

  it('takes X-Vault-Token and nothing else, on both servers', async () => {
    // Measured rather than assumed. OpenBao 2.6.2 answers 403 to
    // `X-Bao-Token`, so the alias the design expected is not one this package
    // can send: `X-Vault-Token` is the compatible header because it is the
    // only accepted header, not because it is one of two.
    const transport = fetchTransport({ endpoint: ADDR ?? '' });

    await expect(
      transport.request({
        method: 'GET',
        path: `${MOUNT}/data/sensitive-string-live`,
        headers: { 'X-Bao-Token': TOKEN ?? '' },
      })
    ).rejects.toMatchObject({ status: 403 });

    await expect(
      transport.request({
        method: 'GET',
        path: `${MOUNT}/data/sensitive-string-live`,
        headers: { 'X-Vault-Token': TOKEN ?? '' },
      })
    ).resolves.toMatchObject({ status: 200 });
  });

  it('changes the answer when a namespace header reaches a server without namespaces', async () => {
    const transport = fetchTransport({ endpoint: ADDR ?? '' });
    const request = {
      method: 'GET' as const,
      path: `${MOUNT}/data/sensitive-string-live`,
      headers: { 'X-Vault-Token': TOKEN ?? '', 'X-Vault-Namespace': 'engineering' },
    };

    if (FLAVOR === 'openbao') {
      // OpenBao 2.6.2 does not ignore the header: the read that answered 200
      // without it answers 404 with it. Either way the caller does not get the
      // secret they asked for, which is why the constructor refuses.
      await expect(transport.request(request)).rejects.toMatchObject({ status: 404 });

      return;
    }

    // Vault 1.21.4 Community Edition ignores the header and serves the root
    // namespace, which is the silent wrong-secret case rather than a failure.
    // This package cannot tell Community from Enterprise without asking the
    // server, and letting a response decide how the client behaves is the
    // thing the flavor flag exists to avoid, so the risk is documented rather
    // than detected.
    await expect(transport.request(request)).resolves.toMatchObject({ status: 200 });
  });

  it('refuses a namespace under OpenBao and accepts one under Vault', () => {
    if (FLAVOR === 'openbao') {
      expect(() => live()).not.toThrow();
      expect(
        () =>
          new VaultSecretSource({
            endpoint: ADDR ?? '',
            token: new SensitiveString(TOKEN ?? '', 'credential'),
            flavor: 'openbao',
            namespace: 'engineering',
          })
      ).toThrow(/OpenBao has no namespaces/);

      return;
    }

    expect(
      () =>
        new VaultSecretSource({
          endpoint: ADDR ?? '',
          token: new SensitiveString(TOKEN ?? '', 'credential'),
          flavor: 'vault',
          namespace: 'engineering',
        })
    ).not.toThrow();
  });
});
