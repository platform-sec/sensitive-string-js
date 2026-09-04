import { describe, it, expect } from 'vitest';

import { FLAVOR_DIVERGENCE, VaultFlavorError, checkFlavor, tokenHeader } from './flavor.js';
import { VaultSecretSource } from './source.js';
import { FakeTransport, kvV2Body, source, vaultToken } from './__tests__/fake-transport.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

describe('checkFlavor', () => {
  it('accepts a namespace under Vault', () => {
    expect(() => checkFlavor('vault', 'engineering')).not.toThrow();
  });

  it('accepts no namespace under either flavor', () => {
    expect(() => checkFlavor('vault', undefined)).not.toThrow();
    expect(() => checkFlavor('openbao', undefined)).not.toThrow();
  });

  it('throws for a namespace under OpenBao', () => {
    expect(() => checkFlavor('openbao', 'engineering')).toThrow(VaultFlavorError);
  });

  it('explains what the silent failure would have been', () => {
    // Sending X-Vault-Namespace to a server that ignores it means every read
    // resolves against the root namespace, so the caller gets the wrong secret
    // or a not-found rather than an error.
    expect(() => checkFlavor('openbao', 'engineering')).toThrow(/root namespace/);
  });
});

describe('the source constructor', () => {
  it('throws at construction rather than sending a header the server ignores', () => {
    expect(
      () =>
        new VaultSecretSource({
          transport: FakeTransport.of({}),
          token: vaultToken(),
          flavor: 'openbao',
          namespace: 'engineering',
        })
    ).toThrow(VaultFlavorError);
  });

  it('defaults to the Vault flavor', () => {
    expect(source(FakeTransport.of({})).flavor).toBe('vault');
  });

  it('names the flavor as the load event source', async () => {
    const events: { source: string }[] = [];
    const transport = FakeTransport.of({ 'kv/data/prod/db': { body: kvV2Body({ a: CANARY }) } });
    const vault = source(transport, {
      flavor: 'openbao',
      onLoad: (event) => events.push(event),
    });

    await vault.getAll('kv/prod/db', { fallback: 'credential' });

    expect(events[0]?.source).toBe('openbao');
  });

  it('needs an endpoint or a transport', () => {
    expect(() => new VaultSecretSource({ token: vaultToken() })).toThrow(/endpoint or a transport/);
  });

  it('refuses a plain-string client token', () => {
    expect(
      () =>
        new VaultSecretSource({
          transport: FakeTransport.of({}),
          token: 'hvs.plain' as unknown as ReturnType<typeof vaultToken>,
        })
    ).toThrow(/SensitiveString/);
  });
});

describe('the token header', () => {
  it('is the compatible one for both flavors', () => {
    expect(tokenHeader('vault')).toBe('X-Vault-Token');
    expect(tokenHeader('openbao')).toBe('X-Vault-Token');
  });

  it('is sent on every request', async () => {
    const transport = FakeTransport.of({ 'kv/data/prod/db': { body: kvV2Body({ a: 'b' }) } });
    const vault = source(transport, { flavor: 'openbao' });

    await vault.getAll('kv/prod/db', { fallback: 'credential' });

    expect(transport.requests[0]?.headers['X-Vault-Token']).toBeDefined();
  });

  it('sends the namespace header only where one was configured', async () => {
    const transport = FakeTransport.of({ 'kv/data/prod/db': { body: kvV2Body({ a: 'b' }) } });

    await source(transport).getAll('kv/prod/db', { fallback: 'credential' });
    await source(transport, { namespace: 'engineering' }).getAll('kv/prod/db', {
      fallback: 'credential',
    });

    expect(transport.requests[0]?.headers['X-Vault-Namespace']).toBeUndefined();
    expect(transport.requests[1]?.headers['X-Vault-Namespace']).toBe('engineering');
  });
});

describe('the divergence table', () => {
  it('covers the areas the compatibility claim rests on', () => {
    expect(FLAVOR_DIVERGENCE.map((row) => row.area)).toEqual([
      'Namespaces',
      'Token header',
      'KV v2 read shape',
      'Response wrapping',
      'Version reporting',
      'Enterprise-only backends',
    ]);
  });

  it('says how each divergence is handled', () => {
    for (const row of FLAVOR_DIVERGENCE) {
      expect(row.handling.length).toBeGreaterThan(0);
    }
  });

  it('names the versions every row that describes a behaviour was checked against', () => {
    // A row with no version is a row nobody has checked. The only such row is
    // the one about backends this package does not touch, which has no
    // behaviour to check.
    const unverified = FLAVOR_DIVERGENCE.filter((row) => row.verified === undefined);

    expect(unverified.map((row) => row.area)).toEqual(['Enterprise-only backends']);
  });

  it('records that X-Bao-Token is refused rather than an accepted alias', () => {
    const row = FLAVOR_DIVERGENCE.find((entry) => entry.area === 'Token header');

    expect(row?.openbao).toContain('403');
  });

  it('records that Vault Community ignores the namespace header', () => {
    // The silent wrong-secret case turned out to be Vault Community rather
    // than OpenBao, which answers 404 instead.
    const row = FLAVOR_DIVERGENCE.find((entry) => entry.area === 'Namespaces');

    expect(row?.vault).toContain('Community Edition ignores the header');
    expect(row?.openbao).toContain('404');
  });
});

describe('flavor never switches behaviour on a server response', () => {
  it('records the flavor on metadata rather than reading it back from the server', async () => {
    const transport = FakeTransport.of({ 'kv/data/prod/db': { body: kvV2Body({ a: 'b' }) } });
    const vault = source(transport, { flavor: 'openbao' });

    const record = await vault.getAll('kv/prod/db', { fallback: 'credential' });

    expect(record.ref.metadata['flavor']).toBe('openbao');
  });
});
