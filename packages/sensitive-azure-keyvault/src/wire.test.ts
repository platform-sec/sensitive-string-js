import { describe, it, expect } from 'vitest';
import type { SecretProperties } from '@azure/keyvault-secrets';

import {
  SecretNotYetValidError,
  assertActive,
  azureLifetime,
  azureMetadata,
  azureResolvedRef,
  parseSecretIdentifier,
} from './wire.js';
import { VAULT_URL, keyVaultSecret } from './__tests__/fake-client.js';

const NOW = new Date('2026-09-03T00:00:00Z');

function properties(overrides: Partial<SecretProperties> = {}): SecretProperties {
  return { vaultUrl: VAULT_URL, name: 'payments-api-key', version: 'v1', ...overrides };
}

describe('parseSecretIdentifier', () => {
  it('keeps a bare name as it is', () => {
    expect(parseSecretIdentifier('payments-api-key')).toEqual({
      name: 'payments-api-key',
      version: undefined,
    });
  });

  it('reduces a secret identifier to the name, so no label names the tenant', () => {
    const parsed = parseSecretIdentifier(`${VAULT_URL}/secrets/payments-api-key`);

    expect(parsed.name).toBe('payments-api-key');
    expect(parsed.name).not.toContain('contoso');
  });

  it('keeps the version an identifier pins rather than dropping it', () => {
    // Dropping it would serve the current secret to a caller who asked for a
    // specific one, with nothing saying so.
    expect(parseSecretIdentifier(`${VAULT_URL}/secrets/payments-api-key/abc123`)).toEqual({
      name: 'payments-api-key',
      version: 'abc123',
    });
  });
});

describe('azureMetadata', () => {
  it('records the vault URL, which names the tenant, off the label', () => {
    const metadata = azureMetadata(properties());

    expect(metadata['vaultUrl']).toBe(VAULT_URL);
  });

  it('surfaces contentType without acting on it', () => {
    expect(azureMetadata(properties({ contentType: 'application/json' }))['contentType']).toBe(
      'application/json'
    );
  });

  it('flattens tags under a prefix so they cannot collide with a field of its own', () => {
    const metadata = azureMetadata(properties({ tags: { owner: 'payments', env: 'prod' } }));

    expect(metadata['tag.owner']).toBe('payments');
    expect(metadata['tag.env']).toBe('prod');
  });

  it('records the dates as ISO strings', () => {
    const metadata = azureMetadata(
      properties({ expiresOn: new Date('2026-12-01T00:00:00Z'), notBefore: NOW })
    );

    expect(metadata['expiresAt']).toBe('2026-12-01T00:00:00.000Z');
    expect(metadata['notBefore']).toBe('2026-09-03T00:00:00.000Z');
  });
});

describe('azureLifetime', () => {
  it('binds expiresOn as a deadline', () => {
    const expiresOn = new Date('2026-12-01T00:00:00Z');

    expect(azureLifetime(properties({ expiresOn }), true)).toEqual({ expiresAt: expiresOn });
  });

  it('binds nothing when the deployment opted out', () => {
    expect(azureLifetime(properties({ expiresOn: new Date() }), false)).toBeUndefined();
  });

  it('binds nothing when the secret has no expiry', () => {
    expect(azureLifetime(properties(), true)).toBeUndefined();
  });
});

describe('assertActive', () => {
  const ref = { path: 'payments-api-key', version: 'v1', metadata: {} };

  it('passes a secret whose notBefore has arrived', () => {
    expect(() =>
      assertActive(properties({ notBefore: new Date('2026-01-01T00:00:00Z') }), ref, NOW)
    ).not.toThrow();
  });

  it('refuses a future-dated secret and names the date', () => {
    const notBefore = new Date('2027-01-01T00:00:00Z');

    try {
      assertActive(properties({ notBefore }), ref, NOW);
      expect.unreachable('the secret should have been refused');
    } catch (error) {
      expect(error).toBeInstanceOf(SecretNotYetValidError);
      expect((error as SecretNotYetValidError).notBefore).toEqual(notBefore);
      expect((error as Error).message).toContain('2027-01-01');
    }
  });
});

describe('azureResolvedRef', () => {
  it('reports the name as the path and the concrete version', () => {
    const resolved = azureResolvedRef(keyVaultSecret('payments-api-key', { value: 'x' }, 'v9'));

    expect(resolved.path).toBe('payments-api-key');
    expect(resolved.version).toBe('v9');
  });
});
