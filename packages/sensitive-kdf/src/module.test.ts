import { describe, expect, it } from 'vitest';
import { MissingKdfModuleError } from './errors.js';
import { loadKdfModule } from './module.js';

describe('loadKdfModule', () => {
  it('reports a module that is not installed, and how to install it', async () => {
    await expect(loadKdfModule('not-an-installed-kdf', 'Argon2')).rejects.toThrow(
      MissingKdfModuleError
    );

    const error = await loadKdfModule('not-an-installed-kdf', 'Argon2').then(
      () => {
        expect.unreachable('loading a module that is not installed must throw');
      },
      (thrown: unknown) => thrown as MissingKdfModuleError
    );

    expect(error.module).toBe('not-an-installed-kdf');
    expect(error.algorithm).toBe('Argon2');
    expect(error.message).toContain('pnpm add not-an-installed-kdf');
    expect(error.message).toContain("algorithm: 'scrypt'");
  });

  it('flattens a CommonJS module reached through a dynamic import', async () => {
    const loaded = await loadKdfModule('node:path', 'nothing');

    expect(typeof loaded['join']).toBe('function');
  });
});
