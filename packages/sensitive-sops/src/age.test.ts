import { describe, it, expect } from 'vitest';
import { Decrypter, Encrypter, generateIdentity, identityToRecipient } from 'age-encryption';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { SecretPayloadError } from '@platform-sec/sensitive-string-secrets';

import { decryptAge } from './age.js';

/**
 * These run against the real `age-encryption`, not a fake.
 *
 * It is a maintained TypeScript implementation by age's own author, which is
 * the whole argument for decrypting age in process while SOPS shells out. A
 * test that faked it would be testing the argument rather than the code.
 */

const CANARY = 'LEAKED_SECRET_abc123xyz';

async function encrypted(plaintext: string): Promise<{
  ciphertext: Uint8Array;
  identity: SensitiveString<'credential'>;
}> {
  const identity = await generateIdentity();
  const recipient = await identityToRecipient(identity);
  const encrypter = new Encrypter();
  encrypter.addRecipient(recipient);

  return {
    ciphertext: await encrypter.encrypt(plaintext),
    identity: new SensitiveString(identity, 'credential', 'age-identity'),
  };
}

describe('decryptAge', () => {
  it('decrypts and wraps', async () => {
    const { ciphertext, identity } = await encrypted(CANARY);

    const secret = await decryptAge(ciphertext, {
      identity,
      decrypter: new Decrypter(),
      label: 'webhook-key',
    });

    expect(secret).toBeInstanceOf(SensitiveString);
    expect(secret.klass).toBe('credential');
    expect(secret.label).toBe('webhook-key');
    expect(secret.reveal({ name: 'test' })).toBe(CANARY);
  });

  it('redacts by default, so the plaintext never appears in a log line', async () => {
    const { ciphertext, identity } = await encrypted(CANARY);
    const secret = await decryptAge(ciphertext, { identity, decrypter: new Decrypter() });

    expect(String(secret)).not.toContain(CANARY);
    expect(JSON.stringify(secret)).not.toContain(CANARY);
  });

  it('takes a class the caller chose', async () => {
    const { ciphertext, identity } = await encrypted(CANARY);
    const secret = await decryptAge(ciphertext, {
      identity,
      decrypter: new Decrypter(),
      klass: 'sensitive',
    });

    expect(secret.klass).toBe('sensitive');
  });

  it('refuses a ciphertext no identity matches, and reports no content', async () => {
    const { ciphertext } = await encrypted(CANARY);
    const other = await generateIdentity();

    const failure = await decryptAge(ciphertext, {
      identity: new SensitiveString(other, 'credential'),
      decrypter: new Decrypter(),
      label: 'webhook-key',
    }).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(SecretPayloadError);
    expect((failure as Error).message).not.toContain(CANARY);
    expect((failure as { cause?: unknown }).cause).toBeUndefined();
  });

  it('refuses input that is not an age file at all', async () => {
    const identity = await generateIdentity();

    await expect(
      decryptAge(CANARY, {
        identity: new SensitiveString(identity, 'credential'),
        decrypter: new Decrypter(),
      })
    ).rejects.toBeInstanceOf(SecretPayloadError);
  });

  it('reveals the identity under a child context, so an ambient audit sink still sees it', async () => {
    const { ciphertext, identity } = await encrypted(CANARY);
    const reveals: string[] = [];

    const { withRevealContext } = await import('@platform-sec/sensitive-string-core');

    await withRevealContext(
      { name: 'app', auditReveal: (_value, details) => reveals.push(details.operation) },
      async () => {
        await decryptAge(ciphertext, { identity, decrypter: new Decrypter() });
      }
    );

    expect(reveals).toEqual(['reveal']);
  });
});
