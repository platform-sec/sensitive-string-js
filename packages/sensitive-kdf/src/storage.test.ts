import { describe, expect, it } from 'vitest';
import { randomBytes, scryptSync } from 'node:crypto';
import {
  RevealLimitExceededError,
  RevokedSensitiveValueError,
  SensitiveString,
  withRevealContext,
} from '@platform-sec/sensitive-string-core';
import type { RevealDetails } from '@platform-sec/sensitive-string-core';

import { UnknownStoredHashError } from './errors.js';
import { hashForStorage, verifyHash } from './index.js';
import { hasArgon2, hasBcrypt } from './__tests__/optional-modules.js';
import type { StorageHashOptions } from './types.js';

const PASSWORD = 'correct horse battery staple';

/** Base64 without padding, which is what the PHC format uses. */
const b64 = (bytes: Buffer): string => bytes.toString('base64').replace(/=+$/, '');

/** Deliberately at the floor rather than at the default: these run on every test run. */
const ARGON2_FAST: StorageHashOptions = {
  algorithm: 'argon2id',
  memoryCost: 19_456,
  timeCost: 2,
  parallelism: 1,
};
const BCRYPT_FAST: StorageHashOptions = { algorithm: 'bcrypt', rounds: 10 };
const SCRYPT: StorageHashOptions = { algorithm: 'scrypt' };

const ALGORITHMS: [name: string, options: StorageHashOptions, available: boolean][] = [
  ['argon2id', ARGON2_FAST, hasArgon2],
  ['bcrypt', BCRYPT_FAST, hasBcrypt],
  ['scrypt', SCRYPT, true],
];

describe('hashForStorage and verifyHash', () => {
  for (const [name, options, available] of ALGORITHMS) {
    describe.skipIf(!available)(name, () => {
      it('verifies the password it was given', async () => {
        const stored = await hashForStorage(PASSWORD, options);

        expect(await verifyHash(stored, PASSWORD)).toBe(true);
      });

      it('refuses a password that differs by one character', async () => {
        const stored = await hashForStorage(PASSWORD, options);

        expect(await verifyHash(stored, `${PASSWORD}!`)).toBe(false);
        expect(await verifyHash(stored, PASSWORD.toUpperCase())).toBe(false);
      });

      it('salts, so the same password twice gives two hashes', async () => {
        const first = await hashForStorage(PASSWORD, options);
        const second = await hashForStorage(PASSWORD, options);

        expect(first.reveal()).not.toBe(second.reveal());
        expect(await verifyHash(second, PASSWORD)).toBe(true);
      });

      it('does not contain the password', async () => {
        const stored = await hashForStorage(PASSWORD, options);

        expect(stored.reveal()).not.toContain(PASSWORD);
        expect(stored.reveal()).not.toContain('correct horse');
      });

      it('produces a credential, whatever the password was classed as', async () => {
        const password = new SensitiveString(PASSWORD, 'sensitive', 'password');
        const stored = await hashForStorage(password, options);

        expect(stored.klass).toBe('credential');
        expect(String(stored)).toBe('[REDACTED:credential]');
      });

      it('labels the hash after the password it came from', async () => {
        const password = new SensitiveString(PASSWORD, 'credential', 'password');

        expect((await hashForStorage(password, options)).label).toBe('password:stored');
        expect((await hashForStorage(PASSWORD, options)).label).toBe('stored');
      });

      it('accepts a protected password on the verifying side too', async () => {
        const stored = await hashForStorage(PASSWORD, options);
        const attempt = new SensitiveString(PASSWORD, 'credential', 'password');

        expect(await verifyHash(stored, attempt)).toBe(true);
      });

      it('verifies a hash that arrived as a plain string from a database row', async () => {
        const stored = await hashForStorage(PASSWORD, options);

        expect(await verifyHash(stored.reveal(), PASSWORD)).toBe(true);
      });

      it('handles a password of non-ASCII characters', async () => {
        const password = 'pässwörd-ünïcodé';
        const stored = await hashForStorage(password, options);

        expect(await verifyHash(stored, password)).toBe(true);
        expect(await verifyHash(stored, 'passwörd-ünïcodé')).toBe(false);
      });
    });
  }

  describe('scrypt without any native module', () => {
    it('writes a PHC string naming its parameters', async () => {
      const stored = await hashForStorage(PASSWORD, { algorithm: 'scrypt' });

      expect(stored.reveal()).toMatch(/^\$scrypt\$ln=14,r=8,p=1\$[^$]+\$[^$]+$/);
    });

    it('verifies a hash written under weaker parameters than it would produce', async () => {
      // A store hashed years ago, under parameters this package now refuses to
      // produce. The parameters come from the string, so it still verifies,
      // and the application can rehash on the next successful login.
      const salt = randomBytes(16);
      const legacy = scryptSync(PASSWORD, salt, 64, { N: 1024, r: 8, p: 1 });
      const stored = `$scrypt$ln=10,r=8,p=1$${b64(salt)}$${b64(legacy)}`;

      expect(await verifyHash(stored, PASSWORD)).toBe(true);
      expect(await verifyHash(stored, 'wrong')).toBe(false);
    });

    it('writes a hash another scrypt implementation can check', async () => {
      const stored = (await hashForStorage(PASSWORD, { algorithm: 'scrypt' })).reveal();
      const [, , parameters, saltSegment, hashSegment] = stored.split('$');
      const [ln, r, p] = (parameters ?? '').split(',').map((part) => Number(part.split('=')[1]));

      const recomputed = scryptSync(
        PASSWORD,
        Buffer.from(saltSegment ?? '', 'base64'),
        Buffer.from(hashSegment ?? '', 'base64').length,
        { N: 2 ** (ln ?? 0), r, p }
      );

      expect(b64(recomputed)).toBe(hashSegment);
    });
  });

  describe('reading the stored hash', () => {
    it('refuses a string that is no hash at all', async () => {
      await expect(verifyHash('not a hash', PASSWORD)).rejects.toThrow(UnknownStoredHashError);
    });

    it('refuses an empty string', async () => {
      await expect(verifyHash('', PASSWORD)).rejects.toThrow(UnknownStoredHashError);
    });

    it('refuses a truncated scrypt hash rather than answering false', async () => {
      await expect(verifyHash('$scrypt$ln=14,r=8,p=1$c2FsdA', PASSWORD)).rejects.toThrow(
        UnknownStoredHashError
      );
    });

    it.skipIf(!hasBcrypt)(
      'refuses a malformed bcrypt hash rather than answering false',
      async () => {
        await expect(verifyHash('$2b$10$tooshort', PASSWORD)).rejects.toThrow(
          UnknownStoredHashError
        );
      }
    );

    it.skipIf(!hasArgon2)(
      'refuses a malformed argon2 hash rather than answering false',
      async () => {
        await expect(verifyHash('$argon2id$not-a-hash', PASSWORD)).rejects.toThrow(
          UnknownStoredHashError
        );
      }
    );

    it('does not repeat the hash it could not read', async () => {
      const error = await verifyHash('STORED_HASH_CANARY', PASSWORD).then(
        () => {
          expect.unreachable('verifyHash must refuse a hash it cannot read');
        },
        (thrown: unknown) => thrown
      );

      expect(error).toBeInstanceOf(UnknownStoredHashError);
      expect(String(error)).not.toContain('STORED_HASH_CANARY');
    });
  });

  describe('bcrypt and its 72 byte limit', () => {
    it.skipIf(!hasBcrypt)('refuses a password bcrypt would truncate', async () => {
      await expect(hashForStorage('a'.repeat(73), BCRYPT_FAST)).rejects.toThrow(RangeError);
    });

    it.skipIf(!hasBcrypt)('counts bytes rather than characters', async () => {
      // 40 two-byte characters is 80 bytes, well inside 72 characters.
      await expect(hashForStorage('é'.repeat(40), BCRYPT_FAST)).rejects.toThrow(/72 bytes/);
    });

    it.skipIf(!hasBcrypt)('refuses the long password on the verifying side too', async () => {
      const stored = await hashForStorage('a'.repeat(72), BCRYPT_FAST);

      // Without this, a password sharing the registered one's first 72 bytes
      // verifies, which is the bypass the hashing side refuses to create.
      await expect(verifyHash(stored, `${'a'.repeat(72)}DIFFERENT`)).rejects.toThrow(
        /first 72 bytes/
      );
    });

    it('lets the other algorithms hash a long passphrase', async () => {
      const long = 'a'.repeat(200);
      const stored = await hashForStorage(long, SCRYPT);

      expect(await verifyHash(stored, long)).toBe(true);
      expect(await verifyHash(stored, `${long}x`)).toBe(false);
    });
  });

  describe('the value it reads', () => {
    it('goes through the gate, so a revoked password cannot be hashed', async () => {
      const password = new SensitiveString(PASSWORD, 'credential', 'password');
      password.revoke('rotated');

      await expect(hashForStorage(password, SCRYPT)).rejects.toThrow(RevokedSensitiveValueError);
    });

    it('counts against a reveal budget', async () => {
      const password = new SensitiveString(PASSWORD, 'credential', 'password', { maxReveals: 1 });

      await hashForStorage(password, SCRYPT);

      await expect(hashForStorage(password, SCRYPT)).rejects.toThrow(RevealLimitExceededError);
    });

    it('audits the exposure', async () => {
      const records: RevealDetails[] = [];

      await withRevealContext(
        { name: 'signup', auditReveal: (_value, details) => void records.push(details) },
        async () => {
          const password = new SensitiveString(PASSWORD, 'credential', 'password');
          await hashForStorage(password, SCRYPT);
        }
      );

      expect(records).toEqual([{ operation: 'reveal' }]);
    });

    it('refuses a value that is neither a string nor a SensitiveString', async () => {
      await expect(hashForStorage(42 as unknown as string, SCRYPT)).rejects.toThrow(TypeError);
    });

    it('rejects impossible parameters before reading the password', async () => {
      const password = new SensitiveString(PASSWORD, 'credential', 'password');

      await expect(hashForStorage(password, { algorithm: 'scrypt', N: 3 })).rejects.toThrow(
        RangeError
      );
      expect(password.revealCount).toBe(0);
    });

    it('reads the stored hash before the password, so an unreadable hash costs nothing', async () => {
      const attempt = new SensitiveString(PASSWORD, 'credential', 'password');

      await expect(verifyHash('not a hash', attempt)).rejects.toThrow(UnknownStoredHashError);
      expect(attempt.revealCount).toBe(0);
    });
  });
});
