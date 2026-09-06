/**
 * KDF Security Tests
 *
 * A stored hash is what an attacker gets when the database leaks, so the
 * properties that matter are that the password is not recoverable from it, that
 * it is protected on the way to the column, and that a wrong password is
 * answered `false` rather than reported as a fault or, worse, accepted.
 */

import { describe, expect, it } from 'vitest';
import * as util from 'node:util';
import {
  SensitiveString,
  containsSensitive,
  safeStringify,
  withRevealContext,
} from '@platform-sec/sensitive-string-core';
import { createTestSecret, expectNotLeaked } from '@platform-sec/sensitive-string-testing';

import { hashForStorage, verifyHash } from '../index.js';
import { hasArgon2, hasBcrypt } from './optional-modules.js';
import type { StorageHashOptions } from '../types.js';

const CANARY = 'KDF_SECURITY_CANARY_5e2a91';

const ALGORITHMS: [name: string, options: StorageHashOptions, available: boolean][] = [
  [
    'argon2id',
    { algorithm: 'argon2id', memoryCost: 19_456, timeCost: 2, parallelism: 1 },
    hasArgon2,
  ],
  ['bcrypt', { algorithm: 'bcrypt', rounds: 10 }, hasBcrypt],
  ['scrypt', { algorithm: 'scrypt' }, true],
];

describe('KDF security', () => {
  for (const [name, options, available] of ALGORITHMS) {
    describe.skipIf(!available)(name, () => {
      it('does not carry the password into the stored hash', async () => {
        const stored = await hashForStorage(CANARY, options);

        expect(stored.reveal()).not.toContain(CANARY);
        expect(Buffer.from(stored.reveal(), 'utf8').includes(CANARY)).toBe(false);
      });

      it('does not carry the password into anything the hash renders as', async () => {
        const password = new SensitiveString(CANARY, 'credential', 'password');
        const stored = await hashForStorage(password, options);

        expectNotLeaked(password, String(stored));
        expectNotLeaked(password, util.inspect(stored));
        expectNotLeaked(password, safeStringify({ user: { password: stored } }));
        expect(JSON.stringify({ stored })).not.toContain(CANARY);
      });

      it('leaves the stored hash detectable as a protected value', async () => {
        const stored = await hashForStorage(CANARY, options);

        expect(containsSensitive({ password: stored })).toBe(true);
      });

      it('answers false for a wrong password rather than throwing', async () => {
        const stored = await hashForStorage(CANARY, options);

        expect(await verifyHash(stored, `${CANARY}x`)).toBe(false);
        expect(await verifyHash(stored, '')).toBe(false);
      });

      it('does not verify against a hash of a different password', async () => {
        const mine = await hashForStorage(CANARY, options);
        const theirs = await hashForStorage('a different password', options);

        expect(await verifyHash(theirs, CANARY)).toBe(false);
        expect(await verifyHash(mine, 'a different password')).toBe(false);
      });

      it('does not leak the password through a failed verification', async () => {
        const stored = await hashForStorage(CANARY, options);

        expect(await verifyHash(stored, 'wrong')).toBe(false);
        expect(stored.reveal()).not.toContain('wrong');
      });
    });
  }

  describe('the audit trail', () => {
    it('records hashing a password as the exposure it is', async () => {
      const seen: string[] = [];
      const password = createTestSecret('credential', 'password');

      await withRevealContext(
        { name: 'signup', auditReveal: (value) => void seen.push(String(value.label)) },
        async () => {
          await hashForStorage(password, { algorithm: 'scrypt' });
        }
      );

      expect(seen).toEqual(['password']);
    });

    it('records both reads a verification makes, and nothing of the password', async () => {
      const records: { label: string | undefined; details: unknown }[] = [];
      const password = new SensitiveString(CANARY, 'credential', 'password');
      const stored = await hashForStorage(CANARY, { algorithm: 'scrypt' });

      await withRevealContext(
        {
          name: 'login',
          auditReveal: (value, details) => void records.push({ label: value.label, details }),
        },
        async () => {
          expect(await verifyHash(stored, password)).toBe(true);
        }
      );

      expect(JSON.stringify(records)).not.toContain(CANARY);
      // The stored hash first and the attempt second, which is the order that
      // keeps an unreadable hash from costing the attempt an exposure.
      expect(records.map((record) => record.label)).toEqual(['stored', 'password']);
    });
  });

  describe('what the stored hash is', () => {
    it('is a credential even when the password was not', async () => {
      const password = new SensitiveString(CANARY, 'sensitive', 'answer');

      expect((await hashForStorage(password, { algorithm: 'scrypt' })).klass).toBe('credential');
    });

    it('is independent of the password, which is what lets it outlive it', async () => {
      // The one place this package parts from every other derivation in the
      // library. A salted, memory-hard hash is not a reversible copy of the
      // password, and a login handler has to read it after the password's own
      // lifetime is over.
      const password = new SensitiveString(CANARY, 'credential', 'password', { maxReveals: 1 });
      const stored = await hashForStorage(password, { algorithm: 'scrypt' });

      expect(stored.isExhausted()).toBe(false);
      expect(stored.reveal()).toMatch(/^\$scrypt\$/);
      expect(await verifyHash(stored, CANARY)).toBe(true);
    });
  });
});
