import { describe, expect, it } from 'vitest';
import {
  ARGON2_DEFAULT_HASH_LENGTH,
  ARGON2_DEFAULT_MEMORY_COST,
  ARGON2_DEFAULT_PARALLELISM,
  ARGON2_DEFAULT_TIME_COST,
  ARGON2_MIN_MEMORY_COST,
  BCRYPT_DEFAULT_ROUNDS,
  BCRYPT_MAX_ROUNDS,
  BCRYPT_MIN_ROUNDS,
  SCRYPT_DEFAULT_KEY_LENGTH,
  SCRYPT_DEFAULT_N,
  planStorageHash,
} from './options.js';
import type { StorageHashOptions } from './types.js';

describe('planStorageHash', () => {
  describe('argon2', () => {
    it('applies the documented defaults', () => {
      expect(planStorageHash({ algorithm: 'argon2id' })).toEqual({
        algorithm: 'argon2id',
        memoryCost: ARGON2_DEFAULT_MEMORY_COST,
        timeCost: ARGON2_DEFAULT_TIME_COST,
        parallelism: ARGON2_DEFAULT_PARALLELISM,
        hashLength: ARGON2_DEFAULT_HASH_LENGTH,
      });
    });

    it('keeps the variant it was given', () => {
      expect(planStorageHash({ algorithm: 'argon2i' }).algorithm).toBe('argon2i');
      expect(planStorageHash({ algorithm: 'argon2d' }).algorithm).toBe('argon2d');
    });

    it('accepts parameters above the floor', () => {
      expect(planStorageHash({ algorithm: 'argon2id', memoryCost: 131_072, timeCost: 4 })).toEqual({
        algorithm: 'argon2id',
        memoryCost: 131_072,
        timeCost: 4,
        parallelism: ARGON2_DEFAULT_PARALLELISM,
        hashLength: ARGON2_DEFAULT_HASH_LENGTH,
      });
    });

    it('refuses memory below the floor rather than raising it', () => {
      expect(() => planStorageHash({ algorithm: 'argon2id', memoryCost: 1024 })).toThrow(
        RangeError
      );
      expect(() => planStorageHash({ algorithm: 'argon2id', memoryCost: 1024 })).toThrow(
        String(ARGON2_MIN_MEMORY_COST)
      );
    });

    it('refuses fewer passes than the floor', () => {
      expect(() => planStorageHash({ algorithm: 'argon2id', timeCost: 1 })).toThrow(RangeError);
    });

    it('keeps the lane count within what Argon2 accepts for the memory floor', () => {
      // Argon2 requires memoryCost >= 8 * parallelism. The floors make that
      // unreachable, and this is the case that would otherwise reach it.
      const plan = planStorageHash({ algorithm: 'argon2id', parallelism: 64 });

      expect(plan.algorithm === 'argon2id' && plan.memoryCost).toBeGreaterThanOrEqual(8 * 64);
    });

    it('refuses a fractional parameter', () => {
      expect(() => planStorageHash({ algorithm: 'argon2id', timeCost: 2.5 })).toThrow(RangeError);
    });

    it('refuses a parameter of the wrong type', () => {
      // @ts-expect-error deliberately invalid parameter
      expect(() => planStorageHash({ algorithm: 'argon2id', timeCost: '3' })).toThrow(TypeError);
    });
  });

  describe('bcrypt', () => {
    it('defaults to twelve rounds', () => {
      expect(planStorageHash({ algorithm: 'bcrypt' })).toEqual({
        algorithm: 'bcrypt',
        rounds: BCRYPT_DEFAULT_ROUNDS,
      });
    });

    it('refuses fewer rounds than the floor', () => {
      expect(() => planStorageHash({ algorithm: 'bcrypt', rounds: BCRYPT_MIN_ROUNDS - 1 })).toThrow(
        RangeError
      );
    });

    it('refuses a cost exponent that would take days', () => {
      expect(() => planStorageHash({ algorithm: 'bcrypt', rounds: BCRYPT_MAX_ROUNDS + 1 })).toThrow(
        RangeError
      );
    });
  });

  describe('scrypt', () => {
    it('applies the documented defaults and computes the memory ceiling', () => {
      expect(planStorageHash({ algorithm: 'scrypt' })).toEqual({
        algorithm: 'scrypt',
        N: SCRYPT_DEFAULT_N,
        r: 8,
        p: 1,
        keyLength: SCRYPT_DEFAULT_KEY_LENGTH,
        maxmem: 128 * SCRYPT_DEFAULT_N * 8 + 1_048_576,
      });
    });

    it('refuses a cost that is not a power of two', () => {
      expect(() => planStorageHash({ algorithm: 'scrypt', N: 20_000 })).toThrow(/power of two/);
    });

    it('refuses a cost below the floor', () => {
      expect(() => planStorageHash({ algorithm: 'scrypt', N: 8192 })).toThrow(RangeError);
    });

    it('refuses parameters that would ask for more than a gibibyte', () => {
      expect(() => planStorageHash({ algorithm: 'scrypt', N: 2 ** 22, r: 8 })).toThrow(/MiB/);
    });
  });

  describe('the algorithm itself', () => {
    it('refuses an unknown one with the list of known ones', () => {
      expect(() =>
        planStorageHash({ algorithm: 'pbkdf2' } as unknown as StorageHashOptions)
      ).toThrow(/argon2id, argon2i, argon2d, bcrypt, scrypt/);
    });

    it('refuses options that are not an object', () => {
      expect(() => planStorageHash(null as unknown as StorageHashOptions)).toThrow(TypeError);
      expect(() => planStorageHash('argon2id' as unknown as StorageHashOptions)).toThrow(TypeError);
    });
  });
});
