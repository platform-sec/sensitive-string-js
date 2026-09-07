import { describe, expect, it } from 'vitest';
import { UnknownStoredHashError } from './errors.js';
import { readStoredParameters } from './parameters.js';

describe('readStoredParameters', () => {
  describe('argon2', () => {
    const stored = '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHRzYWx0$c29tZWhhc2hoYXNoaGFzaA';

    it('reads the variant and the cost', () => {
      expect(readStoredParameters(stored)).toEqual({
        algorithm: 'argon2id',
        memoryCost: 65_536,
        timeCost: 3,
        parallelism: 4,
        hashLength: 16,
      });
    });

    it('reads the other two variants', () => {
      expect(readStoredParameters(stored.replace('argon2id', 'argon2i')).algorithm).toBe('argon2i');
      expect(readStoredParameters(stored.replace('argon2id', 'argon2d')).algorithm).toBe('argon2d');
    });

    it('reads a hash written before the version field existed', () => {
      expect(readStoredParameters(stored.replace('v=19$', '')).memoryCost).toBe(65_536);
    });

    it('tolerates the optional parameters the format allows', () => {
      const withKeyId = stored.replace('p=4$', 'p=4,keyid=Zm9v$');

      expect(readStoredParameters(withKeyId).timeCost).toBe(3);
    });
  });

  describe('bcrypt', () => {
    const stored = `$2b$12$${'a'.repeat(53)}`;

    it('reads the cost', () => {
      expect(readStoredParameters(stored)).toEqual({
        algorithm: 'bcrypt',
        rounds: 12,
        hashLength: 23,
      });
    });

    it('reads every variant tag in use', () => {
      for (const tag of ['2a', '2b', '2x', '2y']) {
        expect(readStoredParameters(`$${tag}$10$${'a'.repeat(53)}`).rounds).toBe(10);
      }
    });
  });

  describe('scrypt', () => {
    it('reads the cost as N, not as the exponent the string carries', () => {
      const stored = '$scrypt$ln=14,r=8,p=1$c29tZXNhbHRzYWx0$c29tZWhhc2hoYXNoaGFzaA';

      expect(readStoredParameters(stored)).toEqual({
        algorithm: 'scrypt',
        N: 16_384,
        r: 8,
        p: 1,
        hashLength: 16,
      });
    });
  });

  describe('anything else', () => {
    const rejected: [string, string][] = [
      ['an empty string', ''],
      ['a plain digest', 'a'.repeat(64)],
      ['a truncated argon2 hash', '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ'],
      ['a bcrypt hash of the wrong length', '$2b$12$tooshort'],
      ['a bcrypt cost that is not two digits', `$2b$4$${'a'.repeat(53)}`],
      ['an argon2 variant that does not exist', '$argon2z$m=65536,t=3,p=4$c2FsdA$aGFzaA'],
      ['scrypt written with N instead of ln', '$scrypt$N=16384,r=8,p=1$c2FsdA$aGFzaA'],
      ['an unbounded memory cost', '$argon2id$m=99999999999999,t=3,p=4$c2FsdA$aGFzaA'],
    ];

    for (const [name, stored] of rejected) {
      it(`refuses ${name}`, () => {
        expect(() => readStoredParameters(stored)).toThrow(UnknownStoredHashError);
      });
    }

    it('never repeats what it refused', () => {
      try {
        readStoredParameters('STORED_HASH_CANARY');
        expect.unreachable('the parse must refuse');
      } catch (error) {
        expect(String(error)).not.toContain('STORED_HASH_CANARY');
      }
    });
  });
});
