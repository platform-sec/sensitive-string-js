import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createHash, createHmac, randomBytes } from 'node:crypto';
import {
  ExpiredSensitiveValueError,
  RevealLimitExceededError,
  RevokedSensitiveValueError,
  SensitiveString,
  registerPolicy,
  resetPolicies,
  withRevealContext,
} from './index.js';
import type { RevealDetails } from './index.js';

const sensitive = (value: string, label?: string) => new SensitiveString(value, 'sensitive', label);
const credential = (value: string, label?: string) =>
  new SensitiveString(value, 'credential', label);

/** Long enough to clear the 16-byte key floor. */
const KEY = 'k'.repeat(32);

const sha256 = (value: string): string => createHash('sha256').update(value, 'utf8').digest('hex');

describe('SensitiveString.hash', () => {
  beforeEach(() => {
    resetPolicies();
  });

  describe('the digest', () => {
    it('matches the digest of the raw value', () => {
      expect(sensitive('value').hash('sha256').reveal()).toBe(sha256('value'));
    });

    it('computes every allowed algorithm', () => {
      for (const algorithm of ['sha256', 'sha384', 'sha512', 'sha3-256', 'sha3-512'] as const) {
        expect(sensitive('value').hash(algorithm).reveal()).toBe(
          createHash(algorithm).update('value', 'utf8').digest('hex')
        );
      }
    });

    it('is stable across instances of the same value', () => {
      expect(sensitive('value').hash('sha256').reveal()).toBe(
        sensitive('value').hash('sha256').reveal()
      );
    });

    it('differs for values that differ by one character', () => {
      expect(sensitive('value').hash('sha256').reveal()).not.toBe(
        sensitive('valuf').hash('sha256').reveal()
      );
    });

    it('reads the value as UTF-8', () => {
      expect(sensitive('ünïcodé').hash('sha256').reveal()).toBe(sha256('ünïcodé'));
    });

    it('hashes the empty value rather than refusing it', () => {
      expect(sensitive('').hash('sha256').reveal()).toBe(sha256(''));
    });
  });

  describe('encodings', () => {
    it('defaults to hex', () => {
      expect(sensitive('value').hash('sha256').reveal()).toMatch(/^[0-9a-f]{64}$/);
    });

    it('renders base64', () => {
      expect(sensitive('value').hash('sha256', { encoding: 'base64' }).reveal()).toBe(
        createHash('sha256').update('value', 'utf8').digest('base64')
      );
    });

    it('renders base64url', () => {
      const digest = sensitive('value').hash('sha256', { encoding: 'base64url' }).reveal();

      expect(digest).toBe(createHash('sha256').update('value', 'utf8').digest('base64url'));
      expect(digest).not.toContain('+');
      expect(digest).not.toContain('/');
      expect(digest).not.toContain('=');
    });

    it('refuses an unknown encoding', () => {
      // @ts-expect-error deliberately invalid encoding
      expect(() => sensitive('value').hash('sha256', { encoding: 'binary' })).toThrow(TypeError);
    });
  });

  describe('the salt', () => {
    it('changes the digest', () => {
      expect(sensitive('value').hash('sha256', { salt: 'pepper' }).reveal()).not.toBe(
        sensitive('value').hash('sha256').reveal()
      );
    });

    it('is prepended, not appended', () => {
      expect(sensitive('value').hash('sha256', { salt: 'pepper' }).reveal()).toBe(
        sha256('peppervalue')
      );
    });

    it('gives the same digest for the same value and salt', () => {
      const salt = randomBytes(16);

      expect(sensitive('value').hash('sha256', { salt }).reveal()).toBe(
        sensitive('value').hash('sha256', { salt }).reveal()
      );
    });

    it('accepts bytes', () => {
      const salt = Uint8Array.from([1, 2, 3, 4]);

      expect(sensitive('value').hash('sha256', { salt }).reveal()).toBe(
        createHash('sha256').update(salt).update('value', 'utf8').digest('hex')
      );
    });

    it('refuses an empty salt rather than treating it as none', () => {
      expect(() => sensitive('value').hash('sha256', { salt: '' })).toThrow(RangeError);
    });

    it('refuses a salt of the wrong type', () => {
      // @ts-expect-error deliberately invalid salt
      expect(() => sensitive('value').hash('sha256', { salt: 42 })).toThrow(TypeError);
    });
  });

  describe('the result', () => {
    it('is a credential whatever the source class was', () => {
      expect(sensitive('value').hash('sha256').klass).toBe('credential');
      expect(credential('value').hash('sha256').klass).toBe('credential');
    });

    it('redacts', () => {
      const digest = sensitive('value').hash('sha256');

      expect(String(digest)).toBe('[REDACTED:credential]');
      expect(JSON.stringify({ digest })).not.toContain(sha256('value'));
    });

    it('derives its label from the source', () => {
      expect(sensitive('value', 'api_key').hash('sha256').label).toBe('api_key:hash');
    });

    it('labels an unlabelled source, and never as undefined', () => {
      expect(sensitive('value').hash('sha256').label).toBe('hash');
    });
  });

  describe('the policy', () => {
    it('refuses a class whose policy sets allowHash: false', () => {
      registerPolicy(
        {
          name: 'sensitive',
          redact: () => '[REDACTED:sensitive]',
          advisory: { allowHash: false },
        },
        { overwrite: true }
      );

      expect(() => sensitive('value', 'ssn').hash('sha256')).toThrow(/allowHash/);
    });

    it('names the class and the label without the value', () => {
      registerPolicy(
        {
          name: 'sensitive',
          redact: () => '[REDACTED:sensitive]',
          advisory: { allowHash: false },
        },
        { overwrite: true }
      );

      try {
        sensitive('LEAKED_SECRET_abc', 'ssn').hash('sha256');
        expect.unreachable('hash must refuse');
      } catch (error) {
        expect(String(error)).toContain("'sensitive'");
        expect(String(error)).toContain('ssn');
        expect(String(error)).not.toContain('LEAKED_SECRET_abc');
      }
    });

    it('allows a class that says nothing about hashing', () => {
      expect(() => sensitive('value').hash('sha256')).not.toThrow();
    });

    it('allows a credential, which the default policy permits explicitly', () => {
      expect(() => credential('value').hash('sha256')).not.toThrow();
    });

    it('refuses before validating options, so a forbidden class reports the prohibition', () => {
      registerPolicy(
        {
          name: 'sensitive',
          redact: () => '[REDACTED:sensitive]',
          advisory: { allowHash: false },
        },
        { overwrite: true }
      );

      // @ts-expect-error deliberately invalid algorithm
      expect(() => sensitive('value').hash('md5')).toThrow(/allowHash/);
    });
  });

  describe('refused algorithms', () => {
    it('refuses md5 with a reason', () => {
      // @ts-expect-error deliberately invalid algorithm
      expect(() => sensitive('value').hash('md5')).toThrow(/MD5 collides/);
    });

    it('refuses sha1 with a reason', () => {
      // @ts-expect-error deliberately invalid algorithm
      expect(() => sensitive('value').hash('sha1')).toThrow(/SHA-1 collisions/);
    });

    it('refuses an unknown algorithm with the list of allowed ones', () => {
      // @ts-expect-error deliberately invalid algorithm
      expect(() => sensitive('value').hash('blake2b512')).toThrow(/sha3-512/);
    });

    it('refuses an algorithm of the wrong type', () => {
      // @ts-expect-error deliberately invalid algorithm
      expect(() => sensitive('value').hash(256)).toThrow(TypeError);
    });
  });

  describe('auditing', () => {
    it('reports the operation, the algorithm and the encoding', () => {
      const records: RevealDetails[] = [];

      withRevealContext(
        { name: 'test', auditReveal: (_value, details) => void records.push(details) },
        () => {
          sensitive('value').hash('sha256', { salt: 'pepper', encoding: 'base64' });
        }
      );

      expect(records).toEqual([
        { operation: 'hash', algorithm: 'sha256', encoding: 'base64', salted: true },
      ]);
    });

    it('reports an unsalted digest as unsalted', () => {
      const records: RevealDetails[] = [];

      withRevealContext(
        { name: 'test', auditReveal: (_value, details) => void records.push(details) },
        () => {
          sensitive('value').hash('sha256');
        }
      );

      expect(records).toEqual([
        { operation: 'hash', algorithm: 'sha256', encoding: 'hex', salted: false },
      ]);
    });

    it('never carries the salt itself', () => {
      const records: RevealDetails[] = [];

      withRevealContext(
        { name: 'test', auditReveal: (_value, details) => void records.push(details) },
        () => {
          sensitive('value').hash('sha256', { salt: 'PEPPER_CANARY' });
        }
      );

      expect(JSON.stringify(records)).not.toContain('PEPPER_CANARY');
    });

    it('lets an audit sink refuse by throwing, and takes no digest', () => {
      const value = sensitive('value');

      expect(() =>
        value.hash(
          'sha256',
          {},
          {
            name: 'test',
            auditReveal: () => {
              throw new Error('denied');
            },
          }
        )
      ).toThrow('denied');
      expect(value.revealCount).toBe(0);
    });

    it('counts one exposure per digest', () => {
      const value = sensitive('value');

      value.hash('sha256');
      value.hash('sha512');

      expect(value.revealCount).toBe(2);
    });

    it('records nothing for a call rejected on its options', () => {
      const audit = vi.fn();

      withRevealContext({ name: 'test', auditReveal: audit }, () => {
        // @ts-expect-error deliberately invalid encoding
        expect(() => sensitive('value').hash('sha256', { encoding: 'binary' })).toThrow(TypeError);
      });

      expect(audit).not.toHaveBeenCalled();
    });
  });

  describe('the gate', () => {
    it('refuses an expired value', () => {
      const value = new SensitiveString('value', 'sensitive', 'otp', { ttl: 0 });

      expect(() => value.hash('sha256')).toThrow(ExpiredSensitiveValueError);
    });

    it('refuses a revoked value', () => {
      const value = sensitive('value', 'token');
      value.revoke('rotated');

      expect(() => value.hash('sha256')).toThrow(RevokedSensitiveValueError);
    });

    it('refuses once the reveal budget is spent', () => {
      const value = new SensitiveString('value', 'sensitive', 'otp', { maxReveals: 1 });

      expect(value.hash('sha256').klass).toBe('credential');
      expect(() => value.hash('sha256')).toThrow(RevealLimitExceededError);
    });
  });

  describe('constraints of the source', () => {
    it('gives the digest the deadline of the value it came from', () => {
      const value = new SensitiveString('value', 'sensitive', 'otp', { ttl: 60_000 });

      expect(value.hash('sha256').expiresAt).toEqual(value.expiresAt);
    });

    it('gives the digest the reveal budget of the value it came from', () => {
      const value = new SensitiveString('value', 'sensitive', 'otp', { maxReveals: 2 });
      const digest = value.hash('sha256');

      expect(digest.revealsRemaining).toBe(1);
      expect(digest.reveal()).toMatch(/^[0-9a-f]{64}$/);
      expect(digest.isExhausted()).toBe(true);
      expect(() => value.reveal()).toThrow(RevealLimitExceededError);
    });

    it('revokes the digest with the value it came from', () => {
      const value = sensitive('value', 'token');
      const digest = value.hash('sha256');

      value.revoke('rotated');

      expect(digest.isRevoked).toBe(true);
      expect(() => digest.reveal()).toThrow(RevokedSensitiveValueError);
    });
  });
});

describe('SensitiveString.hmac', () => {
  beforeEach(() => {
    resetPolicies();
  });

  describe('the digest', () => {
    it('matches the keyed digest of the raw value', () => {
      expect(sensitive('value').hmac('sha256', KEY).reveal()).toBe(
        createHmac('sha256', KEY).update('value', 'utf8').digest('hex')
      );
    });

    it('differs under a different key', () => {
      expect(sensitive('value').hmac('sha256', KEY).reveal()).not.toBe(
        sensitive('value').hmac('sha256', 'j'.repeat(32)).reveal()
      );
    });

    it('differs from the unkeyed digest of the same value', () => {
      expect(sensitive('value').hmac('sha256', KEY).reveal()).not.toBe(sha256('value'));
    });

    it('accepts a byte key', () => {
      const key = randomBytes(32);

      expect(sensitive('value').hmac('sha256', key).reveal()).toBe(
        createHmac('sha256', key).update('value', 'utf8').digest('hex')
      );
    });

    it('renders the requested encoding', () => {
      expect(sensitive('value').hmac('sha256', KEY, { encoding: 'base64url' }).reveal()).toBe(
        createHmac('sha256', KEY).update('value', 'utf8').digest('base64url')
      );
    });
  });

  describe('the key', () => {
    it('refuses a key below the floor', () => {
      expect(() => sensitive('value').hmac('sha256', 'short')).toThrow(RangeError);
    });

    it('names the length it received and not the key', () => {
      try {
        sensitive('value').hmac('sha256', 'SHORTKEY_CANARY');
        expect.unreachable('hmac must refuse a short key');
      } catch (error) {
        expect(String(error)).toContain('16');
        expect(String(error)).not.toContain('SHORTKEY_CANARY');
      }
    });

    it('charges the value nothing for a call refused on the key', () => {
      const value = sensitive('value');

      expect(() => value.hmac('sha256', 'short')).toThrow(RangeError);
      expect(value.revealCount).toBe(0);
    });

    it('refuses a key of the wrong type', () => {
      // @ts-expect-error deliberately invalid key
      expect(() => sensitive('value').hmac('sha256', 42)).toThrow(TypeError);
    });

    it('refuses a salt, which a keyed digest has no use for', () => {
      // @ts-expect-error salt does not belong to HmacOptions
      expect(() => sensitive('value').hmac('sha256', KEY, { salt: 'pepper' })).toThrow(/salt/);
    });
  });

  describe('a protected key', () => {
    it('produces the same digest as the raw key would', () => {
      const key = credential(KEY, 'correlation_key');

      expect(sensitive('value').hmac('sha256', key).reveal()).toBe(
        sensitive('value').hmac('sha256', KEY).reveal()
      );
    });

    it('counts as an exposure of the key', () => {
      const key = credential(KEY, 'correlation_key');

      sensitive('value').hmac('sha256', key);

      expect(key.revealCount).toBe(1);
    });

    it('audits the key read as well as the value read', () => {
      const seen: string[] = [];

      withRevealContext(
        {
          name: 'test',
          auditReveal: (value, details) => void seen.push(`${value.label}:${details.operation}`),
        },
        () => {
          sensitive('value', 'email').hmac('sha256', credential(KEY, 'correlation_key'));
        }
      );

      expect(seen).toEqual(['correlation_key:hmac', 'email:hmac']);
    });

    it('reports the key as protected in the audit record', () => {
      const records: RevealDetails[] = [];

      withRevealContext(
        { name: 'test', auditReveal: (_value, details) => void records.push(details) },
        () => {
          sensitive('value').hmac('sha256', credential(KEY));
        }
      );

      expect(records.every((record) => 'protectedKey' in record && record.protectedKey)).toBe(true);
    });

    it('reports a raw key as not protected', () => {
      const records: RevealDetails[] = [];

      withRevealContext(
        { name: 'test', auditReveal: (_value, details) => void records.push(details) },
        () => {
          sensitive('value').hmac('sha256', KEY);
        }
      );

      expect(records).toEqual([
        { operation: 'hmac', algorithm: 'sha256', encoding: 'hex', protectedKey: false },
      ]);
    });

    it('refuses when the key is revoked', () => {
      const key = credential(KEY, 'correlation_key');
      key.revoke('rotated');

      expect(() => sensitive('value').hmac('sha256', key)).toThrow(RevokedSensitiveValueError);
    });

    it('gives the result the constraints of the key as well as the value', () => {
      const key = new SensitiveString(KEY, 'credential', 'correlation_key', { ttl: 60_000 });
      const digest = sensitive('value', 'email').hmac('sha256', key);

      expect(digest.expiresAt).toEqual(key.expiresAt);
    });
  });

  describe('the result', () => {
    it('is a credential', () => {
      expect(sensitive('value').hmac('sha256', KEY).klass).toBe('credential');
    });

    it('derives its label from the source', () => {
      expect(sensitive('value', 'email').hmac('sha256', KEY).label).toBe('email:hmac');
      expect(sensitive('value').hmac('sha256', KEY).label).toBe('hmac');
    });

    it('redacts', () => {
      expect(String(sensitive('value').hmac('sha256', KEY))).toBe('[REDACTED:credential]');
    });
  });

  describe('the policy', () => {
    it('refuses a class whose policy sets allowHash: false', () => {
      registerPolicy(
        {
          name: 'sensitive',
          redact: () => '[REDACTED:sensitive]',
          advisory: { allowHash: false },
        },
        { overwrite: true }
      );

      expect(() => sensitive('value').hmac('sha256', KEY)).toThrow(/allowHash/);
    });
  });
});
