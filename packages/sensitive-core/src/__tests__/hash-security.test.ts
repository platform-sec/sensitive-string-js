/**
 * Hash Transformation Security Tests
 *
 * A digest is an exposure that produces a durable artifact. These tests verify
 * that taking one runs the same gate as any other read, that the artifact
 * carries the constraints of what it was made from, that nothing about the
 * value survives into the digest's own rendering, and that a refused call
 * discloses nothing.
 */

import { describe, expect, it, beforeEach, vi } from 'vitest';
import * as util from 'node:util';
import { createHash } from 'node:crypto';
import {
  ExpiredSensitiveValueError,
  RevealDuringRedactionError,
  RevealLimitExceededError,
  RevokedSensitiveValueError,
  SensitiveString,
  registerPolicy,
  resetPolicies,
  safeStringify,
  withRevealContext,
} from '../index.js';
import type { RevealAccess, RevealContext, SensitivityClass } from '../index.js';

const CANARY = 'HASH_SECURITY_CANARY_4b8e13';
const KEY_CANARY = 'HASH_KEY_CANARY_a71f0c2d9e';

const sensitive = (value = CANARY, label?: string) =>
  new SensitiveString(value, 'sensitive', label);

describe('hash transformation security', () => {
  beforeEach(() => {
    resetPolicies();
  });

  describe('the canary', () => {
    it('is not in the digest', () => {
      expect(sensitive().hash('sha256').reveal()).not.toContain(CANARY);
      expect(sensitive().hash('sha512', { encoding: 'base64' }).reveal()).not.toContain(CANARY);
      expect(sensitive().hmac('sha256', KEY_CANARY).reveal()).not.toContain(CANARY);
    });

    it("is not in the digest's rendering", () => {
      const digest = sensitive().hash('sha256');

      expect(String(digest)).not.toContain(CANARY);
      expect(JSON.stringify(digest)).not.toContain(CANARY);
      expect(util.inspect(digest)).not.toContain(CANARY);
      expect(safeStringify({ digest })).not.toContain(CANARY);
    });

    it("is not in the digest's own inspect output, which reports a credential", () => {
      expect(util.inspect(sensitive(CANARY, 'api_key').hash('sha256'))).toBe(
        'SensitiveString<credential:api_key:hash> { [REDACTED:credential] }'
      );
    });

    it("is not in the key's rendering after being used as one", () => {
      const key = new SensitiveString(KEY_CANARY, 'credential', 'correlation_key');
      const digest = sensitive().hmac('sha256', key);

      expect(util.inspect(digest)).not.toContain(KEY_CANARY);
      expect(digest.reveal()).not.toContain(KEY_CANARY);
    });

    it('is not in the error from any refusal', () => {
      registerPolicy(
        {
          name: 'sensitive',
          redact: () => '[REDACTED:sensitive]',
          advisory: { allowHash: false },
        },
        { overwrite: true }
      );

      const refusals: (() => unknown)[] = [
        () => sensitive().hash('sha256'),
        () => sensitive().hmac('sha256', KEY_CANARY),
      ];

      resetPolicies();

      refusals.push(
        // @ts-expect-error deliberately invalid algorithm
        () => sensitive().hash('md5'),
        // @ts-expect-error deliberately invalid encoding
        () => sensitive().hash('sha256', { encoding: 'binary' }),
        () => sensitive().hash('sha256', { salt: '' }),
        () => sensitive().hmac('sha256', 'short'),
        () => new SensitiveString(CANARY, 'sensitive', 'otp', { ttl: 0 }).hash('sha256')
      );

      // The allowHash refusals need the policy that produced them.
      for (const [index, refuse] of refusals.entries()) {
        if (index < 2) {
          registerPolicy(
            {
              name: 'sensitive',
              redact: () => '[REDACTED:sensitive]',
              advisory: { allowHash: false },
            },
            { overwrite: true }
          );
        } else {
          resetPolicies();
        }

        let thrown: unknown;
        try {
          refuse();
          expect.unreachable(`refusal ${index} must throw`);
        } catch (error) {
          thrown = error;
        }

        expect(String(thrown)).not.toContain(CANARY);
        expect(util.inspect(thrown)).not.toContain(CANARY);
      }
    });
  });

  describe('the gate', () => {
    it('refuses a digest of an expired value', () => {
      const value = new SensitiveString(CANARY, 'sensitive', 'otp', { ttl: 0 });

      expect(() => value.hash('sha256')).toThrow(ExpiredSensitiveValueError);
      expect(() => value.hmac('sha256', KEY_CANARY)).toThrow(ExpiredSensitiveValueError);
    });

    it('refuses a digest of a revoked value', () => {
      const value = sensitive(CANARY, 'token');
      value.revoke('rotated');

      expect(() => value.hash('sha256')).toThrow(RevokedSensitiveValueError);
      expect(() => value.hmac('sha256', KEY_CANARY)).toThrow(RevokedSensitiveValueError);
    });

    it('refuses a digest taken from inside a redaction walk', () => {
      const value = sensitive();
      let caught: unknown;

      // The walk absorbs whatever a caller's toJSON() throws and redacts the
      // object instead, so the refusal is observed from inside it.
      const hostile = {
        toJSON(): Record<string, unknown> {
          try {
            return { digest: value.hash('sha256').reveal() };
          } catch (error) {
            caught = error;
            throw error;
          }
        },
      };

      const output = safeStringify({ hostile });

      expect(caught).toBeInstanceOf(RevealDuringRedactionError);
      expect(output).not.toContain(CANARY);
    });

    it('charges the reveal budget, so a digest cannot be taken for free', () => {
      const value = new SensitiveString(CANARY, 'sensitive', 'otp', { maxReveals: 2 });

      value.hash('sha256');
      value.hmac('sha256', KEY_CANARY);

      expect(value.revealsRemaining).toBe(0);
      expect(() => value.hash('sha256')).toThrow(RevealLimitExceededError);
      expect(() => value.reveal()).toThrow(RevealLimitExceededError);
    });

    it('asks the policy to authorize an exposure, not a comparison', () => {
      const seen: RevealAccess[] = [];

      registerPolicy(
        {
          name: 'sensitive',
          redact: () => '[REDACTED:sensitive]',
          checkRevealAllowed: (_ctx, _value, access) => {
            seen.push(access);
          },
        },
        { overwrite: true }
      );

      sensitive().hash('sha256');

      expect(seen).toEqual(['expose']);
    });

    it('lets the policy refuse the digest outright', () => {
      registerPolicy(
        {
          name: 'sensitive',
          redact: () => '[REDACTED:sensitive]',
          checkRevealAllowed: () => {
            throw new Error('no reveals without a reason');
          },
        },
        { overwrite: true }
      );

      expect(() => sensitive().hash('sha256')).toThrow('no reveals without a reason');
    });
  });

  describe('what a digest carries', () => {
    it('cannot outlive the value it came from', () => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'));

      try {
        const value = new SensitiveString(CANARY, 'sensitive', 'otp', { ttl: 60_000 });
        const digest = value.hash('sha256');

        vi.advanceTimersByTime(61_000);

        expect(digest.isExpired()).toBe(true);
        expect(() => digest.reveal()).toThrow(ExpiredSensitiveValueError);
      } finally {
        vi.useRealTimers();
      }
    });

    it('is revoked with the value it came from, and revoking it revokes that value', () => {
      const value = sensitive(CANARY, 'token');
      const digest = value.hash('sha256');

      digest.revoke('the digest leaked');

      expect(value.isRevoked).toBe(true);
      expect(() => value.reveal()).toThrow(RevokedSensitiveValueError);
    });

    it('does not launder a spent budget through a chain of digests', () => {
      const value = new SensitiveString(CANARY, 'sensitive', 'otp', { maxReveals: 1 });
      const digest = value.hash('sha256');

      expect(() => digest.hash('sha256')).toThrow(RevealLimitExceededError);
      expect(() => digest.reveal()).toThrow(RevealLimitExceededError);
    });

    it('carries the constraints of a protected key as well as the value', () => {
      const key = new SensitiveString(KEY_CANARY, 'credential', 'correlation_key', {
        maxReveals: 1,
      });
      const digest = sensitive().hmac('sha256', key);

      expect(() => digest.reveal()).toThrow(RevealLimitExceededError);
    });
  });

  describe('the class of a digest', () => {
    it('is credential even when the source is not', () => {
      expect(sensitive().hash('sha256').klass).toBe('credential');
      expect(sensitive().hmac('sha256', KEY_CANARY).klass).toBe('credential');
    });

    it("is not decided by the policy's combineClasses hook", () => {
      registerPolicy(
        {
          name: 'sensitive',
          redact: () => '[REDACTED:sensitive]',
          combineClasses: (): SensitivityClass => 'sensitive',
        },
        { overwrite: true }
      );

      expect(sensitive().hash('sha256').klass).toBe('credential');
    });

    it('brings the credential comparison rule with it', () => {
      const digest = sensitive().hash('sha256');

      expect(digest.equals(createHash('sha256').update(CANARY, 'utf8').digest('hex'))).toBe(true);
      expect(digest.equals('not the digest')).toBe(false);
    });

    it('does not answer a partial query, because credentials do not', () => {
      expect(() => sensitive().hash('sha256').startsWith('a')).toThrow(/Partial queries/);
    });

    it('does not mask, because credentials do not', () => {
      expect(() => sensitive().hash('sha256').mask({ showLast: 4 })).toThrow(/Masking/);
    });
  });

  describe('hostile input', () => {
    it('reads each option exactly once, so a getter cannot change it after validation', () => {
      let saltReads = 0;
      let encodingReads = 0;

      const options = {
        get salt() {
          saltReads += 1;
          return saltReads === 1 ? 'pepper' : '';
        },
        get encoding() {
          encodingReads += 1;
          return encodingReads === 1 ? ('hex' as const) : ('base64' as const);
        },
      };

      const digest = sensitive().hash('sha256', options);

      expect(saltReads).toBe(1);
      expect(encodingReads).toBe(1);
      expect(digest.reveal()).toBe(
        createHash('sha256').update('pepper').update(CANARY, 'utf8').digest('hex')
      );
    });

    it('does not ask the key whether it may be hashed, because it is not', () => {
      // allowHash asks whether a digest OF this value may exist. An HMAC key is
      // used, not hashed, and HMAC does not disclose its key. The key's policy
      // still authorizes the read, through checkRevealAllowed like any other.
      registerPolicy(
        {
          name: 'credential',
          redact: () => '[REDACTED:credential]',
          requireConstantTimeEquals: true,
          advisory: { allowHash: false },
        },
        { overwrite: true }
      );

      const key = new SensitiveString(KEY_CANARY, 'credential', 'correlation_key');
      const digest = sensitive().hmac('sha256', key);

      expect(digest.reveal()).not.toContain(KEY_CANARY);
      expect(() => key.hash('sha256')).toThrow(/allowHash/);
    });

    it('refuses an object that only claims to be a SensitiveString key', () => {
      const impostor = Object.create(SensitiveString.prototype) as SensitiveString;

      expect(() => sensitive().hmac('sha256', impostor)).toThrow(TypeError);
    });

    it('is not lifted by a subclass overriding the public lifecycle accessors', () => {
      class Forged extends SensitiveString<'sensitive'> {
        override isExpired(): boolean {
          return false;
        }

        override get expiresAt(): Date | undefined {
          return undefined;
        }

        override isExhausted(): boolean {
          return false;
        }

        override get isRevoked(): boolean {
          return false;
        }
      }

      const forged = new Forged(CANARY, 'sensitive', 'canary', { ttl: 0, maxReveals: 5 });

      // The gate reads the deadline and the revocation through private paths
      // for exactly this reason, so the digest is refused however the instance
      // answers about itself.
      expect(() => forged.hash('sha256')).toThrow(ExpiredSensitiveValueError);
      expect(() => forged.hmac('sha256', KEY_CANARY)).toThrow(ExpiredSensitiveValueError);
    });

    it('is not lifted by shadowing those accessors on the instance', () => {
      const value = sensitive(CANARY, 'token');
      value.revoke('rotated');

      Object.defineProperty(value, 'isRevoked', { value: false });
      Object.defineProperty(value, 'revocationReason', { value: undefined });

      expect(() => value.hash('sha256')).toThrow(RevokedSensitiveValueError);
    });

    it('does not disclose the value through an audit sink', () => {
      const seen: unknown[] = [];
      const ctx: RevealContext = {
        name: 'test',
        auditReveal: (value, details) => void seen.push({ value: String(value), details }),
      };

      withRevealContext(ctx, () => {
        sensitive(CANARY, 'api_key').hash('sha256', { salt: 'pepper' });
      });

      expect(JSON.stringify(seen)).not.toContain(CANARY);
      expect(JSON.stringify(seen)).not.toContain('pepper');
    });
  });
});
