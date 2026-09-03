import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SensitiveString, resetPolicies } from '@platform-sec/sensitive-string-core';
import { sensitiveMatchers, setupSensitiveMatchers } from './matchers.js';
import { createExpiredSecret, createTestSecret } from './create-test-secret.js';
import './vitest.js';

const CANARY = 'MATCHERS_CANARY_2d81';
const START = new Date('2026-01-01T00:00:00.000Z');

setupSensitiveMatchers(expect);

describe('sensitiveMatchers', () => {
  beforeEach(() => {
    resetPolicies();
  });

  // TST-TU-MAT-001
  describe('toBeSensitiveString', () => {
    it('passes for a SensitiveString', () => {
      expect(createTestSecret()).toBeSensitiveString();
    });

    // TST-TU-MAT-002
    it('fails for a plain string', () => {
      expect(CANARY).not.toBeSensitiveString();
    });

    it('names the type it got instead', () => {
      expect(messageFor(sensitiveMatchers.toBeSensitiveString('plain'))).toContain('string');
      expect(messageFor(sensitiveMatchers.toBeSensitiveString(null))).toContain('null');
      expect(messageFor(sensitiveMatchers.toBeSensitiveString(new Date()))).toContain('Date');
      expect(messageFor(sensitiveMatchers.toBeSensitiveString(Object.create(null)))).toContain(
        'no prototype'
      );
    });
  });

  // TST-TU-MAT-003
  describe('toHaveSensitivityClass', () => {
    it('matches the class', () => {
      expect(createTestSecret('credential')).toHaveSensitivityClass('credential');
      expect(createTestSecret('sensitive')).toHaveSensitivityClass('sensitive');
    });

    it('fails on the wrong class', () => {
      expect(createTestSecret('sensitive')).not.toHaveSensitivityClass('credential');
    });

    it('fails for a value that is not a SensitiveString', () => {
      expect(CANARY).not.toHaveSensitivityClass('credential');
    });

    it('reports both classes', () => {
      const result = sensitiveMatchers.toHaveSensitivityClass(
        createTestSecret('sensitive'),
        'credential'
      );

      expect(result.pass).toBe(false);
      expect(result.message()).toContain("'credential'");
      expect(result.message()).toContain("'sensitive'");
    });
  });

  // TST-TU-MAT-004
  describe('toHaveLabel', () => {
    it('matches the label', () => {
      expect(createTestSecret('credential', 'api_key')).toHaveLabel('api_key');
    });

    it('matches an absent label', () => {
      expect(createTestSecret()).toHaveLabel(undefined);
    });

    it('fails on the wrong label', () => {
      expect(createTestSecret('credential', 'api_key')).not.toHaveLabel('session');
    });

    it('renders an absent label as (none)', () => {
      const result = sensitiveMatchers.toHaveLabel(createTestSecret(), 'api_key');

      expect(result.message()).toContain('(none)');
    });
  });

  // TST-TU-MAT-005
  describe('toRevealAs', () => {
    it('matches the revealed value', () => {
      expect(createTestSecret('credential', 'token', { value: 'abc123' })).toRevealAs('abc123');
    });

    it('fails on a different value', () => {
      expect(createTestSecret('credential', 'token', { value: 'abc123' })).not.toRevealAs('nope');
    });

    it('withholds the actual value from the failure message', () => {
      const secret = new SensitiveString(CANARY, 'credential', 'token');
      const result = sensitiveMatchers.toRevealAs(secret, 'expected-value');

      expect(result.pass).toBe(false);
      expect(result.message()).not.toContain(CANARY);
      expect(result.message()).toContain('expected-value');
      expect(result.message()).toContain('[REDACTED:credential]');
      expect(result.message()).toContain(`${CANARY.length} characters`);
    });

    it('reports a refused reveal as a failed assertion rather than throwing', () => {
      const expired = createExpiredSecret('credential', 'otp');
      const result = sensitiveMatchers.toRevealAs(expired, 'anything');

      expect(result.pass).toBe(false);
      expect(result.message()).toContain('ExpiredSensitiveValueError');
    });

    it('keeps .not usable on a value that cannot be revealed', () => {
      expect(new SensitiveString(CANARY, 'credential', 'otp', { ttl: 0 })).not.toRevealAs(CANARY);
    });
  });

  // TST-TU-MAT-006
  describe('toBeExpired', () => {
    beforeEach(() => {
      vi.useFakeTimers();
      vi.setSystemTime(START);
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it('passes for a secret past its deadline', () => {
      expect(createExpiredSecret('credential', 'otp')).toBeExpired();
    });

    it('fails for a secret still within its deadline', () => {
      expect(createTestSecret('credential', 'otp', { ttl: 60_000 })).not.toBeExpired();
    });

    it('fails for a secret with no deadline', () => {
      expect(createTestSecret()).not.toBeExpired();
    });

    it('reports the remaining lifetime', () => {
      const result = sensitiveMatchers.toBeExpired(
        createTestSecret('credential', 'otp', { ttl: 60_000 })
      );

      expect(result.message()).toContain('60000ms left');
    });

    it('says so when there is no deadline at all', () => {
      expect(sensitiveMatchers.toBeExpired(createTestSecret()).message()).toContain('no deadline');
    });
  });

  // TST-TU-MAT-007
  describe('toContainSensitive', () => {
    it('detects the raw value in output', () => {
      const secret = createTestSecret('credential', 'api_key');

      expect({ header: secret.reveal() }).toContainSensitive(secret);
    });

    it('does not treat a wrapped value as present', () => {
      const secret = createTestSecret('credential', 'api_key');

      expect({ token: secret }).not.toContainSensitive(secret);
    });

    it('reports where it found the value without printing it', () => {
      const secret = new SensitiveString(CANARY, 'credential', 'api_key');
      const result = sensitiveMatchers.toContainSensitive({ header: CANARY }, secret);

      expect(result.pass).toBe(true);
      expect(result.message()).toContain('.header');
      expect(result.message()).not.toContain(CANARY);
    });
  });

  // TST-TU-MAT-008
  describe('negation', () => {
    it('works for every matcher', () => {
      const secret = createTestSecret('sensitive', 'email', { value: 'jane@example.com' });

      expect('plain').not.toBeSensitiveString();
      expect(secret).not.toHaveSensitivityClass('credential');
      expect(secret).not.toHaveLabel('api_key');
      expect(secret).not.toRevealAs('someone@example.com');
      expect(secret).not.toBeExpired();
      expect({ clean: true }).not.toContainSensitive(secret);
    });
  });

  // Q2 from the design document: asymmetric use is free once the matchers are
  // registered, since both frameworks expose a custom matcher on `expect`.
  describe('asymmetric use', () => {
    it('works inside toEqual', () => {
      const response = { token: createTestSecret('credential', 'api_key'), status: 'ok' };

      expect(response).toEqual({
        token: expect.toBeSensitiveString(),
        status: 'ok',
      });
    });

    it('works inside objectContaining', () => {
      const response = { token: createTestSecret('credential', 'api_key'), status: 'ok' };

      expect(response).toEqual(
        expect.objectContaining({ token: expect.toHaveSensitivityClass('credential') })
      );
    });
  });

  describe('the message a negated matcher fails with', () => {
    it('reads correctly for every matcher', () => {
      const secret = createTestSecret('credential', 'api_key', { value: 'abc123', ttl: 0 });

      expect(sensitiveMatchers.toBeSensitiveString(secret).message()).toContain('not to be');
      expect(sensitiveMatchers.toHaveSensitivityClass(secret, 'credential').message()).toContain(
        "not to be 'credential'"
      );
      expect(sensitiveMatchers.toHaveLabel(secret, 'api_key').message()).toContain(
        "not to be 'api_key'"
      );
      expect(sensitiveMatchers.toBeExpired(secret).message()).toContain('not to be expired');
      expect(
        sensitiveMatchers.toContainSensitive({ leaked: 'abc123' }, secret).message()
      ).toContain('not to contain');
    });

    it('reads correctly for toRevealAs', () => {
      const secret = createTestSecret('credential', 'token', { value: 'abc123' });

      expect(sensitiveMatchers.toRevealAs(secret, 'abc123').message()).toContain(
        "not to equal 'abc123'"
      );
    });

    it('names the whole target when the leak is the target itself', () => {
      const secret = createTestSecret('credential', 'api_key', { value: 'abc123' });

      expect(sensitiveMatchers.toContainSensitive('abc123', secret).message()).toContain(
        '(the target itself)'
      );
    });
  });

  describe('values that are not a SensitiveString', () => {
    it('fails every matcher that requires one', () => {
      for (const result of [
        sensitiveMatchers.toBeSensitiveString(42),
        sensitiveMatchers.toHaveSensitivityClass(42, 'credential'),
        sensitiveMatchers.toHaveLabel(42, 'api_key'),
        sensitiveMatchers.toRevealAs(42, 'abc'),
        sensitiveMatchers.toBeExpired(42),
      ]) {
        expect(result.pass).toBe(false);
      }
    });
  });

  describe('as read-only operations', () => {
    it('leaves the value unchanged', () => {
      const secret = createTestSecret('credential', 'api_key', { value: 'abc123', ttl: 60_000 });
      const before = secret.expiresAt;

      expect(secret).toBeSensitiveString();
      expect(secret).toHaveSensitivityClass('credential');
      expect(secret).toHaveLabel('api_key');
      expect(secret).toRevealAs('abc123');
      expect(secret).not.toBeExpired();

      expect(secret.reveal()).toBe('abc123');
      expect(secret.expiresAt).toEqual(before);
      expect(secret.renewalCount).toBe(0);
    });
  });
});

function messageFor(result: { message: () => string }): string {
  return result.message();
}
