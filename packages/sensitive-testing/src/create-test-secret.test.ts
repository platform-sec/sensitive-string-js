import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ExpiredSensitiveValueError, resetPolicies } from '@platform-sec/sensitive-string-core';
import {
  createExpiredSecret,
  createExpiringSecret,
  createTestSecret,
} from './create-test-secret.js';

const START = new Date('2026-01-01T00:00:00.000Z');
const MINUTE = 60_000;

describe('createTestSecret', () => {
  beforeEach(() => {
    resetPolicies();
  });

  // TST-TU-CTS-001
  it('creates a unique value on each call', () => {
    const values = new Set<string>();

    for (let i = 0; i < 100; i += 1) {
      values.add(createTestSecret().reveal());
    }

    expect(values.size).toBe(100);
  });

  it('stays unique when the clock does not move', () => {
    vi.useFakeTimers();
    vi.setSystemTime(START);

    try {
      const first = createTestSecret().reveal();
      const second = createTestSecret().reveal();

      expect(first).not.toBe(second);
    } finally {
      vi.useRealTimers();
    }
  });

  it('generates a value that stands out in output', () => {
    const value = createTestSecret().reveal();

    expect(value.startsWith('__CANARY_')).toBe(true);
    expect(value.endsWith('__')).toBe(true);
  });

  // TST-TU-CTS-002
  it('respects the klass parameter', () => {
    expect(createTestSecret('credential').klass).toBe('credential');
    expect(createTestSecret('sensitive').klass).toBe('sensitive');
  });

  it('defaults to the sensitive class', () => {
    expect(createTestSecret().klass).toBe('sensitive');
  });

  // TST-TU-CTS-003
  it('respects the label parameter', () => {
    expect(createTestSecret('credential', 'api_key').label).toBe('api_key');
    expect(createTestSecret().label).toBeUndefined();
  });

  // TST-TU-CTS-004
  it('accepts a custom prefix', () => {
    const value = createTestSecret('sensitive', undefined, { prefix: 'sk_test_' }).reveal();

    expect(value.startsWith('sk_test_')).toBe(true);
  });

  // TST-TU-CTS-005
  it('accepts a custom suffix', () => {
    const value = createTestSecret('sensitive', undefined, { suffix: '_END' }).reveal();

    expect(value.endsWith('_END')).toBe(true);
  });

  // TST-TU-CTS-006
  it('uses an explicit value instead of generating one', () => {
    const secret = createTestSecret('sensitive', 'email', { value: 'jane@example.com' });

    expect(secret.reveal()).toBe('jane@example.com');
  });

  it('ignores prefix and suffix when an explicit value is given', () => {
    const secret = createTestSecret('sensitive', undefined, {
      value: 'exact',
      prefix: 'ignored',
      suffix: 'ignored',
    });

    expect(secret.reveal()).toBe('exact');
  });

  describe('option passthrough', () => {
    beforeEach(() => {
      vi.useFakeTimers();
      vi.setSystemTime(START);
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    // TST-TU-CTS-007
    it('passes ttl through to the instance', () => {
      const otp = createTestSecret('credential', 'otp', { ttl: 5 * MINUTE });

      expect(otp.expiresAt).toEqual(new Date(START.getTime() + 5 * MINUTE));
      expect(otp.ttlRemaining()).toBe(5 * MINUTE);
    });

    // TST-TU-CTS-008
    it('passes expiresAt through to the instance', () => {
      const deadline = new Date('2026-06-01T12:00:00.000Z');
      const session = createTestSecret('credential', 'session', { expiresAt: deadline });

      expect(session.expiresAt).toEqual(deadline);
    });

    it('leaves a secret without a deadline when neither option is given', () => {
      expect(createTestSecret().expiresAt).toBeUndefined();
    });

    it('passes options it does not know about through to the constructor', () => {
      const onExpire = vi.fn();
      const secret = createTestSecret('sensitive', 'session', { ttl: MINUTE, onExpire });

      vi.setSystemTime(new Date(START.getTime() + MINUTE + 1));
      expect(() => secret.reveal()).toThrow(ExpiredSensitiveValueError);

      expect(onExpire).toHaveBeenCalledTimes(1);
    });
  });
});

describe('createExpiredSecret', () => {
  beforeEach(() => {
    resetPolicies();
  });

  it('creates a secret whose deadline has already passed', () => {
    const secret = createExpiredSecret('credential', 'otp');

    expect(secret.isExpired()).toBe(true);
    expect(() => secret.reveal()).toThrow(ExpiredSensitiveValueError);
  });

  it('needs no fake timers', () => {
    expect(createExpiredSecret().isExpired()).toBe(true);
  });

  it('carries the class and label', () => {
    const secret = createExpiredSecret('credential', 'otp');

    expect(secret.klass).toBe('credential');
    expect(secret.label).toBe('otp');
  });
});

describe('createExpiringSecret', () => {
  beforeEach(() => {
    resetPolicies();
    vi.useFakeTimers();
    vi.setSystemTime(START);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('creates a secret that expires after the given lifetime', () => {
    const session = createExpiringSecret('credential', 'session', MINUTE);

    expect(session.isExpired()).toBe(false);

    vi.setSystemTime(new Date(START.getTime() + MINUTE + 1));

    expect(session.isExpired()).toBe(true);
  });

  it('is still valid at the moment before the deadline', () => {
    const session = createExpiringSecret('credential', 'session', MINUTE);

    vi.setSystemTime(new Date(START.getTime() + MINUTE - 1));

    expect(session.isExpired()).toBe(false);
  });
});
