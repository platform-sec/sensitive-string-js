import * as util from 'node:util';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  SensitiveString,
  registerPolicy,
  resetPolicies,
  withRevealContext,
} from '@platform-sec/sensitive-string-core';
import { createSensitiveSerializer, createTestSecret, sensitiveSerializer } from '../index.js';

const CANARY = 'SNAPSHOT_SERIALIZER_CANARY_4d8e';

/**
 * Every rendering the serializer can be asked for, for a value built from the
 * canary.
 *
 * A leak test that checks one format proves one format. The formats below are
 * every shape the public API can produce, so a placeholder that ever reached
 * the value would have to do it through one of them.
 */
function everyRendering(secret: SensitiveString<'credential'>): string[] {
  const serializers = [
    sensitiveSerializer,
    createSensitiveSerializer({ showLength: true }),
    createSensitiveSerializer({ showExpiration: true }),
    createSensitiveSerializer({ showLength: true, showExpiration: true }),
    createSensitiveSerializer({ format: '{class}{label}{length}{expired}' }),
    createSensitiveSerializer({ format: '{label}' }),
  ];

  return serializers.map((serializer) => serializer.serialize(secret));
}

describe('snapshot serializer security', () => {
  beforeEach(() => {
    resetPolicies();
  });

  afterEach(() => {
    resetPolicies();
  });

  describe('the value never reaches a snapshot', () => {
    it('keeps the canary out of every rendering', () => {
      const secret = new SensitiveString(CANARY, 'credential', 'api_key');

      for (const rendering of everyRendering(secret)) {
        expect(rendering).not.toContain(CANARY);
      }
    });

    it('keeps the canary out of a rendering of an expired value', () => {
      const secret = new SensitiveString(CANARY, 'credential', 'otp', { ttl: 0 });

      for (const rendering of everyRendering(secret)) {
        expect(rendering).not.toContain(CANARY);
      }
    });

    it('renders nothing that varies with the value', () => {
      // The strongest form of the claim: two values that differ in everything
      // but class and label are indistinguishable in the output, so the output
      // carries no information about either one.
      const first = new SensitiveString(CANARY, 'credential', 'api_key');
      const second = new SensitiveString('a'.repeat(CANARY.length), 'credential', 'api_key');

      expect(everyRendering(first)).toEqual(everyRendering(second));
    });

    it('has no placeholder that would print the value', () => {
      for (const attempt of ['{value}', '{raw}', '{secret}', '{reveal}', '{v}']) {
        expect(() => createSensitiveSerializer({ format: attempt })).toThrow(TypeError);
      }
    });

    it('keeps the canary out of the error from a misuse', () => {
      try {
        sensitiveSerializer.serialize(CANARY);
        expect.unreachable('should have thrown');
      } catch (error) {
        const thrown = error as Error;

        expect(thrown.message).not.toContain(CANARY);
        expect(String(thrown.stack)).not.toContain(CANARY);
        expect(util.inspect(thrown)).not.toContain(CANARY);
      }
    });
  });

  describe('the rendering does not go through the value', () => {
    it('does not call reveal', () => {
      const secret = new SensitiveString(CANARY, 'credential', 'api_key');
      const reveal = vi.spyOn(secret, 'reveal');

      everyRendering(secret);

      expect(reveal).not.toHaveBeenCalled();
    });

    it('does not fire the audit hook of the surrounding context', () => {
      // A snapshot is an observation of shape. If rendering one counted as a
      // reveal, every snapshot in a suite would land in the audit log and the
      // log would stop meaning that someone read a value.
      const secret = new SensitiveString(CANARY, 'credential', 'api_key');
      const auditReveal = vi.fn();

      withRevealContext({ name: 'snapshot', auditReveal }, () => {
        everyRendering(secret);
      });

      expect(auditReveal).not.toHaveBeenCalled();
    });

    it('renders a value whose class policy refuses every reveal', () => {
      // A policy this strict is the case where a snapshot matters most, and a
      // serializer built on `reveal()` would make the snapshot throw.
      registerPolicy(
        {
          name: 'credential',
          redact: () => '[REDACTED:credential]',
          checkRevealAllowed: () => {
            throw new Error('reveals are denied');
          },
        },
        { overwrite: true }
      );

      const secret = new SensitiveString(CANARY, 'credential', 'api_key');

      // Every rendering, not just the default one: `{length}` and `{expired}`
      // read the instance too, and a change that routed either of them through
      // the gate would break snapshots only under a policy this strict.
      expect(() => everyRendering(secret)).not.toThrow();
      expect(sensitiveSerializer.serialize(secret)).toBe('SensitiveString<credential:api_key>');
    });

    it('renders a value whose deadline has passed', () => {
      const secret = createTestSecret('credential', 'otp', { ttl: 0 });

      expect(() => everyRendering(secret)).not.toThrow();
      expect(sensitiveSerializer.serialize(secret)).toBe('SensitiveString<credential:otp>');
    });
  });

  describe('the rendering does not depend on the policy', () => {
    it('is unchanged by a custom redaction format', () => {
      const secret = new SensitiveString(CANARY, 'credential', 'api_key');
      const before = sensitiveSerializer.serialize(secret);

      registerPolicy(
        { name: 'credential', redact: () => 'a completely different redaction' },
        { overwrite: true }
      );

      expect(sensitiveSerializer.serialize(secret)).toBe(before);
    });

    it('cannot be made to print the value by a policy that redacts to it', () => {
      // `skipRedactValidation` is the escape hatch that lets a policy return the
      // value from `redact()`. A serializer that rendered through `redact()`
      // would put the value into every snapshot of that project's suite.
      registerPolicy(
        { name: 'credential', redact: (value: string) => value },
        { overwrite: true, skipRedactValidation: true }
      );

      const secret = new SensitiveString(CANARY, 'credential', 'api_key');

      expect(secret.toString()).toContain(CANARY);
      expect(sensitiveSerializer.serialize(secret)).not.toContain(CANARY);
    });
  });
});
