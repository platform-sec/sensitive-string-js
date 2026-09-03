import * as util from 'node:util';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  SensitiveString,
  registerPolicy,
  resetPolicies,
  withRevealContext,
} from '@platform-sec/sensitive-string-core';
import type { RevealContext } from '@platform-sec/sensitive-string-core';
import {
  LeakageDetectedError,
  collectFragments,
  createExpiredSecret,
  createMockAuditLog,
  createTestSecret,
  expectNotLeaked,
  expectRedacted,
  findRawValue,
  joinFragments,
  mockRevealContext,
  sensitiveMatchers,
} from '../index.js';

const CANARY = 'TESTING_UTILS_CANARY_a71c';

describe('testing utilities security', () => {
  beforeEach(() => {
    resetPolicies();
  });

  describe('the utilities never emit the value they guard', () => {
    it('keeps the value out of a leak failure, including its stack', () => {
      const secret = createTestSecret('credential', 'api_key');
      const raw = secret.reveal();

      try {
        expectNotLeaked(secret, { authorization: `Bearer ${raw}` });
        expect.unreachable('should have thrown');
      } catch (error) {
        const thrown = error as LeakageDetectedError;

        expect(thrown.message).not.toContain(raw);
        expect(thrown.context).not.toContain(raw);
        expect(String(thrown.stack)).not.toContain(raw);
        expect(util.inspect(thrown)).not.toContain(raw);
      }
    });

    it('keeps the value out of a missing-redaction failure', () => {
      const secret = createTestSecret('sensitive', 'email');
      const raw = secret.reveal();

      try {
        expectRedacted({ note: 'nothing redacted here' }, secret);
        expect.unreachable('should have thrown');
      } catch (error) {
        expect((error as Error).message).not.toContain(raw);
      }
    });

    it('keeps the value out of every matcher message', () => {
      const secret = new SensitiveString(CANARY, 'credential', 'api_key');
      const messages = [
        sensitiveMatchers.toBeSensitiveString(CANARY).message(),
        sensitiveMatchers.toHaveSensitivityClass(secret, 'sensitive').message(),
        sensitiveMatchers.toHaveLabel(secret, 'other').message(),
        sensitiveMatchers.toRevealAs(secret, 'other').message(),
        sensitiveMatchers.toBeExpired(secret).message(),
        sensitiveMatchers.toContainSensitive({ header: CANARY }, secret).message(),
      ];

      for (const message of messages) {
        expect(message).not.toContain(CANARY);
      }
    });

    it('keeps the value out of a recorded audit log', () => {
      const audit = createMockAuditLog();
      const secret = createTestSecret('credential', 'api_key');

      secret.reveal(audit.context);

      expect(util.inspect(audit.entries)).not.toContain(secret.reveal());
      expect(joinFragments(collectFragments(audit.entries))).not.toContain(secret.reveal());
    });

    it('keeps the value out of a recorded mock context', () => {
      const ctx = mockRevealContext('handler');
      const secret = createTestSecret('credential', 'api_key');

      secret.reveal(ctx);

      // The recorded call holds the instance, whose raw value stays behind the
      // private field, so inspecting the recording redacts.
      expect(util.inspect(ctx.calls, { depth: 6 })).not.toContain(secret.reveal());
    });
  });

  describe('the canary registry is not a way to reach a value', () => {
    it('puts nothing on the instance', () => {
      const secret = createTestSecret('credential', 'api_key');
      const raw = secret.reveal();

      // The classification is public by design. The value is not, and the
      // registry does not add a second way to it.
      expect(Reflect.ownKeys(secret)).toEqual(['klass', 'label']);
      expect(Object.values(secret)).not.toContain(raw);
      expect(JSON.stringify(secret)).not.toContain(raw);
      expect(util.inspect(secret)).not.toContain(raw);
      expect(String(secret)).not.toContain(raw);
    });

    it('does not make an expired value readable again', () => {
      const expired = createExpiredSecret('credential', 'otp');

      expect(() => expired.reveal()).toThrow();
      expect(sensitiveMatchers.toRevealAs(expired, 'anything').pass).toBe(false);
    });

    it('does not make a denied value readable', () => {
      registerPolicy(
        {
          name: 'credential',
          redact: () => '[REDACTED:credential]',
          checkRevealAllowed: () => {
            throw new Error('reveal denied');
          },
        },
        { overwrite: true }
      );

      const secret = createTestSecret('credential', 'api_key');

      expect(() => secret.reveal()).toThrow('reveal denied');
      expect(sensitiveMatchers.toRevealAs(secret, 'anything').message()).toContain('reveal denied');
    });
  });

  describe('a leak check does not disturb what it is checking', () => {
    it('makes no reveal at all for a value it created', () => {
      const audits: string[] = [];
      const ctx: RevealContext = {
        name: 'ambient',
        auditReveal: (value) => audits.push(value.klass),
      };
      const secret = createTestSecret('credential', 'api_key');

      withRevealContext(ctx, () => {
        expectNotLeaked(secret, { status: 'ok' });
        expectRedacted(`token=${String(secret)}`, secret);
      });

      expect(audits).toHaveLength(0);
    });

    it('does not attribute its own reveal to an ambient context', () => {
      const audits: string[] = [];
      const ctx: RevealContext = {
        name: 'ambient',
        auditReveal: (value) => audits.push(value.klass),
      };
      const foreign = new SensitiveString(CANARY, 'credential', 'api_key');

      withRevealContext(ctx, () => {
        expectNotLeaked(foreign, { status: 'ok' });
      });

      // The reveal happened under the package's own named context, so the
      // caller's audit log still describes only what the caller did.
      expect(audits).toHaveLength(0);
    });
  });

  describe('output that hides a leak from JSON.stringify', () => {
    it('finds a copy a toJSON drops', () => {
      class ApiResponse {
        constructor(readonly debugToken: string) {}
        toJSON() {
          return { ok: true };
        }
      }

      const secret = createTestSecret('credential', 'api_key');
      const response = new ApiResponse(secret.reveal());

      expect(JSON.stringify(response)).not.toContain(secret.reveal());
      expect(() => expectNotLeaked(secret, response)).toThrow(LeakageDetectedError);
    });

    it('finds a copy hidden behind a non-enumerable property', () => {
      const secret = createTestSecret('credential', 'api_key');
      const response: Record<string, unknown> = { ok: true };
      Object.defineProperty(response, 'raw', { value: secret.reveal(), enumerable: false });

      expect(() => expectNotLeaked(secret, response)).toThrow(LeakageDetectedError);
    });

    it('finds a copy written into a Buffer', () => {
      const secret = createTestSecret('credential', 'api_key');

      expect(() => expectNotLeaked(secret, { body: Buffer.from(secret.reveal(), 'utf8') })).toThrow(
        LeakageDetectedError
      );
    });

    it('finds a copy an impostor pretends to have redacted', () => {
      const secret = createTestSecret('credential', 'api_key');

      // Not a SensitiveString, so it gets no exemption: it is walked like any
      // other object and its own property gives it away.
      const impostor = {
        klass: 'credential',
        stored: secret.reveal(),
        toString: () => '[REDACTED:credential]',
        toJSON: () => '[REDACTED:credential]',
        [Symbol.for('nodejs.util.inspect.custom')]: () => '[REDACTED:credential]',
      };

      expect(JSON.stringify(impostor)).not.toContain(secret.reveal());
      expect(() => expectNotLeaked(secret, impostor)).toThrow(LeakageDetectedError);
    });

    it('finds a copy a policy renders in place of a redaction', () => {
      registerPolicy(
        { name: 'sensitive', redact: (value) => `value was ${value}` },
        { overwrite: true, skipRedactValidation: true }
      );

      const secret = createTestSecret('sensitive', 'email');

      // The value is wrapped, but the wrapper renders it, so it reaches every
      // log line the wrapper appears in. A leak assertion has to say so.
      expect(() => expectNotLeaked(secret, { email: secret })).toThrow(LeakageDetectedError);
    });
  });

  describe('hostile and awkward targets', () => {
    it('survives a getter that throws', () => {
      const secret = createTestSecret('credential', 'api_key');
      const target = {
        get boom(): string {
          throw new Error('nope');
        },
        leaked: secret.reveal(),
      };

      expect(() => expectNotLeaked(secret, target)).toThrow(LeakageDetectedError);
    });

    it('survives a toString and a toJSON that throw', () => {
      const secret = createTestSecret('credential', 'api_key');
      const target = {
        toString() {
          throw new Error('nope');
        },
        toJSON() {
          throw new Error('nope');
        },
        leaked: secret.reveal(),
      };

      expect(() => expectNotLeaked(secret, target)).toThrow(LeakageDetectedError);
    });

    it('survives a policy whose redact throws', () => {
      registerPolicy(
        {
          name: 'sensitive',
          redact: () => {
            throw new Error('policy exploded');
          },
        },
        { overwrite: true, skipRedactValidation: true }
      );

      const secret = createTestSecret('sensitive', 'email');

      expect(() => expectNotLeaked(secret, { wrapped: secret })).not.toThrow();
      expect(joinFragments(collectFragments({ wrapped: secret }))).toContain('redaction threw');
    });

    it('survives a cycle and still reports the leak', () => {
      const secret = createTestSecret('credential', 'api_key');
      const target: Record<string, unknown> = { leaked: secret.reveal() };
      target['self'] = target;
      target['siblings'] = [target, target];

      expect(() => expectNotLeaked(secret, target)).toThrow(LeakageDetectedError);
    });

    it('terminates on a Proxy that fabricates keys', () => {
      const secret = createTestSecret('credential', 'api_key');
      let depth = 0;
      const target: object = new Proxy(
        {},
        {
          ownKeys: () => ['a'],
          getOwnPropertyDescriptor: () => ({
            configurable: true,
            enumerable: true,
            value: depth++ < 1000 ? new Proxy({}, {}) : 'end',
          }),
        }
      );

      expect(() => expectNotLeaked(secret, target)).not.toThrow();
    });
  });

  describe('canary generation', () => {
    it('does not collapse when Math.random is stubbed', () => {
      const stub = vi.spyOn(Math, 'random').mockReturnValue(0.5);

      try {
        const first = createTestSecret().reveal();
        const second = createTestSecret().reveal();

        expect(first).not.toBe(second);
      } finally {
        stub.mockRestore();
      }
    });

    it('produces a value no realistic fixture would collide with', () => {
      const value = createTestSecret().reveal();

      expect(value).toMatch(/^__CANARY_\d+_\d+_[0-9a-f]{12}__$/);
    });

    it('does not reuse a value across classes or labels', () => {
      const values = [
        createTestSecret('credential', 'api_key'),
        createTestSecret('credential', 'api_key'),
        createTestSecret('sensitive', 'email'),
      ].map((secret) => secret.reveal());

      expect(new Set(values).size).toBe(3);
    });
  });

  describe('findRawValue on a target that is itself sensitive', () => {
    it('does not report the wrapper it was asked about', () => {
      const secret = createTestSecret('credential', 'api_key');

      expect(findRawValue(secret, secret.reveal())).toBeUndefined();
    });
  });
});
