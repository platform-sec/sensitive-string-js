import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  SensitiveString,
  registerPolicy,
  resetPolicies,
} from '@platform-sec/sensitive-string-core';
import { LeakageDetectedError, expectNotLeaked, expectRedacted } from './assertions.js';
import { UnreadableSecretError } from './canary.js';
import { createExpiredSecret, createTestSecret } from './create-test-secret.js';

const CANARY = 'ASSERTIONS_CANARY_7b2e';

describe('expectNotLeaked', () => {
  beforeEach(() => {
    resetPolicies();
  });

  // TST-TU-ASN-001
  it('passes when the value appears nowhere', () => {
    const secret = createTestSecret('credential', 'api_key');

    expect(() =>
      expectNotLeaked(secret, { status: 'ok' }, 'no secrets here', [1, 2, 3])
    ).not.toThrow();
  });

  it('passes when the value is present but still wrapped', () => {
    const secret = createTestSecret('credential', 'api_key');

    expect(() => expectNotLeaked(secret, { token: secret })).not.toThrow();
  });

  // TST-TU-ASN-002
  it('throws when the raw value is present', () => {
    const secret = createTestSecret('credential', 'api_key');
    const leaked = { token: secret.reveal() };

    expect(() => expectNotLeaked(secret, leaked)).toThrow(LeakageDetectedError);
  });

  // TST-TU-ASN-003
  it('checks every target and names the one that leaked', () => {
    const secret = createTestSecret('credential', 'api_key');
    const raw = secret.reveal();

    try {
      expectNotLeaked(secret, { clean: true }, 'also clean', { header: raw });
      expect.unreachable('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(LeakageDetectedError);
      expect((error as LeakageDetectedError).targetIndex).toBe(2);
      expect((error as LeakageDetectedError).path).toBe('.header');
    }
  });

  it('stops at the first target that leaked', () => {
    const secret = createTestSecret('sensitive');
    const raw = secret.reveal();

    try {
      expectNotLeaked(secret, raw, raw);
      expect.unreachable('should have thrown');
    } catch (error) {
      expect((error as LeakageDetectedError).targetIndex).toBe(0);
    }
  });

  // TST-TU-ASN-004
  it('reports the class, the label, and where the value was found', () => {
    const secret = createTestSecret('credential', 'api_key');
    const message = messageOf(() => expectNotLeaked(secret, { auth: { header: secret.reveal() } }));

    expect(message).toContain('credential');
    expect(message).toContain('api_key');
    expect(message).toContain('[0].auth.header');
  });

  it('never puts the value into its own error', () => {
    const secret = createTestSecret('credential', 'api_key');
    const raw = secret.reveal();
    const error = errorOf(() => expectNotLeaked(secret, `Authorization: Bearer ${raw}`));

    expect(error.message).not.toContain(raw);
    expect(error.message).toContain('[LEAKED VALUE]');
    expect((error as LeakageDetectedError).context).not.toContain(raw);
  });

  it('reports an unlabelled value as (none)', () => {
    const secret = createTestSecret('sensitive');

    expect(messageOf(() => expectNotLeaked(secret, secret.reveal()))).toContain('(none)');
  });

  it('accepts no targets at all', () => {
    expect(() => expectNotLeaked(createTestSecret())).not.toThrow();
  });

  describe('values it did not create', () => {
    it('reveals a foreign instance under a named context', () => {
      const secret = new SensitiveString(CANARY, 'credential', 'api_key');
      const seen: string[] = [];

      registerPolicy(
        {
          name: 'credential',
          redact: () => '[REDACTED:credential]',
          checkRevealAllowed: (ctx) => {
            seen.push(ctx?.name ?? '(none)');
          },
        },
        { overwrite: true }
      );

      expectNotLeaked(secret, { status: 'ok' });

      expect(seen).toEqual(['__test-leak-check__']);
    });

    it('finds a leak of a foreign instance', () => {
      const secret = new SensitiveString(CANARY, 'sensitive', 'email');

      expect(() => expectNotLeaked(secret, { copy: CANARY })).toThrow(LeakageDetectedError);
    });

    it('says the check did not run when a foreign value cannot be read', () => {
      const expired = new SensitiveString(CANARY, 'credential', 'otp', { ttl: 0 });
      const error = errorOf(() => expectNotLeaked(expired, { leaked: CANARY }));

      // The value really is leaked in that target. Reporting the refusal as an
      // ExpiredSensitiveValueError would read as an unrelated failure, and the
      // dangerous reading of it is that the check ran and found nothing.
      expect(error).toBeInstanceOf(UnreadableSecretError);
      expect(error.message).toContain('Cannot check this value');
      expect(error.message).toContain('ExpiredSensitiveValueError');
      expect(error.message).toContain('createTestSecret');
      expect(error.message).not.toContain(CANARY);
      expect((error as UnreadableSecretError).contextName).toBe('__test-leak-check__');
    });

    it('says the check did not run when a policy denies the reveal', () => {
      registerPolicy(
        {
          name: 'sensitive',
          redact: () => '[REDACTED:sensitive]',
          checkRevealAllowed: () => {
            throw new Error('reveal denied');
          },
        },
        { overwrite: true }
      );

      const foreign = new SensitiveString(CANARY, 'sensitive', 'email');
      const error = errorOf(() => expectNotLeaked(foreign, { leaked: CANARY }));

      expect(error).toBeInstanceOf(UnreadableSecretError);
      expect(error.message).toContain('reveal denied');
      expect((error as UnreadableSecretError).cause).toBeInstanceOf(Error);
    });

    it('describes an unlabelled value and a non-Error refusal', () => {
      registerPolicy(
        {
          name: 'sensitive',
          redact: () => '[REDACTED:sensitive]',
          checkRevealAllowed: () => {
            // eslint-disable-next-line @typescript-eslint/only-throw-error -- a non-Error refusal is exactly what this test describes
            throw 'denied by string';
          },
        },
        { overwrite: true }
      );

      const foreign = new SensitiveString(CANARY, 'sensitive');
      const error = errorOf(() => expectNotLeaked(foreign, { leaked: CANARY }));

      expect(error.message).toContain('Label:   (none)');
      expect(error.message).toContain('denied by string');
    });

    it('runs normally on a value this package created, whatever the policy', () => {
      registerPolicy(
        {
          name: 'sensitive',
          redact: () => '[REDACTED:sensitive]',
          checkRevealAllowed: () => {
            throw new Error('reveal denied');
          },
        },
        { overwrite: true }
      );

      const secret = createTestSecret('sensitive', 'email');

      expect(() => expectNotLeaked(secret, { status: 'ok' })).not.toThrow();
    });
  });

  describe('expired values', () => {
    it('still checks a secret this package created after it expires', () => {
      const secret = createExpiredSecret('credential', 'otp');

      // The instance itself refuses to be read, which is the point of the TTL.
      expect(() => secret.reveal()).toThrow();
      expect(() => expectNotLeaked(secret, { status: 'ok' })).not.toThrow();
    });

    it('detects a copy that leaked before the deadline passed', () => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'));

      try {
        const secret = createTestSecret('credential', 'otp', { ttl: 1000 });
        const leakedWhileValid = secret.reveal();

        vi.setSystemTime(new Date('2026-01-01T00:01:00.000Z'));

        expect(() => expectNotLeaked(secret, { log: leakedWhileValid })).toThrow(
          LeakageDetectedError
        );
      } finally {
        vi.useRealTimers();
      }
    });
  });
});

describe('expectRedacted', () => {
  beforeEach(() => {
    resetPolicies();
  });

  afterEach(() => {
    resetPolicies();
  });

  // TST-TU-ASN-005
  it('passes when the output holds the redacted rendering', () => {
    const email = createTestSecret('sensitive', 'email');

    expect(() => expectRedacted(`user=${String(email)}`, email)).not.toThrow();
  });

  it('accepts an object whose serialization redacts', () => {
    const email = createTestSecret('sensitive', 'email');

    const roundTripped = JSON.parse(JSON.stringify({ email })) as object;

    expect(() => expectRedacted(roundTripped, email)).not.toThrow();
  });

  it('accepts an object that still holds the wrapped value', () => {
    const email = createTestSecret('sensitive', 'email');

    expect(() => expectRedacted({ email }, email)).not.toThrow();
  });

  // TST-TU-ASN-006
  it('fails when the raw value is present', () => {
    const email = createTestSecret('sensitive', 'email');
    const output = `user=${email.reveal()} [REDACTED:sensitive]`;

    expect(() => expectRedacted(output, email)).toThrow(LeakageDetectedError);
  });

  it('prefers the leak report over the missing-placeholder report', () => {
    const email = createTestSecret('sensitive', 'email');

    expect(() => expectRedacted(email.reveal(), email)).toThrow(LeakageDetectedError);
  });

  // TST-TU-ASN-007
  it('fails when no redacted rendering is present', () => {
    const email = createTestSecret('sensitive', 'email');
    const message = messageOf(() => expectRedacted('user=(hidden)', email));

    expect(message).toContain('Expected a redaction placeholder');
    expect(message).toContain('[REDACTED:sensitive]');
  });

  it('reports an unlabelled value as (none)', () => {
    const secret = createTestSecret('sensitive');

    expect(messageOf(() => expectRedacted('nothing here', secret))).toContain('(none)');
  });

  it('truncates a long output in the failure message', () => {
    const secret = createTestSecret('sensitive', 'email');
    const message = messageOf(() => expectRedacted('x'.repeat(5000), secret));

    expect(message).toContain('...');
    expect(message.length).toBeLessThan(700);
  });

  it('names a failing custom pattern in the failure message', () => {
    const secret = createTestSecret('sensitive', 'email');
    const message = messageOf(() =>
      expectRedacted('nothing here', secret, { customPattern: /<hidden>/ })
    );

    expect(message).toContain('/<hidden>/');
  });

  // TST-TU-ASN-008
  it('accepts a custom pattern', () => {
    const email = createTestSecret('sensitive', 'email');

    expect(() =>
      expectRedacted('user=<hidden email>', email, { customPattern: /<hidden \w+>/ })
    ).not.toThrow();
  });

  it('fails when the custom pattern does not match', () => {
    const email = createTestSecret('sensitive', 'email');

    expect(() =>
      expectRedacted(`user=${String(email)}`, email, { customPattern: /<hidden \w+>/ })
    ).toThrow(/Expected a redaction placeholder/);
  });

  describe('under a custom policy', () => {
    it('checks the rendering the policy actually produces, not [REDACTED:class]', () => {
      registerPolicy(
        {
          name: 'sensitive',
          redact: (value) => `<${value.length} characters hidden>`,
        },
        { overwrite: true }
      );

      const secret = createTestSecret('sensitive', 'email', { value: 'jane@example.com' });

      expect(() => expectRedacted('user=<16 characters hidden>', secret)).not.toThrow();
      expect(() => expectRedacted('user=[REDACTED:sensitive]', secret)).toThrow(
        /Expected a redaction placeholder/
      );
    });

    it('fails when a policy stops redacting', () => {
      registerPolicy(
        { name: 'sensitive', redact: (value) => value },
        { overwrite: true, skipRedactValidation: true }
      );

      const secret = createTestSecret('sensitive', 'email', { value: 'jane@example.com' });

      expect(() => expectRedacted('user=jane@example.com', secret)).toThrow(LeakageDetectedError);
    });

    it('does not catch a policy that discloses only part of the value', () => {
      registerPolicy(
        { name: 'sensitive', redact: (value) => value.slice(0, 4) },
        { overwrite: true, skipRedactValidation: true }
      );

      const secret = createTestSecret('sensitive', 'email', { value: 'jane@example.com' });

      // Documented limitation: both assertions search for the complete value,
      // so a redaction that discloses a prefix reads as a successful redaction.
      // Partial disclosure is what `mask()` and its `minMasked` floor govern,
      // and `registerPolicy` rejects a partial redaction unless a caller passes
      // `skipRedactValidation` as this test does.
      expect(() => expectRedacted('user=jane', secret)).not.toThrow();
    });
  });
});

function errorOf(fn: () => void): Error {
  try {
    fn();
  } catch (error) {
    return error as Error;
  }

  throw new Error('expected the assertion to throw');
}

function messageOf(fn: () => void): string {
  return errorOf(fn).message;
}
