import { describe, expect, it } from 'vitest';
import {
  REFERENCE_VERSION,
  SensitiveString,
  carriesReferenceMarker,
  containsSensitive,
  isSensitiveValueReference,
  redactCopy,
  redactInStructure,
  referenceFormatVersion,
  safeStringify,
  sensitiveClassesIn,
  sensitiveFormat,
} from './index.js';
import type { SensitiveValueReference } from './index.js';

const CANARY = 'LEAKED_SECRET_ref_9f31';

/** What `toReference()` in the secrets package produces, built here by hand. */
function reference(overrides: Partial<SensitiveValueReference> = {}): SensitiveValueReference {
  return {
    __sensitiveRef: true,
    v: REFERENCE_VERSION,
    store: 'vault-prod',
    path: 'kv/payments/stripe',
    version: '7',
    ...overrides,
  };
}

describe('isSensitiveValueReference', () => {
  it('accepts a well-formed reference', () => {
    expect(isSensitiveValueReference(reference())).toBe(true);
  });

  it('accepts one carrying only the required members', () => {
    expect(isSensitiveValueReference({ __sensitiveRef: true, v: 1, store: 's', path: 'p' })).toBe(
      true
    );
  });

  it('accepts the advisory members when they are well formed', () => {
    expect(
      isSensitiveValueReference(
        reference({ field: 'password', klass: 'credential', label: 'kv/payments/stripe' })
      )
    ).toBe(true);
  });

  it('rejects a value that is not an object', () => {
    for (const value of [null, undefined, 'kv/payments/stripe', 7, true]) {
      expect(isSensitiveValueReference(value)).toBe(false);
    }
  });

  it('rejects an object without the marker', () => {
    const { __sensitiveRef: _marker, ...rest } = reference();

    expect(isSensitiveValueReference(rest)).toBe(false);
  });

  it('rejects a marker that is not exactly true', () => {
    expect(isSensitiveValueReference(reference({ __sensitiveRef: 1 as never }))).toBe(false);
  });

  it('rejects a version this build does not know', () => {
    expect(isSensitiveValueReference(reference({ v: 2 as never }))).toBe(false);
  });

  it('rejects a missing or empty store, which is what makes a path ambiguous', () => {
    expect(isSensitiveValueReference(reference({ store: undefined as never }))).toBe(false);
    expect(isSensitiveValueReference(reference({ store: '' }))).toBe(false);
  });

  it('rejects a missing or empty path', () => {
    expect(isSensitiveValueReference(reference({ path: undefined as never }))).toBe(false);
    expect(isSensitiveValueReference(reference({ path: '' }))).toBe(false);
  });

  it('rejects an optional member of the wrong type', () => {
    expect(isSensitiveValueReference(reference({ version: 7 as never }))).toBe(false);
    expect(isSensitiveValueReference(reference({ field: {} as never }))).toBe(false);
    expect(isSensitiveValueReference(reference({ label: false as never }))).toBe(false);
  });

  it('rejects an advisory class the receiving process never registered', () => {
    expect(isSensitiveValueReference(reference({ klass: 'credential-hsm' as never }))).toBe(false);
  });

  it('survives an object that throws from every property read', () => {
    const hostile = new Proxy(
      {},
      {
        get(): never {
          throw new ReferenceError('no');
        },
      }
    );

    expect(() => isSensitiveValueReference(hostile)).not.toThrow();
    expect(isSensitiveValueReference(hostile)).toBe(false);
  });
});

describe('carriesReferenceMarker and referenceFormatVersion', () => {
  it('separates "not a reference" from "a reference this build cannot read"', () => {
    const future = { __sensitiveRef: true, v: 2, store: 's', path: 'p' };

    expect(carriesReferenceMarker(future)).toBe(true);
    expect(referenceFormatVersion(future)).toBe(2);
    expect(isSensitiveValueReference(future)).toBe(false);

    expect(carriesReferenceMarker({ path: 'p' })).toBe(false);
  });

  it('answers undefined for a version that is not a number, rather than echoing it', () => {
    expect(referenceFormatVersion({ __sensitiveRef: true, v: CANARY })).toBeUndefined();
    expect(referenceFormatVersion({ __sensitiveRef: true, v: Number.NaN })).toBeUndefined();
  });

  it('does not mistake a serialize() result for a reference', () => {
    const wire = new SensitiveString(CANARY, 'credential', 'token').serialize({ name: 'test' });

    expect(carriesReferenceMarker(wire)).toBe(false);
    expect(isSensitiveValueReference(wire)).toBe(false);
  });
});

/**
 * These assertions are positive on purpose.
 *
 * A reference carries no secret material and resolving one needs credentials
 * the reader of a log would have to hold independently, so every walk emits it
 * as it is. That is a decision rather than an accident, and a later change to
 * redact everything carrying a `__sensitive`-shaped marker would make a
 * reference-passing system undebuggable while passing every leak test in the
 * suite. It fails here instead.
 */
describe('a reference on the log path', () => {
  const nested = () => ({
    job: 'charge',
    key: reference(),
    attempts: [{ key: reference({ field: 'password' }) }],
  });

  it('survives redactInStructure with its path intact', () => {
    const walked = redactInStructure(nested()) as ReturnType<typeof nested>;

    expect(walked.key).toEqual(reference());
    expect(walked.attempts[0]?.key.path).toBe('kv/payments/stripe');
  });

  it('survives redactCopy with its path intact', () => {
    const copied = redactCopy(nested()) as ReturnType<typeof nested>;

    expect(copied.key.store).toBe('vault-prod');
    expect(copied.key.version).toBe('7');
  });

  it('survives safeStringify', () => {
    expect(safeStringify(nested())).toContain('kv/payments/stripe');
  });

  it('survives the winston format', () => {
    const format = sensitiveFormat();
    const info = format.transform({ level: 'info', message: 'charging', ...nested() });

    expect(info).not.toBe(false);
    expect(JSON.stringify(info)).toContain('kv/payments/stripe');
  });

  it('is not reported as sensitive, and names no class', () => {
    expect(containsSensitive(nested())).toBe(false);
    expect(sensitiveClassesIn(nested()).size).toBe(0);
  });

  it('names no class even when it carries an advisory one', () => {
    expect(containsSensitive(reference({ klass: 'credential' }))).toBe(false);
    expect(sensitiveClassesIn(reference({ klass: 'credential' })).size).toBe(0);
  });

  it('does not shield a value that travels beside it', () => {
    const payload = { key: reference(), token: new SensitiveString(CANARY, 'credential') };

    expect(containsSensitive(payload)).toBe(true);
    expect(safeStringify(payload)).not.toContain(CANARY);
    expect(safeStringify(payload)).toContain('kv/payments/stripe');
  });
});
