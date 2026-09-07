/**
 * The shape of every refusal this package raises.
 *
 * `SensitiveStringError` exists so a caller can catch "any refusal from this
 * library" without naming each one, and `code` exists so a log line or a
 * metric can discriminate them without a prototype chain. Both promises are
 * only worth anything if they hold for every error, including the next one
 * somebody adds.
 *
 * So this suite drives off the module's own export list rather than a list
 * written here: an error added without the base, without a code, or with a
 * code that collides with an existing one fails, and so does one added
 * without a row in the sample table below.
 */
import { describe, expect, it } from 'vitest';
import * as core from '../index.js';
import { SensitiveStringError } from '../index.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

/** Every export whose name ends in `Error`, which is the taxonomy plus its base. */
const EXPORTED_ERROR_NAMES = Object.keys(core)
  .filter((name) => name.endsWith('Error'))
  .sort();

/**
 * One constructed instance per concrete error, with its documented code.
 *
 * A table rather than reflection, because the constructors take different
 * arguments and a generic `new C()` would assert on errors built out of
 * nothing. The completeness check below is what keeps it honest.
 */
const SAMPLES: readonly (readonly [string, SensitiveStringError, string])[] = [
  [
    'ExpiredSensitiveValueError',
    new core.ExpiredSensitiveValueError(new Date(0), new Date(1), 'otp', 'key'),
    'expired-value',
  ],
  [
    'RenewalNotAllowedError',
    new core.RenewalNotAllowedError('policy', 'session'),
    'renewal-not-allowed',
  ],
  [
    'RevealDuringRedactionError',
    new core.RevealDuringRedactionError('credential', 'api_key'),
    'reveal-during-redaction',
  ],
  [
    'RevealLimitExceededError',
    new core.RevealLimitExceededError(1, 2, 'bootstrap'),
    'reveal-limit-exceeded',
  ],
  ['RevealRateLimitError', new core.RevealRateLimitError(50, 10, 'api_key'), 'reveal-rate-limited'],
  [
    'RevokedSensitiveValueError',
    new core.RevokedSensitiveValueError('rotated', new Date(0), 'api_key'),
    'revoked-value',
  ],
  [
    'MalformedWorkerPayloadError',
    new core.MalformedWorkerPayloadError('detail'),
    'malformed-payload',
  ],
  ['ConsumedWorkerPayloadError', new core.ConsumedWorkerPayloadError(), 'consumed-payload'],
  ['MissingWorkerValueError', new core.MissingWorkerValueError('token'), 'missing-value'],
  [
    'UnregisteredClassError',
    new core.UnregisteredClassError('ssn', 'pii', ['sensitive', 'credential']),
    'unregistered-class',
  ],
  ['UnauditedWorkerError', new core.UnauditedWorkerError(), 'unaudited-worker'],
  [
    'UnportableDataError',
    new core.UnportableDataError('data.f', 'clone', 'why'),
    'unportable-data',
  ],
  [
    'UnshareableConstraintError',
    new core.UnshareableConstraintError('boot', ['maxReveals']),
    'unshareable-constraint',
  ],
  [
    'DeterministicRedactionNotAllowedError',
    new core.DeterministicRedactionNotAllowedError('credential'),
    'deterministic-redaction-refused',
  ],
];

describe('the error taxonomy', () => {
  it('samples every concrete error the package exports', () => {
    // The check that makes this file self-maintaining. A new error class
    // exported without a row here fails, rather than shipping with none of
    // the guarantees below asserted about it.
    expect(SAMPLES.map(([name]) => name).sort()).toEqual(
      EXPORTED_ERROR_NAMES.filter((name) => name !== 'SensitiveStringError')
    );
  });

  it.each(EXPORTED_ERROR_NAMES.filter((name) => name !== 'SensitiveStringError'))(
    '%s extends SensitiveStringError',
    (name) => {
      // Read off the export rather than off the sample, so a class that is
      // exported but somehow absent from the table is still checked.
      const constructor = (core as unknown as Record<string, unknown>)[name];

      expect(Object.getPrototypeOf(constructor)).toBe(SensitiveStringError);
    }
  );

  it.each(SAMPLES)('%s is an Error, its own type, and carries its code', (name, error, code) => {
    // `instanceof Error` and the class's own `instanceof` both held before
    // the base was introduced, and a handler in the wild depends on each.
    expect(error).toBeInstanceOf(Error);
    expect(error).toBeInstanceOf(SensitiveStringError);
    expect(error.name).toBe(name);
    expect(error.code).toBe(code);
    // The name reaches a stack trace, which is where somebody reads it first.
    expect(error.stack).toContain(name);
  });

  it('gives every error a distinct code', () => {
    const codes = SAMPLES.map(([, error]) => error.code);

    expect(new Set(codes).size).toBe(codes.length);
  });

  it('spells every code as a stable, loggable slug', () => {
    // The flat discriminator a metric or a log line keys on. Anything that
    // needed quoting or casing would be a worse key than the class name.
    for (const [, error] of SAMPLES) {
      expect(error.code).toMatch(/^[a-z][a-z0-9-]*$/);
    }
  });

  it('catches any refusal through the base, which is the point of having one', () => {
    const caught: string[] = [];

    for (const [, error] of SAMPLES) {
      try {
        throw error;
      } catch (thrown) {
        if (thrown instanceof SensitiveStringError) {
          caught.push(thrown.code);
        }
      }
    }

    expect(caught).toHaveLength(SAMPLES.length);
  });

  it('echoes only the key or label the caller supplied, never anything else', () => {
    // A label, a payload key and a revocation reason are developer text and
    // appear in messages by design; that is what makes an error actionable.
    // What must never appear is the protected value. This one is built with
    // the canary in the caller-controlled slot, so the message is exactly the
    // library's own prose plus what the caller put there.
    const keyed = new core.MissingWorkerValueError(CANARY);
    expect(keyed.message).toContain(CANARY);
    expect(keyed.message.replaceAll(CANARY, '')).not.toContain('LEAKED');

    // And the two that take no caller text at all carry none, so neither a
    // key nor a label can reach them by any route.
    for (const error of [new core.ConsumedWorkerPayloadError(), new core.UnauditedWorkerError()]) {
      expect(error.message).not.toContain(CANARY);
      expect(error.message).toMatch(/^[\x20-\x7e]+$/);
    }
  });
});
