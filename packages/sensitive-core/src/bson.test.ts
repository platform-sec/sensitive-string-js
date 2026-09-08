import { describe, it, expect } from 'vitest';
import { serialize } from 'bson';
import { SensitiveString } from './sensitive-string.js';
import { SensitiveBsonError } from './bson.js';
import { SensitiveStringError } from './errors.js';

/**
 * BSON is the one serializer this library refuses rather than redacts.
 *
 * These drive the real `bson` encoder, because the whole change rests on a
 * claim about it: that it dispatches to `toBSON()` and ignores `toJSON()`. A
 * test that called `value.toBSON()` directly would pass whether or not that is
 * true, and the bug it is guarding against is exactly the encoder taking a
 * different path.
 */
const CANARY = 'LEAKED_SECRET_abc123xyz';

/** The encoder's output, as a byte string that can be searched. */
const encoded = (doc: Record<string, unknown>): string =>
  Buffer.from(serialize(doc)).toString('latin1');

describe('BSON serialization', () => {
  it('refuses a value at the top level of a document', () => {
    const token = new SensitiveString(CANARY, 'credential', 'token');
    expect(() => serialize({ apiKey: token })).toThrow(SensitiveBsonError);
  });

  it('refuses a value nested in a subdocument', () => {
    const token = new SensitiveString(CANARY, 'credential', 'token');
    expect(() => serialize({ user: { apiKey: token } })).toThrow(SensitiveBsonError);
  });

  it('refuses a value inside an array', () => {
    const token = new SensitiveString(CANARY, 'credential', 'token');
    expect(() => serialize({ keys: [token] })).toThrow(SensitiveBsonError);
  });

  it('names the class and label without carrying the value', () => {
    const token = new SensitiveString(CANARY, 'credential', 'token');
    let raised: unknown;
    try {
      serialize({ apiKey: token });
    } catch (e) {
      raised = e;
    }
    const error = raised as SensitiveBsonError;
    expect(error).toBeInstanceOf(SensitiveStringError);
    expect(error.code).toBe('bson-serialization-refused');
    expect(error.message).toContain('credential:token');
    // The stack is formatted lazily from the message, so read it explicitly
    // rather than trusting that a censored message is enough.
    expect(error.message).not.toContain(CANARY);
    expect(error.stack ?? '').not.toContain(CANARY);
  });

  it('is what the encoder dispatches to, rather than toJSON', () => {
    // The premise of the whole change. If BSON ever honours toJSON() instead,
    // this goes red and the refusal above is decorative.
    const jsonOnly = { toJSON: () => 'JSON_FORM_MARKER' };
    expect(encoded({ v: jsonOnly })).not.toContain('JSON_FORM_MARKER');
    const bsonOnly = { toBSON: () => 'BSON_FORM_MARKER' };
    expect(encoded({ v: bsonOnly })).toContain('BSON_FORM_MARKER');
  });

  it('replaces a silent husk write, which is the corruption it exists to stop', () => {
    // Documents what happened before this method existed: `klass` and `label`
    // are the instance's only own enumerable properties, so the encoder wrote
    // them and dropped the value, with nothing thrown and nothing logged.
    const token = new SensitiveString(CANARY, 'credential', 'token');
    const husk = { klass: token.klass, label: token.label };
    const bytes = encoded({ apiKey: husk });
    expect(bytes).toContain('credential');
    expect(bytes).not.toContain(CANARY);
    // Every classified value collapses to the same bytes, which is why a
    // filter built from one matched a document written from another.
    const other = new SensitiveString('a-completely-different-secret', 'credential', 'token');
    expect(encoded({ apiKey: { klass: other.klass, label: other.label } })).toBe(bytes);
  });

  it('does not leak the value through a revealed write, which is the supported path', () => {
    const token = new SensitiveString(CANARY, 'credential', 'token');
    const bytes = encoded({ apiKey: token.reveal({ name: 'test', reason: 'write' }) });
    expect(bytes).toContain(CANARY);
    // The point is that reaching storage is now explicit and audited, not that
    // the value can never get there.
    expect(() => serialize({ apiKey: token })).toThrow(SensitiveBsonError);
  });

  it('leaves every other serializer redacting rather than throwing', () => {
    const token = new SensitiveString(CANARY, 'credential', 'token');
    expect(() => JSON.stringify({ apiKey: token })).not.toThrow();
    expect(JSON.stringify({ apiKey: token })).not.toContain(CANARY);
    expect(String(token)).not.toContain(CANARY);
  });
});
