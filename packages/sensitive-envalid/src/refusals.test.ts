import { describe, it, expect } from 'vitest';

import { credential, makeSensitiveValidator, sensitive } from './validators.js';
import type { SensitiveSpec } from './validators.js';

/**
 * The four options refused at construction, and why each is refused there.
 *
 * Each is a mistake in a schema that is written once, so the right time to
 * report it is when the schema is built rather than when a variable happens to
 * be absent. Every message names the replacement, because an option that
 * silently means something else is the failure this is preventing.
 */

const CANARY = 'LEAKED_SECRET_abc123xyz';

/** The options are typed `never`, so the cast is what a JS caller does. */
function forbidden(option: string, value: unknown): SensitiveSpec {
  return { [option]: value };
}

describe('construction-time refusals', () => {
  it.each(['default', 'devDefault', 'testDefault'])(
    'refuses %s and names sensitiveDefault',
    (option) => {
      expect(() => credential(forbidden(option, CANARY))).toThrow(/sensitiveDefault/);
      expect(() => sensitive(forbidden(option, CANARY))).toThrow(/sensitiveDefault/);
    }
  );

  it('refuses choices and names the format check instead', () => {
    expect(() => credential(forbidden('choices', ['a', 'b']))).toThrow(/`format`/);
  });

  it('says why choices cannot work, not only that it is refused', () => {
    try {
      credential(forbidden('choices', ['a', 'b']));
      expect.unreachable();
    } catch (error) {
      // envalid checks `choices` against the *parsed* value, so an instance
      // never matches and the error message is built from it.
      expect((error as Error).message).toMatch(/parsed value/);
    }
  });

  it('names no value in a refusal', () => {
    for (const option of ['default', 'devDefault', 'testDefault', 'choices']) {
      try {
        credential(forbidden(option, CANARY));
        expect.unreachable();
      } catch (error) {
        expect((error as Error).message).not.toContain(CANARY);
      }
    }
  });

  it('names the class in the refusal, so the schema line is findable', () => {
    expect(() => credential(forbidden('default', 'x'))).toThrow(/credential validator/);
    expect(() => sensitive(forbidden('default', 'x'))).toThrow(/sensitive validator/);
  });

  it('refuses an option set to undefined, because the key is the mistake', () => {
    // `{ default: undefined }` still has the key, and a reader of the schema
    // reads it as a default. envalid reads it the same way: `'default' in spec`
    // is what it checks.
    expect(() => credential(forbidden('default', undefined))).toThrow(/sensitiveDefault/);
  });

  it('accepts everything it does support', () => {
    expect(() =>
      credential({
        label: 'db_password',
        desc: 'the database password',
        example: 'hunter2',
        docs: 'https://example.invalid/db',
        sensitiveDefault: 'dev-fallback',
        format: { check: (raw) => raw.length > 3, detail: 'at least four characters' },
      })
    ).not.toThrow();
  });

  it('accepts no options at all', () => {
    expect(() => credential()).not.toThrow();
    expect(() => makeSensitiveValidator('sensitive')()).not.toThrow();
  });

  it('refuses a spec that is not an object', () => {
    expect(() => credential('credential' as unknown as SensitiveSpec)).toThrow(TypeError);
    expect(() => credential(null as unknown as SensitiveSpec)).toThrow(TypeError);
  });
});
