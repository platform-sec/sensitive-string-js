import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { describe, expect, it } from 'vitest';

import { normalizeConfig } from './config.js';
import { PrismaFieldTypeError } from './errors.js';
import { buildResultComponent } from './result.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

function build(models: Parameters<typeof normalizeConfig>[0]['models']) {
  return buildResultComponent(normalizeConfig({ models }));
}

describe('buildResultComponent', () => {
  // TEST-PRISMA-U003
  it('emits one needs/compute entry per configured field under the client key', () => {
    const result = build({
      User: { email: 'sensitive', passwordHash: 'credential' },
      PaymentMethod: { cardNumber: 'credential' },
    });

    expect(Object.keys(result).sort()).toEqual(['paymentMethod', 'user']);
    expect(Object.keys(result['user'] ?? {}).sort()).toEqual(['email', 'passwordHash']);
    expect(result['user']?.['email']?.needs).toEqual({ email: true });
    expect(result['paymentMethod']?.['cardNumber']?.needs).toEqual({ cardNumber: true });
  });

  // TEST-PRISMA-U004: nothing wraps by surprise.
  it('emits nothing for a model or field that is not configured', () => {
    const result = build({ User: { email: 'sensitive' } });

    expect(result['post']).toBeUndefined();
    expect(result['user']?.['name']).toBeUndefined();
  });

  it('wraps with the configured class and label', () => {
    const result = build({ User: { email: { klass: 'credential', label: 'login' } } });
    const wrapped = result['user']?.['email']?.compute({ email: CANARY });

    expect(wrapped).toBeInstanceOf(SensitiveString);
    expect((wrapped as SensitiveString<'credential'>).klass).toBe('credential');
    expect((wrapped as SensitiveString<'credential'>).label).toBe('login');
  });

  it('defaults the label to the field name', () => {
    const result = build({ User: { email: 'sensitive' } });
    const wrapped = result['user']?.['email']?.compute({ email: CANARY });

    expect((wrapped as SensitiveString<'sensitive'>).label).toBe('email');
  });

  it('does not leak the value through the wrapped instance', () => {
    const result = build({ User: { email: 'sensitive' } });
    const wrapped = result['user']?.['email']?.compute({ email: CANARY });

    expect(String(wrapped)).not.toContain(CANARY);
    expect(JSON.stringify({ wrapped })).not.toContain(CANARY);
    expect((wrapped as SensitiveString<'sensitive'>).reveal({ name: 'test' })).toBe(CANARY);
  });

  // TEST-PRISMA-U005 / INV-PRISMA-011
  describe('null and empty handling', () => {
    it('passes null through unchanged', () => {
      const result = build({ User: { nickname: { klass: 'sensitive', nullable: true } } });
      expect(result['user']?.['nickname']?.compute({ nickname: null })).toBeNull();
    });

    it('passes undefined through, for a field a nested select did not fetch', () => {
      const result = build({ User: { nickname: 'sensitive' } });
      expect(result['user']?.['nickname']?.compute({})).toBeUndefined();
    });

    it('wraps the empty string rather than turning it into null', () => {
      const result = build({ User: { email: 'sensitive' } });
      const wrapped = result['user']?.['email']?.compute({ email: '' });

      expect(wrapped).toBeInstanceOf(SensitiveString);
      expect((wrapped as SensitiveString<'sensitive'>).isEmpty()).toBe(true);
    });
  });

  // TEST-PRISMA-U009 / INV-PRISMA-014
  describe('scalar lists', () => {
    it('wraps each element', () => {
      const result = build({ User: { recoveryCodes: { klass: 'credential', list: true } } });
      const wrapped = result['user']?.['recoveryCodes']?.compute({
        recoveryCodes: ['one', 'two'],
      });

      expect(Array.isArray(wrapped)).toBe(true);
      const items = wrapped as SensitiveString<'credential'>[];
      expect(items).toHaveLength(2);
      expect(items[0]).toBeInstanceOf(SensitiveString);
      expect(items[1]?.reveal({ name: 'test' })).toBe('two');
    });

    it('returns an empty array for an empty list', () => {
      const result = build({ User: { recoveryCodes: { klass: 'credential', list: true } } });
      expect(result['user']?.['recoveryCodes']?.compute({ recoveryCodes: [] })).toEqual([]);
    });

    // The runtime follows the value, not the declaration: a list column left
    // undeclared still wraps element by element rather than handing an array
    // to the SensitiveString constructor.
    it('wraps a list even when the spec did not declare one', () => {
      const result = build({ User: { recoveryCodes: 'credential' } });
      const wrapped = result['user']?.['recoveryCodes']?.compute({ recoveryCodes: ['a'] });

      expect((wrapped as SensitiveString<'credential'>[])[0]).toBeInstanceOf(SensitiveString);
    });
  });

  describe('double wrapping', () => {
    // Applying the extension twice, or stacking it under another result
    // extension for the same field, hands `compute` a value that is already an
    // instance. Wrapping it again would bury the string a level down.
    it('returns an existing instance untouched', () => {
      const result = build({ User: { email: 'sensitive' } });
      const first = result['user']?.['email']?.compute({ email: CANARY });
      const second = result['user']?.['email']?.compute({ email: first });

      expect(second).toBe(first);
      expect((second as SensitiveString<'sensitive'>).reveal({ name: 'test' })).toBe(CANARY);
    });

    it('leaves instances inside a list alone', () => {
      const result = build({ User: { codes: { klass: 'credential', list: true } } });
      const inner = new SensitiveString('one', 'credential');
      const wrapped = result['user']?.['codes']?.compute({ codes: [inner, 'two'] });

      expect((wrapped as SensitiveString<'credential'>[])[0]).toBe(inner);
    });
  });

  describe('a column that is not a string', () => {
    it.each([
      ['a number', 42],
      ['a boolean', true],
      ['a Date', new Date()],
      ['a Uint8Array', new Uint8Array([1, 2])],
      ['an object', { nested: true }],
    ])('refuses %s and names the model and field', (_label, value) => {
      const result = build({ User: { email: 'sensitive' } });

      expect(() => result['user']?.['email']?.compute({ email: value })).toThrow(
        PrismaFieldTypeError
      );
      expect(() => result['user']?.['email']?.compute({ email: value })).toThrow(/User\.email/);
    });

    it('refuses a non-string element of a list', () => {
      const result = build({ User: { codes: { klass: 'credential', list: true } } });
      expect(() => result['user']?.['codes']?.compute({ codes: ['ok', 7] })).toThrow(
        PrismaFieldTypeError
      );
    });

    it('does not put the value in the message', () => {
      const result = build({ User: { email: 'sensitive' } });
      try {
        result['user']?.['email']?.compute({ email: { secret: CANARY } });
        expect.unreachable('should have thrown');
      } catch (error) {
        const text = `${String((error as Error).message)} ${String((error as Error).stack)}`;
        expect(text).not.toContain(CANARY);
        expect((error as PrismaFieldTypeError).code).toBe('PRISMA_FIELD_NOT_A_STRING');
      }
    });
  });

  // INV-PRISMA-021: each field's configuration is resolved once, when the
  // extension is built, and lives in the closure from then on.
  it('closes over its own configuration rather than a shared one', () => {
    const first = build({ User: { email: { klass: 'credential', label: 'first' } } });
    const entry = first['user']?.['email'];

    // A second, differently configured component must not disturb the first.
    const second = build({ User: { email: { klass: 'sensitive', label: 'second' } } });

    expect((entry?.compute({ email: CANARY }) as SensitiveString<'credential'>).label).toBe(
      'first'
    );
    expect(
      (second['user']?.['email']?.compute({ email: CANARY }) as SensitiveString<'sensitive'>).klass
    ).toBe('sensitive');
    expect(first['user']?.['email']).toBe(entry);
  });
});
