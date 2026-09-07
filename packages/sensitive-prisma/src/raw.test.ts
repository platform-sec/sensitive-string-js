import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { describe, expect, it } from 'vitest';

import { PrismaConfigError, PrismaFieldTypeError } from './errors.js';
import { wrapRows } from './raw.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

describe('wrapRows', () => {
  // TEST-PRISMA-U010
  it('wraps configured columns and leaves the rest alone', () => {
    const rows = [{ id: 1, email: CANARY, name: 'A' }];
    const [user] = wrapRows(rows, { email: 'sensitive' });

    expect(user?.email).toBeInstanceOf(SensitiveString);
    expect(user?.email.reveal({ name: 'test' })).toBe(CANARY);
    expect(user?.id).toBe(1);
    expect(user?.name).toBe('A');
  });

  it('applies the configured class and label', () => {
    const [row] = wrapRows([{ passwordHash: 'h' }], {
      passwordHash: { klass: 'credential', label: 'password' },
    });

    expect(row?.passwordHash.klass).toBe('credential');
    expect(row?.passwordHash.label).toBe('password');
  });

  it('adds no key for a configured column the row does not have', () => {
    const [row] = wrapRows([{ id: 1 }], { email: 'sensitive' });

    expect(Object.keys(row ?? {})).toEqual(['id']);
    expect('email' in (row ?? {})).toBe(false);
  });

  it('does not modify the input rows', () => {
    const rows = [{ email: CANARY }];
    const wrapped = wrapRows(rows, { email: 'sensitive' });

    expect(rows[0]?.email).toBe(CANARY);
    expect(wrapped[0]).not.toBe(rows[0]);
  });

  it('passes null and undefined through', () => {
    const [row] = wrapRows([{ nickname: null, missing: undefined }], {
      nickname: { klass: 'sensitive', nullable: true },
      missing: 'sensitive',
    });

    expect(row?.nickname).toBeNull();
    expect(row?.missing).toBeUndefined();
  });

  it('wraps the empty string', () => {
    const [row] = wrapRows([{ email: '' }], { email: 'sensitive' });

    expect(row?.email).toBeInstanceOf(SensitiveString);
    expect(row?.email.isEmpty()).toBe(true);
  });

  it('wraps each element of a list column', () => {
    const [row] = wrapRows([{ codes: ['a', 'b'] }], { codes: { klass: 'credential', list: true } });

    expect(row?.codes).toHaveLength(2);
    expect(row?.codes[0]).toBeInstanceOf(SensitiveString);
    expect(row?.codes[1]?.reveal({ name: 'test' })).toBe('b');
  });

  it('handles an empty result set', () => {
    expect(wrapRows([], { email: 'sensitive' })).toEqual([]);
  });

  it('wraps every row', () => {
    const wrapped = wrapRows([{ email: 'a' }, { email: 'b' }], { email: 'sensitive' });

    expect(wrapped).toHaveLength(2);
    expect(wrapped.every((row) => row.email instanceof SensitiveString)).toBe(true);
  });

  // Pitfall 7: an already wrapped value must not be buried a level deeper.
  it('leaves an existing instance alone', () => {
    const instance = new SensitiveString(CANARY, 'sensitive');
    const [row] = wrapRows([{ email: instance }], { email: 'sensitive' });

    expect(row?.email).toBe(instance);
    expect(row?.email.reveal({ name: 'test' })).toBe(CANARY);
  });

  it('is idempotent', () => {
    const once = wrapRows([{ email: CANARY }], { email: 'sensitive' });
    const twice = wrapRows(once, { email: 'sensitive' });

    expect(twice[0]?.email).toBe(once[0]?.email);
  });

  describe('refusals', () => {
    it('rejects a spec that names an unregistered class', () => {
      expect(() => wrapRows([{ email: CANARY }], { email: 'secert' as never })).toThrow(
        PrismaConfigError
      );
    });

    it('validates the spec before it touches a row', () => {
      expect(() => wrapRows([], { email: 'secert' as never })).toThrow(PrismaConfigError);
    });

    it('refuses a named column that is not a string', () => {
      expect(() => wrapRows([{ email: 42 }], { email: 'sensitive' })).toThrow(PrismaFieldTypeError);
    });

    it('names the model in the refusal when one is given', () => {
      expect(() => wrapRows([{ email: 42 }], { email: 'sensitive' }, 'User')).toThrow(
        /User\.email/
      );
    });

    it('keeps the value out of the refusal', () => {
      try {
        wrapRows([{ email: { nested: CANARY } }], { email: 'sensitive' });
        expect.unreachable('should have thrown');
      } catch (error) {
        expect(String((error as Error).message)).not.toContain(CANARY);
      }
    });
  });

  it('does not leak through serialization of a wrapped row', () => {
    const [row] = wrapRows([{ id: 1, email: CANARY }], { email: 'sensitive' });

    expect(JSON.stringify(row)).not.toContain(CANARY);
    expect(String(row?.email)).not.toContain(CANARY);
  });
});
