import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { integer, sqliteTable, text } from 'drizzle-orm/sqlite-core';
import { beforeEach, describe, expect, it } from 'vitest';
import { resetClassifiedColumnNames } from './column.js';
import { DrizzleConfigError, DrizzleMarkerReadError } from './errors.js';
import { hydrateRawRows } from './raw.js';
import { credentialText, sensitiveText } from './sqlite.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

beforeEach(() => {
  resetClassifiedColumnNames();
});

const users = sqliteTable('users', {
  id: integer('id').primaryKey(),
  name: text('name'),
  email: sensitiveText('email', { table: 'users' }),
  passwordHash: credentialText('password_hash', { table: 'users' }),
});

describe('hydrateRawRows', () => {
  it('wraps the classified columns of a row keyed by database name', () => {
    const [row] = hydrateRawRows(
      [{ id: 1, name: 'A', email: 'a@example.com', password_hash: CANARY }],
      users
    );
    expect(row?.['email']).toBeInstanceOf(SensitiveString);
    expect(row?.['password_hash']).toBeInstanceOf(SensitiveString);
    expect((row?.['password_hash'] as SensitiveString<'credential'>).klass).toBe('credential');
    expect(row?.['id']).toBe(1);
    expect(row?.['name']).toBe('A');
  });

  it('wraps a row keyed by schema key', () => {
    const [row] = hydrateRawRows([{ passwordHash: CANARY }], users);
    expect(row?.['passwordHash']).toBeInstanceOf(SensitiveString);
  });

  it('keeps the canary out of anything the row serialises to', () => {
    const rows = hydrateRawRows([{ email: 'a@example.com', password_hash: CANARY }], users);
    expect(JSON.stringify(rows)).not.toContain(CANARY);
  });

  it('leaves null and undefined alone', () => {
    const [row] = hydrateRawRows([{ email: null, password_hash: undefined }], users);
    expect(row?.['email']).toBeNull();
    expect(row?.['password_hash']).toBeUndefined();
  });

  it('passes an unmatched key through by default', () => {
    const [row] = hydrateRawRows([{ total: 7 }], users);
    expect(row?.['total']).toBe(7);
  });

  it('refuses an unmatched key when told to', () => {
    expect(() => hydrateRawRows([{ total: 7 }], users, { allowUnknownKeys: false })).toThrow(
      DrizzleConfigError
    );
  });

  it('maps a key the caller chose in a sql selection', () => {
    const [row] = hydrateRawRows([{ e: 'a@example.com' }], users, { keys: { e: 'email' } });
    expect(row?.['e']).toBeInstanceOf(SensitiveString);
  });

  it('refuses a marker in a raw row exactly as an ordinary select would', () => {
    expect(() => hydrateRawRows([{ email: '[REDACTED:sensitive]' }], users)).toThrow(
      DrizzleMarkerReadError
    );
  });

  it('does not mutate the rows it was given', () => {
    const rows = [{ email: 'a@example.com' }];
    hydrateRawRows(rows, users);
    expect(rows[0]?.email).toBe('a@example.com');
  });

  it('handles an empty list', () => {
    expect(hydrateRawRows([], users)).toEqual([]);
  });

  it('refuses something that is not a table', () => {
    expect(() => hydrateRawRows([{ email: 'x' }], 'users')).toThrow(DrizzleConfigError);
    expect(() => hydrateRawRows([{ email: 'x' }], {})).toThrow(DrizzleConfigError);
  });

  it('says why an array-shaped row cannot be hydrated', () => {
    expect(() => hydrateRawRows([1 as unknown as Record<string, unknown>], users)).toThrow(
      /values\(\)/
    );
  });
});
