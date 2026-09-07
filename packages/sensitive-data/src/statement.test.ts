import { describe, expect, it } from 'vitest';
import {
  identifiersIn,
  indexClassifiedPaths,
  touchesClassifiedColumn,
  truncateStatement,
} from './statement.js';

describe('identifiersIn', () => {
  it('reads bare and quoted identifiers in three dialects', () => {
    const found = identifiersIn('SELECT "Email", `phone`, [Ssn], id FROM users');
    expect([...found]).toEqual(expect.arrayContaining(['email', 'phone', 'ssn', 'id', 'users']));
  });

  it('is empty for a non-statement', () => {
    expect(identifiersIn('').size).toBe(0);
    expect(identifiersIn(undefined as unknown as string).size).toBe(0);
  });
});

describe('indexClassifiedPaths', () => {
  it('indexes by table, lowercased, skipping plain and bare keys', () => {
    const index = indexClassifiedPaths([
      ['Users.Email', 'sensitive'],
      ['users.id', 'plain'],
      ['password', 'credential'],
      ['public.accounts.token', 'credential'],
    ]);

    expect(index.get('users')).toEqual(new Set(['email']));
    expect(index.get('public.accounts')).toEqual(new Set(['token']));
    expect(index.has('password')).toBe(false);
  });
});

describe('touchesClassifiedColumn', () => {
  const paths = indexClassifiedPaths([['users.email', 'sensitive']]);

  it('answers no when nothing is configured', () => {
    expect(touchesClassifiedColumn('SELECT * FROM users')).toBe(false);
  });

  it('needs both halves of a path', () => {
    expect(touchesClassifiedColumn('SELECT email FROM users', { paths })).toBe(true);
    expect(touchesClassifiedColumn('SELECT id FROM users', { paths })).toBe(false);
    expect(touchesClassifiedColumn('SELECT email FROM contacts', { paths })).toBe(false);
  });

  it('matches a schema-qualified table by its last segment', () => {
    const qualified = indexClassifiedPaths([['public.users.email', 'sensitive']]);
    expect(touchesClassifiedColumn('SELECT email FROM public.users', { paths: qualified })).toBe(
      true
    );
  });

  it('matches a bare registered column anywhere', () => {
    const columns = new Set(['api_key']);
    expect(touchesClassifiedColumn('SELECT api_key FROM anything', { columns })).toBe(true);
    expect(touchesClassifiedColumn('SELECT id FROM anything', { columns })).toBe(false);
  });

  it('answers the rule half through classify, and never on the fallback', () => {
    // The trap: a specification with the usual `fallback: 'plain'` resolves
    // every identifier, so a `classify` that returned the fallback here would
    // report every statement in the process as touching a classified column.
    const classify = (name: string): string | undefined =>
      /password/.test(name) ? 'credential' : undefined;

    expect(touchesClassifiedColumn('SELECT password_hash FROM u', { classify })).toBe(true);
    expect(touchesClassifiedColumn('SELECT id FROM u', { classify })).toBe(false);
    expect(touchesClassifiedColumn('SELECT id FROM u', { classify: () => 'plain' })).toBe(false);
  });
});

describe('truncateStatement', () => {
  it('cuts a long statement and keeps a short one', () => {
    expect(truncateStatement('SELECT 1')).toBe('SELECT 1');
    expect(truncateStatement('x'.repeat(500))).toHaveLength(203);
    expect(truncateStatement(42)).toBe('(not a string)');
  });
});
