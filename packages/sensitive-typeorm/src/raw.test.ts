import { SensitiveString } from '@platform-sec/sensitive-string-core';
import type { DataSource } from 'typeorm';
import { afterEach, describe, expect, it } from 'vitest';
import { TypeOrmMarkerReadError } from './errors.js';
import { CANARY, KEY_CANARY, makeDataSource, testSchema } from './__tests__/fixtures.js';

describe('hydrateRaw', () => {
  const schema = testSchema();
  let ds: DataSource;

  afterEach(async () => {
    if (ds?.isInitialized) await ds.destroy();
  });

  it('wraps the classified columns and leaves the rest by identity', () => {
    const [row] = schema.hydrateRaw('users', [
      { id: 1, name: 'ann', email: CANARY, api_key: KEY_CANARY },
    ]);
    expect(row?.['id']).toBe(1);
    expect(row?.['name']).toBe('ann');
    expect(row?.['email']).toBeInstanceOf(SensitiveString);
    expect((row?.['email'] as SensitiveString<'sensitive'>).klass).toBe('sensitive');
    expect((row?.['api_key'] as SensitiveString<'credential'>).klass).toBe('credential');
  });

  it('produces the same instances find() would have produced', async () => {
    ds = await makeDataSource(schema);
    await ds.getRepository('User').insert({
      name: 'raw',
      email: new SensitiveString(CANARY, 'sensitive'),
      apiKey: new SensitiveString(KEY_CANARY, 'credential'),
    });

    const found = (await ds.getRepository('User').find()) as {
      email: SensitiveString<'sensitive'>;
      apiKey: SensitiveString<'credential'>;
    }[];
    const raw = await ds.query<Record<string, unknown>[]>(
      'SELECT id, name, email, api_key FROM users'
    );
    const hydrated = schema.hydrateRaw('users', raw);

    const fromFind = found[0];
    const fromRaw = hydrated[0];
    expect((fromRaw?.['email'] as SensitiveString<'sensitive'>).reveal({ name: 't' })).toBe(
      fromFind?.email.reveal({ name: 't' })
    );
    expect((fromRaw?.['email'] as SensitiveString<'sensitive'>).klass).toBe(fromFind?.email.klass);
    expect((fromRaw?.['api_key'] as SensitiveString<'credential'>).klass).toBe(
      fromFind?.apiKey.klass
    );
  });

  it('proves the raw path returns plaintext without it', async () => {
    ds = await makeDataSource(schema);
    await ds
      .getRepository('User')
      .insert({ name: 'raw', email: new SensitiveString(CANARY, 'sensitive') });

    const raw = await ds.query<{ email: unknown }[]>('SELECT email FROM users');
    expect(raw[0]?.email).toBe(CANARY);
    expect(raw[0]?.email).not.toBeInstanceOf(SensitiveString);

    const rawQb = await ds
      .createQueryBuilder('User', 'u')
      .select('u.email', 'email')
      .getRawMany<{ email: unknown }>();
    expect(rawQb[0]?.email).toBe(CANARY);
  });

  it('strips a known alias prefix, and nothing by default', () => {
    // getRawMany() on an entity selection returns User_email rather than email.
    // Guessing at the separator would classify api_key by its key suffix, so
    // the prefix has to be named.
    const rows = [{ User_email: CANARY }];
    expect(schema.hydrateRaw('users', rows)[0]?.['User_email']).toBe(CANARY);
    expect(
      schema.hydrateRaw('users', rows, { aliasPrefix: 'User' })[0]?.['User_email']
    ).toBeInstanceOf(SensitiveString);
  });

  it('leaves null, undefined and non-strings alone', () => {
    const [row] = schema.hydrateRaw('users', [{ email: null, api_key: undefined, id: 7 }]);
    expect(row?.['email']).toBeNull();
    expect(row?.['api_key']).toBeUndefined();
    expect(row?.['id']).toBe(7);
  });

  it('raises on a marker, as the read transformer does', () => {
    expect(() => schema.hydrateRaw('users', [{ email: '[REDACTED:sensitive]' }])).toThrow(
      TypeOrmMarkerReadError
    );
  });

  it('copies rather than mutating the rows it was given', () => {
    const rows = [{ email: CANARY }];
    const hydrated = schema.hydrateRaw('users', rows);
    expect(rows[0]?.email).toBe(CANARY);
    expect(hydrated[0]).not.toBe(rows[0]);
  });

  it('wraps nothing for a table the specification does not classify', () => {
    const [row] = schema.hydrateRaw('audit_log', [{ email: CANARY }]);
    expect(row?.['email']).toBe(CANARY);
  });
});
