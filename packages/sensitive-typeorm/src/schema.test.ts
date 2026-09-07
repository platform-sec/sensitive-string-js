import { describe, expect, it } from 'vitest';
import { TypeOrmCacheRefusedError, TypeOrmConfigError, TypeOrmDriftError } from './errors.js';
import { defineSchema } from './schema.js';
import type { DataSourceLike } from './schema.js';
import { sensitiveColumn } from './transformer.js';
import type { DataSchemaSpec } from './types.js';

const spec: DataSchemaSpec = {
  fields: { 'users.email': 'sensitive', 'users.id': 'plain' },
  rules: [{ pattern: /(^|[._])(token|secret|password)([._]|$)/i, klass: 'credential' }],
  fallback: 'plain',
};

/** A minimal stand-in for the parts of a DataSource `check()` reads. */
function dataSource(
  columns: { table: string; property: string; database: string; transformer?: unknown }[],
  cache?: unknown
): DataSourceLike {
  const byTable = new Map<string, typeof columns>();
  for (const column of columns) {
    byTable.set(column.table, [...(byTable.get(column.table) ?? []), column]);
  }
  return {
    entityMetadatas: [...byTable].map(([tableName, cols]) => ({
      name: tableName,
      tableName,
      columns: cols.map((c) => ({
        propertyName: c.property,
        databaseName: c.database,
        ...(c.transformer === undefined ? {} : { transformer: c.transformer }),
      })),
    })),
    options: cache === undefined ? {} : { cache },
  };
}

describe('defineSchema', () => {
  it('resolves an exact field, then a rule, then the fallback', () => {
    const schema = defineSchema(spec);
    expect(schema.classify('users.email')).toBe('sensitive');
    expect(schema.classify('users.password_hash')).toBe('credential');
    expect(schema.classify('users.name')).toBe('plain');
  });

  it('matches a rule through the bare column name', () => {
    // The alias mechanism, and the reason a rule can be written /password/
    // without the author anticipating which table it sits in.
    const schema = defineSchema(spec);
    expect(schema.classify('accounts.api_token')).toBe('credential');
  });

  it('requires a fallback', () => {
    expect(() => defineSchema({ fields: {} } as unknown as DataSchemaSpec)).toThrow(
      TypeOrmConfigError
    );
  });

  it('refuses an unregistered class in a field or a rule', () => {
    expect(() =>
      defineSchema({ fields: { 'a.b': 'secret' as 'sensitive' }, fallback: 'plain' })
    ).toThrow(TypeOrmConfigError);
    expect(() =>
      defineSchema({
        rules: [{ pattern: /x/, klass: 'secret' as 'sensitive' }],
        fallback: 'plain',
      })
    ).toThrow(TypeOrmConfigError);
  });

  it('refuses an empty path', () => {
    expect(() => defineSchema({ fields: { '': 'sensitive' }, fallback: 'plain' })).toThrow(
      TypeOrmConfigError
    );
  });
});

describe('schema.column', () => {
  const schema = defineSchema(spec);

  it('resolves the class from the specification', () => {
    const transformer = schema.column('users.email');
    const wrapped = transformer.from('a@example.com') as { klass: string; label: string };
    expect(wrapped.klass).toBe('sensitive');
    expect(wrapped.label).toBe('email');
  });

  it('refuses a path the specification classifies as plain', () => {
    // A pass-through transformer is worse than no transformer: it reads as
    // coverage in a review and protects nothing.
    expect(() => schema.column('users.name')).toThrow(TypeOrmConfigError);
    expect(() => schema.column('users.id')).toThrow(TypeOrmConfigError);
  });

  it('carries a schema-qualified table through to the brand', () => {
    const qualified = defineSchema({
      fields: { 'public.users.email': 'sensitive' },
      fallback: 'plain',
    });
    const transformer = qualified.column('public.users.email');
    const wrapped = transformer.from('a@example.com') as { label: string };
    expect(wrapped.label).toBe('email');
  });

  it('applies the schema defaults and lets a per-column option win', () => {
    const strict = defineSchema(spec, { strictWrites: true });
    expect(() => strict.column('users.email').to('a plain string')).toThrow();
    expect(() =>
      strict.column('users.email', { strictWrites: false }).to('a plain string')
    ).not.toThrow();
  });
});

describe('schema.check', () => {
  const schema = defineSchema(spec);

  it('passes when every classified column carries its transformer', () => {
    const ds = dataSource([
      { table: 'users', property: 'id', database: 'id' },
      { table: 'users', property: 'name', database: 'name' },
      {
        table: 'users',
        property: 'email',
        database: 'email',
        transformer: schema.column('users.email'),
      },
    ]);
    expect(() => schema.check(ds)).not.toThrow();
  });

  it('catches a classified column with no transformer', () => {
    const ds = dataSource([{ table: 'users', property: 'email', database: 'email' }]);
    expect(() => schema.check(ds)).toThrow(TypeOrmDriftError);
    try {
      schema.check(ds);
    } catch (error) {
      expect((error as Error).message).toContain("schema.column('users.email')");
    }
  });

  it('catches a transformed column the specification no longer classifies', () => {
    const ds = dataSource([
      {
        table: 'users',
        property: 'name',
        database: 'name',
        transformer: sensitiveColumn('sensitive', { table: 'users', column: 'name' }),
      },
    ]);
    expect(() => schema.check(ds)).toThrow(TypeOrmDriftError);
  });

  it('catches a transformer built for a different column', () => {
    // What a copied schema.column() line looks like. It works, and it audits
    // every reveal under the wrong column.
    const ds = dataSource([
      {
        table: 'users',
        property: 'email',
        database: 'email',
        transformer: schema.column('accounts.api_token'),
      },
    ]);
    expect(() => schema.check(ds)).toThrow(TypeOrmDriftError);
  });

  it('reports every finding at once', () => {
    const ds = dataSource([
      { table: 'users', property: 'email', database: 'email' },
      { table: 'accounts', property: 'apiToken', database: 'api_token' },
    ]);
    try {
      schema.check(ds);
      expect.unreachable('should have reported drift');
    } catch (error) {
      expect((error as TypeOrmDriftError).findings).toHaveLength(2);
    }
  });

  it('looks inside a transformer array', () => {
    const encrypt = { to: (v: unknown) => v, from: (v: unknown) => v };
    const ds = dataSource([
      {
        table: 'users',
        property: 'email',
        database: 'email',
        transformer: [schema.column('users.email'), encrypt],
      },
    ]);
    expect(() => schema.check(ds)).not.toThrow();
  });

  it('classifies by the database name rather than the property name', () => {
    // @Column({ name }) lets the two differ, and the specification is keyed on
    // what the database calls the column.
    const ds = dataSource([
      {
        table: 'users',
        property: 'emailAddress',
        database: 'email',
        transformer: schema.column('users.email'),
      },
    ]);
    expect(() => schema.check(ds)).not.toThrow();
  });

  it('refuses an enabled query result cache', () => {
    const ds = dataSource(
      [
        {
          table: 'users',
          property: 'email',
          database: 'email',
          transformer: schema.column('users.email'),
        },
      ],
      true
    );
    expect(() => schema.check(ds)).toThrow(TypeOrmCacheRefusedError);
    expect(() => schema.check(ds, { allowCachedPlaintext: true })).not.toThrow();
  });

  it('refuses the object form of the cache option too', () => {
    const ds = dataSource(
      [
        {
          table: 'users',
          property: 'email',
          database: 'email',
          transformer: schema.column('users.email'),
        },
      ],
      { type: 'redis', duration: 1000 }
    );
    expect(() => schema.check(ds)).toThrow(TypeOrmCacheRefusedError);
  });

  it('allows cache: false', () => {
    const ds = dataSource(
      [
        {
          table: 'users',
          property: 'email',
          database: 'email',
          transformer: schema.column('users.email'),
        },
      ],
      false
    );
    expect(() => schema.check(ds)).not.toThrow();
  });
});
