import { integer, sqliteTable, text } from 'drizzle-orm/sqlite-core';
import { relations } from 'drizzle-orm';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { beforeEach, describe, expect, it } from 'vitest';
import { checkSchema, classifiedColumns } from './check.js';
import { resetClassifiedColumnNames } from './column.js';
import { DrizzleCacheRefusedError, DrizzleDriftError, DrizzleGuardMissingError } from './errors.js';
import { sensitiveLogger } from './logger.js';
import { credentialText, sensitiveText } from './sqlite.js';
import type { DatabaseLike } from './types.js';

beforeEach(() => {
  resetClassifiedColumnNames();
});

const users = sqliteTable('users', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  name: text('name'),
  email: sensitiveText('email', { table: 'users' }).notNull(),
  passwordHash: credentialText('password_hash', { table: 'users' }).notNull(),
});
const posts = sqliteTable('posts', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  authorId: integer('author_id'),
  body: text('body'),
});
const usersRelations = relations(users, ({ many }) => ({ posts: many(posts) }));
const schema = { users, posts, usersRelations };

/** A database handle with only what `checkSchema` reads off it. */
const dbWith = (logger: unknown, cache?: unknown): DatabaseLike => ({
  session: { logger, ...(cache === undefined ? {} : { cache }) },
});

/** A cache object tagged the way Drizzle tags its own entities. */
function cacheOfKind(kind: string): unknown {
  class Fake {}
  Object.defineProperty(Fake, Symbol.for('drizzle:entityKind'), { value: kind });
  return new Fake();
}
const noopCache = (): unknown => cacheOfKind('NoopCache');
const upstashCache = (): unknown => cacheOfKind('UpstashCache');

describe('checkSchema', () => {
  it('finds the classified columns of every table in the schema object', () => {
    const result = checkSchema(dbWith(sensitiveLogger()), schema);
    expect(result.classified.map((c) => c.path).sort()).toEqual([
      'users.email',
      'users.password_hash',
    ]);
    expect(result.classified.find((c) => c.path === 'users.password_hash')).toMatchObject({
      klass: 'credential',
      label: 'password_hash',
      sqlType: 'text',
    });
  });

  it('skips what a schema module exports beside its tables', () => {
    const result = checkSchema(dbWith(sensitiveLogger()), schema);
    expect(result.skipped).toEqual(['usersRelations']);
  });

  it('refuses a database built without the guard', () => {
    expect(() => checkSchema(dbWith(undefined), schema)).toThrow(DrizzleGuardMissingError);
    expect(() => checkSchema(dbWith({ logQuery: () => undefined }), schema)).toThrow(
      DrizzleGuardMissingError
    );
  });

  it('refuses a guard that was told not to refuse', () => {
    expect(() => checkSchema(dbWith(sensitiveLogger({ refuse: false })), schema)).toThrow(
      DrizzleGuardMissingError
    );
  });

  it('names the classified columns in the refusal, and no values', () => {
    try {
      checkSchema(dbWith(undefined), schema);
      expect.unreachable('should have refused');
    } catch (error) {
      const refusal = error as DrizzleGuardMissingError;
      expect(refusal.classifiedColumns).toContain('users.password_hash');
      expect(refusal.message).toContain('sensitiveLogger()');
    }
  });

  it('proceeds unguarded when told to in writing', () => {
    expect(() => checkSchema(dbWith(undefined), schema, { allowUnguarded: true })).not.toThrow();
  });

  it('says nothing about the guard when the schema classifies nothing', () => {
    expect(() => checkSchema(dbWith(undefined), { posts })).not.toThrow();
  });

  it('refuses a configured query cache', () => {
    expect(() => checkSchema(dbWith(sensitiveLogger(), upstashCache()), schema)).toThrow(
      DrizzleCacheRefusedError
    );
  });

  it('accepts the NoopCache every database has by default', () => {
    expect(() => checkSchema(dbWith(sensitiveLogger(), noopCache()), schema)).not.toThrow();
  });

  it('names the cache in the refusal', () => {
    try {
      checkSchema(dbWith(sensitiveLogger(), upstashCache()), schema);
      expect.unreachable('should have refused');
    } catch (error) {
      expect((error as DrizzleCacheRefusedError).cacheKind).toBe('UpstashCache');
    }
  });

  it('proceeds with a cache when told to in writing', () => {
    expect(() =>
      checkSchema(dbWith(sensitiveLogger(), upstashCache()), schema, {
        allowCachedPlaintext: true,
      })
    ).not.toThrow();
  });

  describe('requireClassified', () => {
    const withPlainSsn = {
      people: sqliteTable('people', {
        id: integer('id').primaryKey(),
        ssn: text('ssn'),
        email: sensitiveText('email', { table: 'people' }),
      }),
    };

    it('reports a column that should have been classified and was not', () => {
      expect(() =>
        checkSchema(dbWith(sensitiveLogger()), withPlainSsn, { requireClassified: ['ssn'] })
      ).toThrow(DrizzleDriftError);
    });

    it('names the path and says what is wrong', () => {
      try {
        checkSchema(dbWith(sensitiveLogger()), withPlainSsn, { requireClassified: ['ssn'] });
        expect.unreachable('should have reported drift');
      } catch (error) {
        const drift = error as DrizzleDriftError;
        expect(drift.findings[0]?.path).toBe('people.ssn');
        expect(drift.findings[0]?.detail).toContain('requireClassified');
      }
    });

    it('is satisfied by a classified column of that name', () => {
      expect(() =>
        checkSchema(dbWith(sensitiveLogger()), withPlainSsn, { requireClassified: ['email'] })
      ).not.toThrow();
    });

    it('matches the schema key as well as the database name', () => {
      const table = {
        t: sqliteTable('t', { id: integer('id').primaryKey(), taxId: text('tax_id') }),
      };
      expect(() =>
        checkSchema(dbWith(sensitiveLogger()), table, { requireClassified: ['taxId'] })
      ).toThrow(DrizzleDriftError);
    });
  });

  describe('column defaults', () => {
    const withDefault = {
      t: sqliteTable('t', {
        id: integer('id').primaryKey(),
        secret: sensitiveText('secret').default(new SensitiveString('seed', 'sensitive')),
      }),
    };

    it('reports a classified column carrying one', () => {
      expect(() => checkSchema(dbWith(sensitiveLogger()), withDefault)).toThrow(DrizzleDriftError);
    });

    it('explains that the default lands in the migration', () => {
      try {
        checkSchema(dbWith(sensitiveLogger()), withDefault);
        expect.unreachable('should have reported drift');
      } catch (error) {
        expect((error as DrizzleDriftError).findings[0]?.detail).toContain('migration');
      }
    });

    it('accepts one when told to in writing', () => {
      expect(() =>
        checkSchema(dbWith(sensitiveLogger()), withDefault, { allowColumnDefaults: true })
      ).not.toThrow();
    });
  });
});

describe('classifiedColumns', () => {
  it('reports without enforcing anything', () => {
    expect(
      classifiedColumns(schema)
        .map((c) => c.path)
        .sort()
    ).toEqual(['users.email', 'users.password_hash']);
  });

  it('is empty for a schema that classifies nothing', () => {
    expect(classifiedColumns({ posts })).toEqual([]);
  });
});
