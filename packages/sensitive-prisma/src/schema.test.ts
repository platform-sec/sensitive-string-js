import { beforeAll, describe, expect, it } from 'vitest';

import { normalizeConfig } from './config.js';
import { PrismaUnknownFieldError, PrismaUnknownModelError } from './errors.js';
import { assertConfigMatchesSchema, readSchemaModels } from './schema.js';
import { createBaseClient } from './__tests__/fixtures.js';

type Client = Awaited<ReturnType<typeof createBaseClient>>;

let client: Client;

beforeAll(async () => {
  client = await createBaseClient();
});

/**
 * Prisma keeps the schema on the client under an internal name, so this suite
 * is the thing standing between a Prisma release that moves it and a
 * validation that silently stops running. `readSchemaModels` is written to
 * return `undefined` rather than throw when the shape is not what it expects,
 * which is the right behaviour and also exactly the failure a test has to
 * catch.
 */
describe('readSchemaModels', () => {
  it('finds the test schema on a real client', () => {
    const schema = readSchemaModels(client);

    expect(schema).toBeDefined();
    expect([...(schema?.keys() ?? [])].sort()).toEqual(['paymentMethod', 'post', 'user']);
  });

  it('keeps the schema casing of each model name', () => {
    const schema = readSchemaModels(client);

    expect(schema?.get('user')?.name).toBe('User');
    expect(schema?.get('paymentMethod')?.name).toBe('PaymentMethod');
  });

  it('lists the scalar fields and omits the relations', () => {
    const user = readSchemaModels(client)?.get('user');

    expect([...(user?.scalars ?? [])].sort()).toEqual([
      'email',
      'id',
      'name',
      'nickname',
      'passwordHash',
    ]);
    expect(user?.scalars.has('posts')).toBe(false);
    expect(user?.scalars.has('cards')).toBe(false);
  });

  it('reads the non-string scalar columns too, so they can be refused by class', () => {
    const card = readSchemaModels(client)?.get('paymentMethod');

    expect(card?.scalars.has('balance')).toBe(true);
    expect(card?.scalars.has('token')).toBe(true);
    expect(card?.scalars.has('createdAt')).toBe(true);
  });

  it.each([
    ['a non-object', 'client'],
    ['null', null],
    ['an object with no runtime data model', {}],
    ['a runtime data model with no models', { _runtimeDataModel: {} }],
    ['a models bag with no fields', { _runtimeDataModel: { models: { User: {} } } }],
  ])('returns undefined for %s rather than throwing', (_label, value) => {
    expect(readSchemaModels(value)).toBeUndefined();
  });
});

/**
 * The gap this closes, measured on Prisma 6.19.3 and 7.10.0: a `result`
 * component keyed by a model Prisma does not know is ignored, and a computed
 * field under a name Prisma does not know is added beside the real column
 * instead of replacing it. In both the configured column reads back as a plain
 * string. TypeScript does not catch either, because `models` is keyed by
 * string.
 */
describe('assertConfigMatchesSchema', () => {
  it('accepts a configuration that matches', () => {
    const config = normalizeConfig({
      models: {
        User: { email: 'sensitive', passwordHash: 'credential' },
        PaymentMethod: { cardNumber: 'credential' },
      },
    });

    expect(() => assertConfigMatchesSchema(client, config)).not.toThrow();
  });

  it('accepts a configuration written in client casing', () => {
    const config = normalizeConfig({ models: { user: { email: 'sensitive' } } });

    expect(() => assertConfigMatchesSchema(client, config)).not.toThrow();
  });

  it('refuses a misspelled model', () => {
    const config = normalizeConfig({ models: { Usr: { passwordHash: 'credential' } } });

    expect(() => assertConfigMatchesSchema(client, config)).toThrow(PrismaUnknownModelError);
    expect(() => assertConfigMatchesSchema(client, config)).toThrow(
      /Model 'Usr' is configured but the Prisma client has no 'usr'/
    );
  });

  it('suggests the model whose casing differs only', () => {
    const config = normalizeConfig({ models: { USER: { email: 'sensitive' } } });

    expect(() => assertConfigMatchesSchema(client, config)).toThrow(/Did you mean 'user'\?/);
  });

  it('refuses a misspelled field', () => {
    const config = normalizeConfig({ models: { User: { passwrdHash: 'credential' } } });

    expect(() => assertConfigMatchesSchema(client, config)).toThrow(PrismaUnknownFieldError);
    expect(() => assertConfigMatchesSchema(client, config)).toThrow(
      /User\.passwrdHash is configured but is not a scalar field/
    );
  });

  it('refuses a relation field, which cannot carry a computed field', () => {
    const config = normalizeConfig({ models: { User: { posts: 'sensitive' } } });

    expect(() => assertConfigMatchesSchema(client, config)).toThrow(PrismaUnknownFieldError);
  });

  it('names the model in schema casing even when the config used client casing', () => {
    const config = normalizeConfig({ models: { user: { passwrdHash: 'credential' } } });

    expect(() => assertConfigMatchesSchema(client, config)).toThrow(/User\.passwrdHash/);
  });

  it('carries stable codes', () => {
    try {
      assertConfigMatchesSchema(client, normalizeConfig({ models: { Usr: {} } }));
      expect.unreachable('should have thrown');
    } catch (error) {
      expect((error as PrismaUnknownModelError).code).toBe('PRISMA_UNKNOWN_MODEL');
    }

    try {
      assertConfigMatchesSchema(
        client,
        normalizeConfig({ models: { User: { nope: 'sensitive' } } })
      );
      expect.unreachable('should have thrown');
    } catch (error) {
      expect((error as PrismaUnknownFieldError).code).toBe('PRISMA_UNKNOWN_FIELD');
    }
  });

  // Applied to something that is not a Prisma client, it has nothing to check
  // against and must not invent a failure.
  it('does nothing when there is no client to check against', () => {
    const config = normalizeConfig({ models: { User: { email: 'sensitive' } } });

    expect(() => assertConfigMatchesSchema(null, config)).not.toThrow();
    expect(() => assertConfigMatchesSchema('client', config)).not.toThrow();
  });

  // The model check is public; the field check needs the internal schema. When
  // only the first is available the extension still refuses an unknown model.
  it('still checks models when the schema cannot be read', () => {
    const bare = { user: {} };

    expect(() =>
      assertConfigMatchesSchema(
        bare,
        normalizeConfig({ models: { User: { anything: 'sensitive' } } })
      )
    ).not.toThrow();
    expect(() =>
      assertConfigMatchesSchema(
        bare,
        normalizeConfig({ models: { Post: { secret: 'credential' } } })
      )
    ).toThrow(PrismaUnknownModelError);
  });
});
