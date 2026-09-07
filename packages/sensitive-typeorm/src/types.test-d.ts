import { SensitiveString } from '@platform-sec/sensitive-string-core';
import type { ValueTransformer } from 'typeorm';
import { expectTypeOf } from 'vitest';
import { defineSchema } from './schema.js';
import { sensitiveColumn } from './transformer.js';
import type { SensitiveTransformer } from './types.js';

/**
 * The seam checks. Nothing here runs: the file is named `.test-d.ts` so
 * `pnpm typecheck` compiles it and `vitest run` does not collect it.
 *
 * There is less to check here than in the other ORM integrations, and that is
 * the point of the file rather than an omission. A `ValueTransformer` is two
 * methods over `any`, so TypeORM publishes no type for a transformed column: a
 * property is typed by the author's own annotation on the entity field, and no
 * transformer can make the compiler check that the annotation matches the
 * specification. `schema.check()` is the runtime answer to that, and the README
 * says the Drizzle guarantee is unavailable here rather than implying it.
 */

const schema = defineSchema({
  fields: { 'users.email': 'sensitive', 'users.password_hash': 'credential' },
  fallback: 'plain',
});

// A transformer this package builds is assignable wherever TypeORM wants one,
// which is the seam that would break if the ORM changed the interface.
expectTypeOf(schema.column('users.email')).toExtend<ValueTransformer>();
expectTypeOf(sensitiveColumn('credential')).toExtend<ValueTransformer>();
expectTypeOf(schema.column('users.email')).toExtend<SensitiveTransformer>();

// An array of them is accepted too, which is what composition with an
// encryption transformer relies on.
expectTypeOf([schema.column('users.email'), {} as ValueTransformer]).toExtend<ValueTransformer[]>();

// The property type the README recommends. It is an assertion by the author,
// not something TypeORM checks, so what is verified here is only that the
// annotation and the wrapped value agree.
declare const row: { email: SensitiveString<'sensitive'>; name: string };
expectTypeOf(row.email).toEqualTypeOf<SensitiveString<'sensitive'>>();
expectTypeOf(row.email.reveal({ name: 'x' })).toEqualTypeOf<string>();
expectTypeOf(row.name).toEqualTypeOf<string>();

// The specification's classification is a closed set, so a misspelt class is a
// compile error even though a misspelt path is not.
// @ts-expect-error 'secret' is not a sensitivity class
defineSchema({ fields: { 'users.email': 'secret' }, fallback: 'plain' });

// hydrateRaw is driven by the rows it is given rather than by a declared type.
expectTypeOf(schema.hydrateRaw('users', [{ email: 'a' }])).toEqualTypeOf<
  Record<string, unknown>[]
>();
