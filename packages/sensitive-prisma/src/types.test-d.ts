import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { expectTypeOf } from 'vitest';

import { createBaseClient } from './__tests__/fixtures.js';
import { sensitiveExtension } from './extension.js';
import { sensitiveInput, type UnwrapSensitive, type WrapRow } from './types.js';
import { wrapRows } from './raw.js';

const config = {
  models: {
    User: {
      email: 'sensitive',
      passwordHash: { klass: 'credential', label: 'password' },
      nickname: { klass: 'sensitive', nullable: true },
    },
    Post: { secret: 'credential' },
    PaymentMethod: { cardNumber: 'credential' },
  },
} as const;

/**
 * A client and an extension, declared for their types.
 *
 * Nothing here runs. The file is named `.test-d.ts` so `pnpm typecheck`
 * compiles it and `vitest run` does not collect it, which is the same split
 * `sensitive-bugsnag` and `sensitive-sentry` use for their seam checks. The
 * behaviour these types describe is exercised by `extension.test.ts`.
 */
declare const base: Awaited<ReturnType<typeof createBaseClient>>;
const prisma = base.$extends(sensitiveExtension(config));

// TEST-PRISMA-T001 / TEST-PRISMA-T002
async function readTypes() {
  const user = await prisma.user.findUniqueOrThrow({ where: { id: 1 } });

  expectTypeOf(user.email).toEqualTypeOf<SensitiveString<'sensitive'>>();
  expectTypeOf(user.passwordHash).toEqualTypeOf<SensitiveString<'credential'>>();
  expectTypeOf(user.name).toEqualTypeOf<string>();
  expectTypeOf(user.id).toEqualTypeOf<number>();

  // `nullable: true` in the spec is what widens the published type, because the
  // computed field's declared return type is what Prisma republishes.
  expectTypeOf(user.nickname).toEqualTypeOf<SensitiveString<'sensitive'> | null>();
}

// TEST-PRISMA-T004
async function narrowingTypes() {
  const selected = await prisma.user.findUniqueOrThrow({
    where: { id: 1 },
    select: { id: true, email: true },
  });
  expectTypeOf(selected.email).toEqualTypeOf<SensitiveString<'sensitive'>>();
  expectTypeOf(selected).not.toHaveProperty('name');

  const included = await prisma.user.findUniqueOrThrow({
    where: { id: 1 },
    include: { posts: { include: { author: true } } },
  });
  expectTypeOf(included.posts[0]!.secret).toEqualTypeOf<SensitiveString<'credential'>>();
  expectTypeOf(included.posts[0]!.author.email).toEqualTypeOf<SensitiveString<'sensitive'>>();
  expectTypeOf(included.posts[0]!.title).toEqualTypeOf<string>();

  const omitted = await prisma.user.findUniqueOrThrow({
    where: { id: 1 },
    omit: { passwordHash: true },
  });
  expectTypeOf(omitted).not.toHaveProperty('passwordHash');
  expectTypeOf(omitted.email).toEqualTypeOf<SensitiveString<'sensitive'>>();

  const many = await prisma.user.findMany();
  expectTypeOf(many[0]!.email).toEqualTypeOf<SensitiveString<'sensitive'>>();

  // A model with no configuration keeps Prisma's own types.
  const card = await prisma.paymentMethod.findUniqueOrThrow({ where: { id: 1 } });
  expectTypeOf(card.cardNumber).toEqualTypeOf<SensitiveString<'credential'>>();
  expectTypeOf(card.cardCvv).toEqualTypeOf<string>();
  expectTypeOf(card.createdAt).toEqualTypeOf<Date>();
}

// TEST-PRISMA-T003
function unwrapTypes() {
  expectTypeOf<UnwrapSensitive<SensitiveString<'credential'>>>().toEqualTypeOf<string>();
  expectTypeOf<UnwrapSensitive<SensitiveString<'sensitive'> | null>>().toEqualTypeOf<
    string | null
  >();
  expectTypeOf<
    UnwrapSensitive<{ email: SensitiveString<'sensitive'>; name: string }>
  >().toEqualTypeOf<{
    email: string;
    name: string;
  }>();
  expectTypeOf<UnwrapSensitive<{ codes: SensitiveString<'credential'>[] }>>().toEqualTypeOf<{
    codes: string[];
  }>();
  expectTypeOf<
    UnwrapSensitive<{ nested: { deep: SensitiveString<'sensitive'> } }>
  >().toEqualTypeOf<{ nested: { deep: string } }>();

  // Column types Prisma accepts must survive: mapping over a class would build
  // a structural copy that no longer matches it.
  // A known imprecision, pinned so a change to it is visible: an array branch
  // collapses a tuple to the union of its positions. It costs nothing at the
  // one place it shows, the documented
  // `$executeRawUnsafe(sql, ...sensitiveInput([secret, id]))` spread, whose
  // target is variadic. Recovering the positions needs a homomorphic mapped
  // type that this conditional chain does not currently produce.
  expectTypeOf<UnwrapSensitive<[SensitiveString<'credential'>, number]>>().toEqualTypeOf<
    (string | number)[]
  >();
  expectTypeOf<UnwrapSensitive<SensitiveString<'sensitive'>[]>>().toEqualTypeOf<string[]>();

  expectTypeOf<UnwrapSensitive<Date>>().toEqualTypeOf<Date>();
  expectTypeOf<UnwrapSensitive<Uint8Array>>().toEqualTypeOf<Uint8Array>();
  expectTypeOf<UnwrapSensitive<number>>().toEqualTypeOf<number>();
  expectTypeOf<UnwrapSensitive<undefined>>().toEqualTypeOf<undefined>();
}

function inputTypes() {
  const data = sensitiveInput({
    email: new SensitiveString('a@example.com', 'sensitive'),
    name: 'A',
    createdAt: new Date(),
  });

  expectTypeOf(data.email).toEqualTypeOf<string>();
  expectTypeOf(data.name).toEqualTypeOf<string>();
  expectTypeOf(data.createdAt).toEqualTypeOf<Date>();
}

// The result of `sensitiveInput()` has to satisfy Prisma's generated input
// type, which is the whole reason the helper is typed rather than cast at each
// call site.
async function writeTypes() {
  await prisma.user.create({
    data: sensitiveInput({
      email: new SensitiveString('a@example.com', 'sensitive'),
      passwordHash: new SensitiveString('hash', 'credential'),
      name: 'A',
    }),
  });

  await prisma.user.update({
    where: { id: 1 },
    data: sensitiveInput({ nickname: new SensitiveString('nick', 'sensitive') }),
  });

  await prisma.user.findUnique({
    where: sensitiveInput({ email: new SensitiveString('a@example.com', 'sensitive') }),
  });

  await prisma.paymentMethod.create({
    data: sensitiveInput({
      cardNumber: new SensitiveString('4111', 'credential'),
      cardCvv: '123',
      cardExpiry: '12/30',
      balance: '1.00',
      token: new Uint8Array([1]),
      createdAt: new Date(),
      ownerId: 1,
    }),
  });
}

// TEST-PRISMA-T005: the runtime guard is not the only thing standing between a
// wrapped value and a corrupted column. The compiler refuses it first.
async function unwrappedWriteIsATypeError() {
  await prisma.user.update({
    where: { id: 1 },
    // @ts-expect-error a SensitiveString is not assignable to Prisma's `string`
    data: { passwordHash: new SensitiveString('hash', 'credential') },
  });

  await prisma.user.findFirst({
    // @ts-expect-error the same guard applies to a lookup by a sensitive value
    where: { email: new SensitiveString('a@example.com', 'sensitive') },
  });
}

function rawTypes() {
  const rows: { id: number; email: string; passwordHash: string; name: string | null }[] = [];
  const wrapped = wrapRows(rows, config.models.User);

  expectTypeOf(wrapped[0]!.email).toEqualTypeOf<SensitiveString<'sensitive'>>();
  expectTypeOf(wrapped[0]!.passwordHash).toEqualTypeOf<SensitiveString<'credential'>>();
  expectTypeOf(wrapped[0]!.id).toEqualTypeOf<number>();
  expectTypeOf(wrapped[0]!.name).toEqualTypeOf<string | null>();

  // The row type drives nullability, so a spec need not repeat it.
  expectTypeOf<WrapRow<{ nickname: string | null }, { nickname: 'sensitive' }>>().toEqualTypeOf<{
    nickname: SensitiveString<'sensitive'> | null;
  }>();

  expectTypeOf<WrapRow<{ codes: string[] }, { codes: 'credential' }>>().toEqualTypeOf<{
    codes: SensitiveString<'credential'>[];
  }>();
}

export {
  inputTypes,
  narrowingTypes,
  rawTypes,
  readTypes,
  unwrapTypes,
  unwrappedWriteIsATypeError,
  writeTypes,
};
