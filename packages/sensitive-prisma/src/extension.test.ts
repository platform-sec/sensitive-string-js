import {
  RevealLimitExceededError,
  SensitiveString,
  withRevealContext,
  type AuditContext,
} from '@platform-sec/sensitive-string-core';
import { beforeEach, describe, expect, it } from 'vitest';

import { CANARY, createBaseClient, readColumn } from './__tests__/fixtures.js';
import { sensitiveExtension } from './extension.js';
import { PrismaUnknownFieldError, PrismaUnknownModelError } from './errors.js';
import { sensitiveInput } from './types.js';
import { wrapRows } from './raw.js';

const config = {
  models: {
    User: {
      email: 'sensitive',
      passwordHash: 'credential',
      nickname: { klass: 'sensitive', nullable: true },
    },
    Post: { secret: 'credential' },
    PaymentMethod: { cardNumber: 'credential', cardCvv: 'credential' },
  },
} as const;

type Base = Awaited<ReturnType<typeof createBaseClient>>;

async function createClient(options?: Record<string, unknown>) {
  const base = await createBaseClient(options);
  return { base, prisma: base.$extends(sensitiveExtension(config)) };
}

let base: Base;
let prisma: Awaited<ReturnType<typeof createClient>>['prisma'];

beforeEach(async () => {
  ({ base, prisma } = await createClient());
});

async function seedUser(email = 'a@example.com') {
  return prisma.user.create({
    data: { email, passwordHash: CANARY, name: 'A', nickname: null },
  });
}

describe('reads', () => {
  // TEST-PRISMA-I001
  it('wraps configured fields and leaves the rest as they were', async () => {
    await seedUser();
    const user = await prisma.user.findUniqueOrThrow({ where: { id: 1 } });

    expect(user.email).toBeInstanceOf(SensitiveString);
    expect(user.passwordHash).toBeInstanceOf(SensitiveString);
    expect(user.passwordHash.klass).toBe('credential');
    expect(user.passwordHash.reveal({ name: 'test' })).toBe(CANARY);
    expect(user.name).toBe('A');
    expect(user.id).toBe(1);
  });

  it('labels a value with its field name', async () => {
    await seedUser();
    const user = await prisma.user.findUniqueOrThrow({ where: { id: 1 } });

    expect(user.email.label).toBe('email');
  });

  // TEST-PRISMA-I002
  it('wraps every element of findMany', async () => {
    await seedUser('a@example.com');
    await seedUser('b@example.com');
    const users = await prisma.user.findMany({ orderBy: { id: 'asc' } });

    expect(users).toHaveLength(2);
    expect(users.every((user) => user.email instanceof SensitiveString)).toBe(true);
    expect(users[1]?.email.reveal({ name: 'test' })).toBe('b@example.com');
  });

  // INV-PRISMA-011, against a real nullable column.
  it('leaves a null column null', async () => {
    await seedUser();
    const user = await prisma.user.findUniqueOrThrow({ where: { id: 1 } });

    expect(user.nickname).toBeNull();
  });

  it('wraps a nullable column that holds a value', async () => {
    await prisma.user.create({
      data: { email: 'n@example.com', passwordHash: 'h', name: 'N', nickname: 'nick' },
    });
    const user = await prisma.user.findUniqueOrThrow({ where: { id: 1 } });

    expect(user.nickname).toBeInstanceOf(SensitiveString);
  });

  // TEST-PRISMA-I006 / INV-PRISMA-001: the whole reason reads use the result
  // component rather than post-processing in the query hook.
  it('wraps relations loaded through include, at any depth', async () => {
    await seedUser();
    await prisma.post.create({ data: { title: 't', secret: CANARY, authorId: 1 } });

    const user = await prisma.user.findUniqueOrThrow({
      where: { id: 1 },
      include: { posts: { include: { author: true } } },
    });

    expect(user.posts[0]?.secret).toBeInstanceOf(SensitiveString);
    expect(user.posts[0]?.author.email).toBeInstanceOf(SensitiveString);
    expect(user.posts[0]?.secret.reveal({ name: 'test' })).toBe(CANARY);
  });

  it('wraps relations loaded through a nested select', async () => {
    await seedUser();
    await prisma.post.create({ data: { title: 't', secret: CANARY, authorId: 1 } });

    const post = await prisma.post.findFirstOrThrow({
      select: { title: true, author: { select: { email: true } } },
    });

    expect(post.author.email).toBeInstanceOf(SensitiveString);
    expect(post.title).toBe('t');
  });

  it('narrows with select and still wraps what it kept', async () => {
    await seedUser();
    const partial = await prisma.user.findUniqueOrThrow({
      where: { id: 1 },
      select: { id: true, email: true },
    });

    expect(Object.keys(partial).sort()).toEqual(['email', 'id']);
    expect(partial.email).toBeInstanceOf(SensitiveString);
  });

  // TEST-PRISMA-I010
  describe('omit', () => {
    it('removes a configured field per query, with no raw copy left behind', async () => {
      await seedUser();
      const user = await prisma.user.findUniqueOrThrow({
        where: { id: 1 },
        omit: { passwordHash: true },
      });

      expect('passwordHash' in user).toBe(false);
      expect(JSON.stringify(user)).not.toContain(CANARY);
      expect(Object.values(user)).not.toContain(CANARY);
    });

    it('removes a configured field globally, with no raw copy left behind', async () => {
      const client = await createBaseClient({ omit: { user: { passwordHash: true } } });
      const extended = client.$extends(sensitiveExtension(config));
      await extended.user.create({
        data: { email: 'g@example.com', passwordHash: CANARY, name: 'G' },
      });

      const user = await extended.user.findUniqueOrThrow({ where: { id: 1 } });
      expect('passwordHash' in user).toBe(false);
      expect(JSON.stringify(user)).not.toContain(CANARY);
    });
  });

  // The computed field materialises on access and is then a data property, so
  // it is stable inside one result and different between two.
  it('gives one instance per result object, not per property read', async () => {
    await seedUser();
    const user = await prisma.user.findUniqueOrThrow({ where: { id: 1 } });
    const again = await prisma.user.findUniqueOrThrow({ where: { id: 1 } });

    expect(user.email).toBe(user.email);
    expect(user.email).not.toBe(again.email);
    expect(user.email.equals(again.email.reveal({ name: 'test' }))).toBe(true);
  });

  // Neither TypeScript nor Prisma catches a typo in a model or column name:
  // `models` is keyed by string, Prisma ignores a result component under an
  // unknown model, and it adds a computed field under an unknown name beside
  // the real column. Either way the column would read back unwrapped, so the
  // extension checks the names against the client it is applied to.
  describe('names checked against the schema', () => {
    it('refuses a misspelled model when the extension is applied', () => {
      expect(() =>
        base.$extends(sensitiveExtension({ models: { Usr: { passwordHash: 'credential' } } }))
      ).toThrow(PrismaUnknownModelError);
    });

    it('refuses a misspelled column when the extension is applied', () => {
      expect(() =>
        base.$extends(sensitiveExtension({ models: { User: { passwrdHash: 'credential' } } }))
      ).toThrow(PrismaUnknownFieldError);
    });

    it('refuses a relation field, which cannot carry a computed field', () => {
      expect(() =>
        base.$extends(sensitiveExtension({ models: { User: { posts: 'sensitive' } } }))
      ).toThrow(PrismaUnknownFieldError);
    });

    it('refuses before any query runs, so nothing reads unwrapped in the meantime', async () => {
      await seedUser();
      expect(() =>
        base.$extends(sensitiveExtension({ models: { Usr: { passwordHash: 'credential' } } }))
      ).toThrow(PrismaUnknownModelError);
      expect(await base.user.count()).toBe(1);
    });
  });

  // Adopting one field at a time starts here, and an empty configuration must
  // not be a special case that breaks the client.
  it('leaves everything alone when nothing is configured', async () => {
    const bare = base.$extends(sensitiveExtension({ models: {} }));
    await bare.user.create({
      data: { email: 'bare@example.com', passwordHash: CANARY, name: 'B' },
    });

    const user = await bare.user.findUniqueOrThrow({ where: { id: 1 } });
    expect(user.passwordHash).toBe(CANARY);
    expect(typeof user.email).toBe('string');
  });

  it('leaves a model with no configuration untouched', async () => {
    await seedUser();
    await prisma.post.create({ data: { title: 't', secret: 's', authorId: 1 } });
    const post = await prisma.post.findFirstOrThrow();

    expect(post.title).toBe('t');
    expect(typeof post.title).toBe('string');
  });
});

describe('writes', () => {
  // TEST-PRISMA-I003 / INV-PRISMA-004: the column holds the value, not the marker.
  it('unwraps on create and stores the raw value', async () => {
    await prisma.user.create({
      data: sensitiveInput({
        email: new SensitiveString('c@example.com', 'sensitive'),
        passwordHash: new SensitiveString(CANARY, 'credential'),
        name: 'C',
      }),
    });

    expect(await readColumn(base, 'User', 'passwordHash', 1)).toBe(CANARY);
    expect(await readColumn(base, 'User', 'email', 1)).toBe('c@example.com');
  });

  it('accepts plain values alongside wrapped ones', async () => {
    await prisma.user.create({
      data: sensitiveInput({
        email: new SensitiveString('m@example.com', 'sensitive'),
        passwordHash: 'plain-hash',
        name: 'M',
      }),
    });

    expect(await readColumn(base, 'User', 'passwordHash', 1)).toBe('plain-hash');
  });

  // TEST-PRISMA-I004
  it('unwraps on update', async () => {
    await seedUser();
    await prisma.user.update({
      where: { id: 1 },
      data: sensitiveInput({ passwordHash: new SensitiveString('rotated', 'credential') }),
    });

    expect(await readColumn(base, 'User', 'passwordHash', 1)).toBe('rotated');
  });

  it('unwraps in both branches of upsert', async () => {
    await prisma.user.upsert({
      where: { email: 'u@example.com' },
      create: sensitiveInput({
        email: new SensitiveString('u@example.com', 'sensitive'),
        passwordHash: new SensitiveString(CANARY, 'credential'),
        name: 'U',
      }),
      update: sensitiveInput({ passwordHash: new SensitiveString('never', 'credential') }),
    });
    expect(await readColumn(base, 'User', 'passwordHash', 1)).toBe(CANARY);

    await prisma.user.upsert({
      where: { email: 'u@example.com' },
      create: sensitiveInput({
        email: new SensitiveString('u@example.com', 'sensitive'),
        passwordHash: new SensitiveString('never', 'credential'),
        name: 'U',
      }),
      update: sensitiveInput({ passwordHash: new SensitiveString('rotated', 'credential') }),
    });
    expect(await readColumn(base, 'User', 'passwordHash', 1)).toBe('rotated');
  });

  // TEST-PRISMA-I005
  it('unwraps every row of createMany', async () => {
    await prisma.user.createMany({
      data: sensitiveInput([
        {
          email: new SensitiveString('a@example.com', 'sensitive'),
          passwordHash: new SensitiveString(`${CANARY}-1`, 'credential'),
          name: 'A',
        },
        {
          email: new SensitiveString('b@example.com', 'sensitive'),
          passwordHash: new SensitiveString(`${CANARY}-2`, 'credential'),
          name: 'B',
        },
      ]),
    });

    expect(await readColumn(base, 'User', 'passwordHash', 1)).toBe(`${CANARY}-1`);
    expect(await readColumn(base, 'User', 'passwordHash', 2)).toBe(`${CANARY}-2`);
  });

  it('unwraps inside a nested write', async () => {
    await prisma.user.create({
      data: sensitiveInput({
        email: new SensitiveString('n@example.com', 'sensitive'),
        passwordHash: 'h',
        name: 'N',
        posts: { create: [{ title: 't', secret: new SensitiveString(CANARY, 'credential') }] },
      }),
    });

    expect(await readColumn(base, 'Post', 'secret', 1)).toBe(CANARY);
  });

  it('unwraps in updateMany', async () => {
    await seedUser();
    await prisma.user.updateMany({
      where: { name: 'A' },
      data: sensitiveInput({ passwordHash: new SensitiveString('bulk', 'credential') }),
    });

    expect(await readColumn(base, 'User', 'passwordHash', 1)).toBe('bulk');
  });

  // The unwrap happens at the call site, so a value's reveal budget is spent
  // there and the refusal arrives before Prisma is involved.
  it('refuses a reveal-limited value from sensitiveInput, not from the query', async () => {
    const limited = new SensitiveString(CANARY, 'credential', 'pw', { maxReveals: 1 });
    expect(limited.reveal({ name: 'first' })).toBe(CANARY);

    expect(() =>
      sensitiveInput({ passwordHash: limited, email: 'l@example.com', name: 'L' })
    ).toThrow(RevealLimitExceededError);
    expect(await base.user.count()).toBe(0);
  });

  // TEST-PRISMA-I009 / INV-PRISMA-013
  it('finds a row by a sensitive value in where', async () => {
    await seedUser('find@example.com');
    const found = await prisma.user.findUnique({
      where: sensitiveInput({ email: new SensitiveString('find@example.com', 'sensitive') }),
    });

    expect(found?.id).toBe(1);
  });

  it('filters findMany by a sensitive value', async () => {
    await seedUser('one@example.com');
    await seedUser('two@example.com');
    const found = await prisma.user.findMany({
      where: sensitiveInput({
        email: { in: [new SensitiveString('two@example.com', 'sensitive')] },
      }),
    });

    expect(found).toHaveLength(1);
    expect(found[0]?.id).toBe(2);
  });

  // INV-PRISMA-015, against the column types Prisma actually hands the driver.
  it('leaves Decimal, Bytes and DateTime arguments untouched', async () => {
    await seedUser();
    const createdAt = new Date('2026-01-02T03:04:05.000Z');
    const token = new Uint8Array([1, 2, 3, 4]);

    await prisma.paymentMethod.create({
      data: sensitiveInput({
        cardNumber: new SensitiveString('4111111111111111', 'credential'),
        cardCvv: new SensitiveString('123', 'credential'),
        cardExpiry: '12/30',
        balance: '10.50',
        token,
        createdAt,
        ownerId: 1,
      }),
    });

    const card = await prisma.paymentMethod.findUniqueOrThrow({ where: { id: 1 } });
    expect(card.cardNumber.reveal({ name: 'test' })).toBe('4111111111111111');
    expect(card.createdAt.getTime()).toBe(createdAt.getTime());
    expect(Array.from(card.token)).toEqual([1, 2, 3, 4]);
    expect(card.balance.toString()).toBe('10.5');
  });
});

// TEST-PRISMA-I007
describe('transactions', () => {
  it('wraps and unwraps inside an interactive transaction', async () => {
    const created = await prisma.$transaction(async (tx) => {
      await tx.user.create({
        data: sensitiveInput({
          email: new SensitiveString('t@example.com', 'sensitive'),
          passwordHash: new SensitiveString(CANARY, 'credential'),
          name: 'T',
        }),
      });
      return tx.user.findUniqueOrThrow({ where: { id: 1 } });
    });

    expect(created.passwordHash).toBeInstanceOf(SensitiveString);
    expect(await readColumn(base, 'User', 'passwordHash', 1)).toBe(CANARY);
  });

  it('wraps the results of a batch transaction', async () => {
    await seedUser();
    const [users, count] = await prisma.$transaction([prisma.user.findMany(), prisma.user.count()]);

    expect(count).toBe(1);
    expect(users[0]?.email).toBeInstanceOf(SensitiveString);
  });

  it('rolls a failed transaction back without persisting a marker', async () => {
    await expect(
      prisma.$transaction(async (tx) => {
        await tx.user.create({
          data: sensitiveInput({
            email: new SensitiveString('r@example.com', 'sensitive'),
            passwordHash: new SensitiveString(CANARY, 'credential'),
            name: 'R',
          }),
        });
        throw new Error('rollback');
      })
    ).rejects.toThrow('rollback');

    expect(await base.user.count()).toBe(0);
  });
});

// TEST-PRISMA-I008
describe('raw queries', () => {
  it('binds a revealed parameter, not the marker, through a tagged template', async () => {
    await seedUser();
    const rotated = new SensitiveString('raw-rotated', 'credential');

    await prisma.$executeRaw`UPDATE "User" SET "passwordHash" = ${rotated} WHERE "id" = ${1}`;

    expect(await readColumn(base, 'User', 'passwordHash', 1)).toBe('raw-rotated');
  });

  it('binds a revealed parameter through the Unsafe variant', async () => {
    await seedUser();
    // The Unsafe variants take their parameters through Prisma's argument
    // copy, so the value has to be unwrapped at the call site like any other
    // write; the tagged-template form above is the one the hook can serve.
    await prisma.$executeRawUnsafe(
      'UPDATE "User" SET "passwordHash" = ? WHERE "id" = ?',
      ...sensitiveInput([new SensitiveString('unsafe-rotated', 'credential'), 1])
    );

    expect(await readColumn(base, 'User', 'passwordHash', 1)).toBe('unsafe-rotated');
  });

  it('returns plain strings until wrapRows is applied', async () => {
    await seedUser();
    const rows = await prisma.$queryRaw<{ id: number; passwordHash: string }[]>`
      SELECT "id", "passwordHash" FROM "User" WHERE "id" = ${1}
    `;

    expect(rows[0]?.passwordHash).toBe(CANARY);

    const wrapped = wrapRows(rows, config.models.User);
    expect(wrapped[0]?.passwordHash).toBeInstanceOf(SensitiveString);
    expect(JSON.stringify(wrapped)).not.toContain(CANARY);
  });

  it('finds a row by a revealed parameter', async () => {
    await seedUser('raw@example.com');
    const rows = await prisma.$queryRaw<{ id: number }[]>`
      SELECT "id" FROM "User" WHERE "email" = ${new SensitiveString('raw@example.com', 'sensitive')}
    `;

    expect(rows[0]?.id).toBe(1);
  });
});

// TEST-PRISMA-I011 / INV-PRISMA-010
describe('composition', () => {
  it('keeps wrapping when another extension is applied after it', async () => {
    const composed = prisma.$extends({
      name: 'after',
      result: {
        user: {
          shout: { needs: { name: true }, compute: (row) => row.name.toUpperCase() },
        },
      },
    });
    await composed.user.create({
      data: { email: 's@example.com', passwordHash: 'h', name: 'shout' },
    });

    const user = await composed.user.findUniqueOrThrow({ where: { id: 1 } });
    expect(user.email).toBeInstanceOf(SensitiveString);
    expect(user.shout).toBe('SHOUT');
  });

  // Applying it twice is an easy mistake in an application that builds its
  // client in two places. The compute guard is what keeps the second pass from
  // burying the value a level deeper, where `reveal()` would return the inner
  // instance's marker.
  it('is idempotent when applied twice', async () => {
    const twice = prisma.$extends(sensitiveExtension(config));
    await twice.user.create({
      data: sensitiveInput({
        email: new SensitiveString('twice@example.com', 'sensitive'),
        passwordHash: new SensitiveString(CANARY, 'credential'),
        name: 'T',
      }),
    });

    const user = await twice.user.findUniqueOrThrow({ where: { id: 1 } });
    expect(user.passwordHash).toBeInstanceOf(SensitiveString);
    expect(user.passwordHash.reveal({ name: 'test' })).toBe(CANARY);
    expect(JSON.stringify(user)).not.toContain(CANARY);
  });

  // A later extension that claims the same field wins, as Prisma's protocol
  // says. What it wins is this extension's output, not the column: `needs`
  // resolves through the computed field, so the raw value is not reachable.
  it('hands a later override the wrapped value rather than the column', async () => {
    await seedUser();
    const clobbered = prisma.$extends({
      name: 'clobber',
      result: {
        user: {
          passwordHash: {
            needs: { passwordHash: true },
            compute: (row) => `seen:${String(row.passwordHash)}`,
          },
        },
      },
    });

    const user = await clobbered.user.findUniqueOrThrow({ where: { id: 1 } });
    expect(user.passwordHash).toBe('seen:[REDACTED:credential]');
    expect(user.passwordHash).not.toContain(CANARY);
  });
});

describe('audit', () => {
  // TEST-PRISMA-S006 / INV-PRISMA-002
  it('audits one reveal per sensitive value with the model, operation and path', async () => {
    const seen: { klass: string; tags: Record<string, unknown> | undefined }[] = [];

    await withRevealContext(
      {
        name: 'registration',
        auditReveal: (value, _details, context) => {
          seen.push({
            klass: value.klass,
            // The context the reveal ran under, which core hands the hook. It
            // is the per-value one the extension built, not this one.
            tags: tagsOf(context),
          });
        },
      },
      async () => {
        await prisma.user.create({
          data: sensitiveInput(
            {
              email: new SensitiveString('audit@example.com', 'sensitive'),
              passwordHash: new SensitiveString(CANARY, 'credential'),
              name: 'A',
            },
            { model: 'User', operation: 'create' }
          ),
        });
      }
    );

    expect(seen).toHaveLength(2);
    expect(seen.map((entry) => entry.tags?.['path'])).toEqual(['email', 'passwordHash']);
    expect(seen[0]?.tags).toMatchObject({ model: 'User', operation: 'create' });
  });

  it('audits a raw parameter under the raw operation name', async () => {
    await seedUser();
    const seen: (Record<string, unknown> | undefined)[] = [];

    await withRevealContext(
      { name: 'rotation', auditReveal: (_value, _details, context) => seen.push(tagsOf(context)) },
      async () => {
        await prisma.$executeRaw`UPDATE "User" SET "passwordHash" = ${new SensitiveString('r', 'credential')} WHERE "id" = ${1}`;
      }
    );

    expect(seen).toHaveLength(1);
    expect(seen[0]).toEqual({ operation: '$executeRaw', path: 'values.0' });
  });
});

function tagsOf(context: AuditContext): Readonly<Record<string, unknown>> | undefined {
  return context.tags;
}
