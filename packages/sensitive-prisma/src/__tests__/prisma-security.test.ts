import { inspect } from 'node:util';

import {
  SensitiveString,
  containsSensitive,
  getCurrentRevealContext,
  safeStringify,
  withRevealContext,
} from '@platform-sec/sensitive-string-core';
import { beforeEach, describe, expect, it } from 'vitest';

import { sensitiveExtension } from '../extension.js';
import { PrismaUnwrappedValueError } from '../errors.js';
import { sensitiveInput } from '../types.js';
import { CANARY, createBaseClient, readColumn } from './fixtures.js';

const MARKER = '[REDACTED:';

const config = {
  models: {
    User: { email: 'sensitive', passwordHash: 'credential' },
    Post: { secret: 'credential' },
  },
} as const;

async function createClient(
  overrides: Partial<typeof config> & { detectUnwrapped?: boolean } = {},
  clientOptions?: Record<string, unknown>
) {
  const base = await createBaseClient(clientOptions);
  return { base, prisma: base.$extends(sensitiveExtension({ ...config, ...overrides })) };
}

type Clients = Awaited<ReturnType<typeof createClient>>;

let base: Clients['base'];
let prisma: Clients['prisma'];

beforeEach(async () => {
  ({ base, prisma } = await createClient());
});

async function seed() {
  await base.user.create({
    data: { email: 'canary@example.com', passwordHash: CANARY, name: 'A' },
  });
}

// TEST-PRISMA-S001, S002, S003
describe('a row read back does not leak', () => {
  beforeEach(seed);

  it('through JSON.stringify', async () => {
    const user = await prisma.user.findUniqueOrThrow({ where: { id: 1 } });

    expect(JSON.stringify(user)).not.toContain(CANARY);
    expect(JSON.stringify(user)).toContain(MARKER);
  });

  it('through util.inspect and template interpolation', async () => {
    const user = await prisma.user.findUniqueOrThrow({ where: { id: 1 } });

    expect(inspect(user, { depth: 5 })).not.toContain(CANARY);
    expect(`${String(user.passwordHash)}`).not.toContain(CANARY);
  });

  it('through core safeStringify, which still sees the row as a plain object', async () => {
    const user = await prisma.user.findUniqueOrThrow({ where: { id: 1 } });

    expect(safeStringify(user)).not.toContain(CANARY);
    expect(containsSensitive(user)).toBe(true);
  });

  it('through a relation loaded with include', async () => {
    await base.post.create({ data: { title: 't', secret: CANARY, authorId: 1 } });
    const user = await prisma.user.findUniqueOrThrow({
      where: { id: 1 },
      include: { posts: true },
    });

    expect(JSON.stringify(user)).not.toContain(CANARY);
    expect(inspect(user, { depth: 5 })).not.toContain(CANARY);
  });

  it('through findMany over many rows', async () => {
    await base.user.create({ data: { email: 'b@example.com', passwordHash: CANARY, name: 'B' } });
    const users = await prisma.user.findMany();

    expect(JSON.stringify(users)).not.toContain(CANARY);
  });

  it('through a spread copy of the row', async () => {
    const user = await prisma.user.findUniqueOrThrow({ where: { id: 1 } });
    const copy = { ...user };

    expect(JSON.stringify(copy)).not.toContain(CANARY);
    expect(copy.passwordHash).toBeInstanceOf(SensitiveString);
  });
});

// TEST-PRISMA-S004 / INV-PRISMA-004: what the driver was handed.
describe('the marker never reaches a column', () => {
  it('on create', async () => {
    await prisma.user.create({
      data: sensitiveInput({
        email: new SensitiveString('c@example.com', 'sensitive'),
        passwordHash: new SensitiveString(CANARY, 'credential'),
        name: 'C',
      }),
    });

    const stored = await readColumn(base, 'User', 'passwordHash', 1);
    expect(stored).toBe(CANARY);
    expect(String(stored)).not.toContain(MARKER);
  });

  it('on update', async () => {
    await seed();
    await prisma.user.update({
      where: { id: 1 },
      data: sensitiveInput({ passwordHash: new SensitiveString(`${CANARY}-2`, 'credential') }),
    });

    expect(String(await readColumn(base, 'User', 'passwordHash', 1))).not.toContain(MARKER);
  });

  it('on createMany', async () => {
    await prisma.user.createMany({
      data: sensitiveInput([
        {
          email: 'm1@example.com',
          passwordHash: new SensitiveString(`${CANARY}-1`, 'credential'),
          name: 'M1',
        },
        {
          email: 'm2@example.com',
          passwordHash: new SensitiveString(`${CANARY}-2`, 'credential'),
          name: 'M2',
        },
      ]),
    });

    for (const id of [1, 2]) {
      expect(String(await readColumn(base, 'User', 'passwordHash', id))).not.toContain(MARKER);
    }
  });

  it('on a nested write', async () => {
    await prisma.user.create({
      data: sensitiveInput({
        email: 'n@example.com',
        passwordHash: 'h',
        name: 'N',
        posts: { create: [{ title: 't', secret: new SensitiveString(CANARY, 'credential') }] },
      }),
    });

    expect(String(await readColumn(base, 'Post', 'secret', 1))).not.toContain(MARKER);
  });

  it('on $executeRaw', async () => {
    await seed();
    await prisma.$executeRaw`UPDATE "User" SET "passwordHash" = ${new SensitiveString(`${CANARY}-raw`, 'credential')} WHERE "id" = ${1}`;

    const stored = await readColumn(base, 'User', 'passwordHash', 1);
    expect(stored).toBe(`${CANARY}-raw`);
    expect(String(stored)).not.toContain(MARKER);
  });

  it('across every column of the database after a mixed workload', async () => {
    await prisma.user.create({
      data: sensitiveInput({
        email: new SensitiveString('mix@example.com', 'sensitive'),
        passwordHash: new SensitiveString(CANARY, 'credential'),
        name: 'Mix',
        posts: { create: [{ title: 't', secret: new SensitiveString('s', 'credential') }] },
      }),
    });

    const users = await base.$queryRawUnsafe<Record<string, unknown>[]>('SELECT * FROM "User"');
    const posts = await base.$queryRawUnsafe<Record<string, unknown>[]>('SELECT * FROM "Post"');

    expect(JSON.stringify([users, posts])).not.toContain(MARKER);
  });
});

/**
 * The hazard the package exists for, pinned in both directions.
 *
 * Measured on Prisma 6.19.3 and 7.10.0. Prisma copies query arguments before an
 * extension sees them and the copy cannot reach an ES private field, so a
 * `SensitiveString` that skipped `sensitiveInput()` is already destroyed by the
 * time any hook runs. On a bare client there is no hook at all and Prisma
 * serialises the instance through `toJSON()`, which writes the marker into the
 * column and reports success.
 */
describe('a forgotten sensitiveInput', () => {
  it('is refused by name rather than persisted', async () => {
    await expect(
      prisma.user.create({
        data: {
          email: 'f@example.com',
          passwordHash: new SensitiveString(CANARY, 'credential') as never,
          name: 'F',
        },
      })
    ).rejects.toThrow(PrismaUnwrappedValueError);

    expect(await base.user.count()).toBe(0);
  });

  it('is refused inside a nested write', async () => {
    await expect(
      prisma.user.create({
        data: {
          email: 'f@example.com',
          passwordHash: 'h',
          name: 'F',
          posts: {
            create: [{ title: 't', secret: new SensitiveString(CANARY, 'credential') as never }],
          },
        },
      })
    ).rejects.toThrow(/data\.posts\.create\.0\.secret/);
  });

  it('is refused in a where clause', async () => {
    await expect(
      prisma.user.findFirst({
        where: { email: new SensitiveString('f@example.com', 'sensitive') as never },
      })
    ).rejects.toThrow(PrismaUnwrappedValueError);
  });

  it('is refused for an Unsafe raw parameter', async () => {
    await seed();
    await expect(
      prisma.$executeRawUnsafe(
        'UPDATE "User" SET "passwordHash" = ? WHERE "id" = ?',
        new SensitiveString(CANARY, 'credential'),
        1
      )
    ).rejects.toThrow(PrismaUnwrappedValueError);

    expect(await readColumn(base, 'User', 'passwordHash', 1)).toBe(CANARY);
  });

  it('leaves the marker in the column on a bare client, which is what the guard prevents', async () => {
    await base.user.create({
      data: {
        email: 'bare@example.com',
        passwordHash: new SensitiveString(CANARY, 'credential') as never,
        name: 'B',
      },
    });

    const stored = await readColumn(base, 'User', 'passwordHash', 1);
    expect(String(stored)).toContain(MARKER);
    expect(stored).not.toBe(CANARY);
  });

  it('can be turned off for a schema the check would misread', async () => {
    const { prisma: permissive } = await createClient({ detectUnwrapped: false });

    // With the guard off the failure is Prisma's own, which names neither the
    // cause nor the fix. That is the trade, and it is why the guard defaults on.
    await expect(
      permissive.user.create({
        data: {
          email: 'p@example.com',
          passwordHash: new SensitiveString(CANARY, 'credential') as never,
          name: 'P',
        },
      })
    ).rejects.not.toThrow(PrismaUnwrappedValueError);
  });
});

// TEST-PRISMA-S005 / INV-PRISMA-005
describe('errors do not echo the value', () => {
  it('when the guard refuses a write', async () => {
    await prisma.user
      .create({
        data: {
          email: 'e@example.com',
          passwordHash: new SensitiveString(CANARY, 'credential') as never,
          name: 'E',
        },
      })
      .then(
        () => expect.unreachable('should have been refused'),
        (error: Error) => {
          expect(`${error.message} ${String(error.stack)}`).not.toContain(CANARY);
        }
      );
  });

  it('when Prisma itself rejects the argument', async () => {
    const { prisma: permissive } = await createClient({ detectUnwrapped: false });

    await permissive.user
      .create({
        data: {
          email: new SensitiveString(CANARY, 'sensitive') as never,
          passwordHash: 'h',
          name: 'E',
        },
      })
      .then(
        () => expect.unreachable('should have been rejected'),
        (error: Error) => {
          expect(`${error.message} ${String(error.stack)}`).not.toContain(CANARY);
        }
      );
  });

  it('when the driver rejects a write carrying a revealed value', async () => {
    await seed();

    await prisma.user
      .create({
        data: sensitiveInput({
          email: new SensitiveString('canary@example.com', 'sensitive'),
          passwordHash: new SensitiveString(CANARY, 'credential'),
          name: 'Dup',
        }),
      })
      .then(
        () => expect.unreachable('should have violated the unique constraint'),
        (error: Error) => {
          expect(`${error.message} ${String(error.stack)}`).not.toContain(CANARY);
        }
      );
  });
});

// TEST-PRISMA-S006
describe('audit', () => {
  it('fires once per sensitive value, with the class and the argument path', async () => {
    const seen: { klass: string; label: string | undefined; path: unknown }[] = [];

    await withRevealContext(
      {
        name: 'registration',
        auditReveal: (value) => {
          seen.push({ klass: value.klass, label: value.label, path: currentPath() });
        },
      },
      async () => {
        await prisma.user.create({
          data: sensitiveInput(
            {
              email: new SensitiveString('audited@example.com', 'sensitive'),
              passwordHash: new SensitiveString(CANARY, 'credential'),
              name: 'A',
            },
            { model: 'User', operation: 'create' }
          ),
        });
      }
    );

    expect(seen).toEqual([
      { klass: 'sensitive', label: undefined, path: 'email' },
      { klass: 'credential', label: undefined, path: 'passwordHash' },
    ]);
  });

  it('fires for a value bound into a raw statement', async () => {
    await seed();
    const seen: unknown[] = [];

    await withRevealContext(
      { name: 'rotation', auditReveal: () => seen.push(currentPath()) },
      async () => {
        await prisma.$executeRaw`UPDATE "User" SET "passwordHash" = ${new SensitiveString('r', 'credential')} WHERE "id" = ${1}`;
      }
    );

    expect(seen).toEqual(['values.0']);
  });
});

/**
 * TEST-PRISMA-S008: a known limitation, pinned so a Prisma change is noticed.
 *
 * Query-level log events carry the bound parameters, and no client extension
 * can intercept engine logging. The assertion is that the leak exists, because
 * the day it stops existing the README is wrong.
 */
describe('Prisma query logging', () => {
  it('delivers bound parameters, which no extension can filter', async () => {
    const events: { query: string; params: string }[] = [];
    const { base: logged, prisma: extended } = await createClient(
      {},
      {
        log: [{ emit: 'event', level: 'query' }],
      }
    );
    (logged as unknown as { $on: (e: string, cb: (v: never) => void) => void }).$on(
      'query',
      (event: never) => events.push(event)
    );

    await extended.user.create({
      data: sensitiveInput({
        email: 'log@example.com',
        passwordHash: new SensitiveString(CANARY, 'credential'),
        name: 'L',
      }),
    });

    const leaking = events.filter((event) => event.params.includes(CANARY));
    expect(leaking.length).toBeGreaterThan(0);

    // The documented mitigation: drop `params` before forwarding the event.
    const forwarded = events.map(({ params: _params, ...rest }) => rest);
    expect(JSON.stringify(forwarded)).not.toContain(CANARY);
  });
});

function currentPath(): unknown {
  return currentTags()?.['path'];
}

function currentTags(): Record<string, unknown> | undefined {
  return getCurrentRevealContext()?.tags;
}
