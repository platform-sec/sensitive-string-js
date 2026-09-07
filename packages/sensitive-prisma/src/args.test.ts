import {
  SensitiveString,
  getCurrentRevealContext,
  withRevealContext,
  type AuditContext,
  type RevealContext,
} from '@platform-sec/sensitive-string-core';
import { describe, expect, it, vi } from 'vitest';

import { buildRevealContext, revealArgs, revealRawArgs } from './args.js';
import { PrismaCyclicArgumentError, PrismaUnsafeStatementError } from './errors.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

function info(overrides: { model?: string | undefined; operation?: string } = {}) {
  return {
    model: 'model' in overrides ? overrides.model : 'User',
    operation: overrides.operation ?? 'create',
  };
}

/**
 * Record the context each audited reveal ran under.
 *
 * Core hands the audit hook the context the reveal ran under, which is the
 * per-value one this package builds: the model, the operation and the argument
 * path travel in its tags. The ambient context is captured alongside it, since
 * the two are no longer the same object and the difference is the point.
 */
function captureContexts(): {
  hook: (value: unknown, details: unknown, context: AuditContext) => void;
  contexts: AuditContext[];
  ambient: (RevealContext | null)[];
} {
  const contexts: AuditContext[] = [];
  const ambient: (RevealContext | null)[] = [];
  return {
    hook: vi.fn((_value: unknown, _details: unknown, context: AuditContext) => {
      contexts.push(context);
      ambient.push(getCurrentRevealContext());
    }),
    contexts,
    ambient,
  };
}

/** A `Prisma.Sql`, reproduced by shape: two own properties and getters over them. */
class FakeSql {
  constructor(
    readonly strings: string[],
    readonly values: unknown[]
  ) {}

  get sql(): string {
    return this.strings.join('?');
  }
}

describe('revealArgs', () => {
  // TEST-PRISMA-U006 / INV-PRISMA-002
  it('reveals a SensitiveString in data', () => {
    const args = { data: { email: new SensitiveString(CANARY, 'sensitive'), name: 'A' } };
    const out = revealArgs(args, info()) as typeof args;

    expect(out.data.email).toBe(CANARY);
    expect(out.data.name).toBe('A');
  });

  // INV-PRISMA-013: a lookup by a sensitive value is an ordinary query.
  it('reveals a SensitiveString in where', () => {
    const args = { where: { email: new SensitiveString(CANARY, 'sensitive') } };
    const out = revealArgs(args, info({ operation: 'findUnique' })) as typeof args;

    expect(out.where.email).toBe(CANARY);
  });

  it('reveals through a filter operator', () => {
    const args = { where: { email: { equals: new SensitiveString(CANARY, 'sensitive') } } };
    const out = revealArgs(args, info({ operation: 'findMany' })) as typeof args;

    expect(out.where.email.equals).toBe(CANARY);
  });

  it('reveals inside a nested write', () => {
    const args = {
      data: {
        name: 'A',
        posts: { create: [{ title: 't', secret: new SensitiveString(CANARY, 'credential') }] },
      },
    };
    const out = revealArgs(args, info()) as typeof args;

    expect(out.data.posts.create[0]?.secret).toBe(CANARY);
  });

  it('reveals every element of a createMany array', () => {
    const args = {
      data: [
        { email: new SensitiveString('a@example.com', 'sensitive') },
        { email: new SensitiveString('b@example.com', 'sensitive') },
      ],
    };
    const out = revealArgs(args, info({ operation: 'createMany' })) as typeof args;

    expect(out.data.map((row) => row.email)).toEqual(['a@example.com', 'b@example.com']);
  });

  it('reveals in every branch of an upsert', () => {
    const args = {
      where: { email: new SensitiveString('u@example.com', 'sensitive') },
      create: { email: new SensitiveString('u@example.com', 'sensitive') },
      update: { email: new SensitiveString('v@example.com', 'sensitive') },
    };
    const out = revealArgs(args, info({ operation: 'upsert' })) as typeof args;

    expect([out.where.email, out.create.email, out.update.email]).toEqual([
      'u@example.com',
      'u@example.com',
      'v@example.com',
    ]);
  });

  // TEST-PRISMA-U007 / INV-PRISMA-012
  it('returns plain values unchanged', () => {
    const args = { data: { name: 'A', age: 3, active: true, missing: null } };
    expect(revealArgs(args, info())).toBe(args);
  });

  it('handles undefined and primitive arguments', () => {
    expect(revealArgs(undefined, info())).toBeUndefined();
    expect(revealArgs(null, info())).toBeNull();
    expect(revealArgs('raw', info())).toBe('raw');
  });

  // TEST-PRISMA-U007 / INV-PRISMA-015
  describe('class instances', () => {
    it.each([
      ['Date', new Date('2026-01-01')],
      ['Uint8Array', new Uint8Array([1, 2, 3])],
      ['Map', new Map([['k', 'v']])],
      ['Set', new Set(['v'])],
      ['RegExp', /x/],
    ])('does not descend into %s', (_label, value) => {
      const args = { data: { column: value } };
      const out = revealArgs(args, info()) as typeof args;

      expect(out).toBe(args);
      expect(out.data.column).toBe(value);
    });

    it('leaves a class instance alone even when it holds a SensitiveString', () => {
      class Decimalish {
        constructor(readonly inner: SensitiveString<'sensitive'>) {}
      }
      const held = new Decimalish(new SensitiveString(CANARY, 'sensitive'));
      const args = { data: { amount: held } };

      expect(revealArgs(args, info())).toBe(args);
      expect(held.inner).toBeInstanceOf(SensitiveString);
    });
  });

  // TEST-PRISMA-U008 / INV-PRISMA-013
  describe('purity', () => {
    it('does not mutate the input', () => {
      const instance = new SensitiveString(CANARY, 'sensitive');
      const args = { data: { email: instance } };
      revealArgs(args, info());

      expect(args.data.email).toBe(instance);
    });

    it('returns the same reference for a subtree it did not change', () => {
      const args = {
        where: { id: 1 },
        include: { posts: { include: { author: true } } },
        data: { email: new SensitiveString(CANARY, 'sensitive') },
      };
      const out = revealArgs(args, info({ operation: 'update' })) as typeof args;

      expect(out).not.toBe(args);
      expect(out.include).toBe(args.include);
      expect(out.where).toBe(args.where);
      expect(out.data).not.toBe(args.data);
    });

    it('returns the whole argument object by identity when nothing is wrapped', () => {
      const args = { where: { id: 1 }, select: { id: true, email: true } };
      expect(revealArgs(args, info({ operation: 'findUnique' }))).toBe(args);
    });

    it('adds and removes no keys', () => {
      const args = { data: { email: new SensitiveString(CANARY, 'sensitive'), name: 'A' } };
      const out = revealArgs(args, info()) as typeof args;

      expect(Object.keys(out.data).sort()).toEqual(['email', 'name']);
    });

    // A cycle has no correct answer for the back edge: its rebuild is
    // unfinished, so the only reference available still holds the wrapped
    // values. Returning it handed back a half-unwrapped graph with no signal.
    it('refuses a cycle rather than returning a half-unwrapped graph', () => {
      const args: Record<string, unknown> = {
        data: { email: new SensitiveString(CANARY, 'sensitive') },
      };
      args['self'] = args;

      expect(() => revealArgs(args, info())).toThrow(PrismaCyclicArgumentError);
      expect(() => revealArgs(args, info())).toThrow(/refers back to itself at 'self'/);
    });

    it('refuses a cycle that closes deeper in the tree', () => {
      const inner: Record<string, unknown> = { name: 'A' };
      inner['parent'] = { child: inner };
      const args = { data: inner };

      expect(() => revealArgs(args, info())).toThrow(/at 'data.parent.child'/);
    });

    it('refuses a cycle through an array', () => {
      const rows: unknown[] = [];
      rows.push({ rows });

      expect(() => revealArgs({ data: rows }, info({ operation: 'createMany' }))).toThrow(
        PrismaCyclicArgumentError
      );
    });

    it('keeps the value out of the cycle refusal', () => {
      const args: Record<string, unknown> = {
        data: { email: new SensitiveString(CANARY, 'sensitive') },
      };
      args['self'] = args;

      try {
        revealArgs(args, info());
        expect.unreachable('should have thrown');
      } catch (error) {
        const refusal = error as PrismaCyclicArgumentError;
        expect(`${refusal.message} ${String(refusal.stack)}`).not.toContain(CANARY);
        expect(refusal.code).toBe('PRISMA_CYCLIC_ARGUMENT');
      }
    });

    // A DAG is not a cycle: the second reference is reached after the first
    // subtree finished, so it gets the finished result.
    it('does not mistake a repeated sibling for a cycle', () => {
      const shared = { name: 'A' };
      expect(() => revealArgs({ data: { first: shared, second: shared } }, info())).not.toThrow();
    });

    // A container reached twice has to produce the same result both times.
    // Marking it visited and returning it by identity left the second reference
    // still wrapped, so half the input reached Prisma unrevealed.
    it('reveals every reference to a shared subtree', () => {
      const shared = { email: new SensitiveString(CANARY, 'sensitive') };
      const args = { data: { first: shared, second: shared } };
      const out = revealArgs(args, info()) as {
        data: { first: { email: unknown }; second: { email: unknown } };
      };

      expect(out.data.first.email).toBe(CANARY);
      expect(out.data.second.email).toBe(CANARY);
      expect(out.data.first).toBe(out.data.second);
    });

    it('reveals a shared row of a createMany array once, into both positions', () => {
      const seen = captureContexts();
      const shared = { email: new SensitiveString(CANARY, 'sensitive') };
      const args = { data: [shared, shared] };

      const out = withRevealContext({ name: 'bulk', auditReveal: seen.hook }, () =>
        revealArgs(args, info({ operation: 'createMany' }))
      ) as { data: { email: unknown }[] };

      expect(out.data.map((row) => row.email)).toEqual([CANARY, CANARY]);
      expect(seen.contexts).toHaveLength(1);
    });

    it('reveals a repeated instance once per position it appears in', () => {
      const one = new SensitiveString(CANARY, 'sensitive');
      const args = { data: [{ email: one }, { email: one }] };
      const out = revealArgs(args, info({ operation: 'createMany' })) as {
        data: { email: unknown }[];
      };

      expect(out.data.map((row) => row.email)).toEqual([CANARY, CANARY]);
    });
  });

  // Section 2.5 / TEST-PRISMA-U011
  describe('reveal context', () => {
    // Core calls `auditReveal(value, details)` and `details` for a reveal is
    // only `{ operation: 'reveal' }`, so the sink reads the context it is
    // running under. That is what these assert reaches it.
    it('tags each reveal with the model, operation and argument path', () => {
      const seen = captureContexts();
      const args = {
        data: {
          email: new SensitiveString(CANARY, 'sensitive'),
          posts: { create: [{ secret: new SensitiveString('s', 'credential') }] },
        },
      };

      withRevealContext({ name: 'handler', auditReveal: seen.hook }, () =>
        revealArgs(args, info())
      );

      expect(seen.contexts).toHaveLength(2);
      expect(seen.contexts.map((ctx) => ctx?.tags?.['path'])).toEqual([
        'data.email',
        'data.posts.create.0.secret',
      ]);
      expect(seen.contexts[0]?.tags).toMatchObject({ model: 'User', operation: 'create' });
    });

    it('reaches the sink through the hook argument, with nothing installed ambiently', () => {
      const seen = captureContexts();
      const args = { data: { email: new SensitiveString(CANARY, 'sensitive') } };

      withRevealContext({ name: 'handler', auditReveal: seen.hook }, () =>
        revealArgs(args, info())
      );

      // The per-value context is what the hook is handed. It is deliberately
      // not installed: a reveal used to cost an AsyncLocalStorage entry purely
      // so a sink could find these tags, and the entry is what came out when
      // core started passing the context. What is ambient during the hook is
      // the caller's own context, which names where the caller stood.
      expect(seen.contexts[0]?.tags?.['path']).toBe('data.email');
      expect(seen.ambient[0]?.name).toBe('handler');
      expect(seen.ambient[0]?.tags?.['path']).toBeUndefined();
      expect(seen.ambient[0]).not.toBe(seen.contexts[0]);
    });

    it('inherits the ambient audit hook rather than replacing the context', () => {
      const seen = captureContexts();
      const args = { data: { email: new SensitiveString(CANARY, 'sensitive') } };

      withRevealContext(
        { name: 'handler', tags: { requestId: 'r-1' }, auditReveal: seen.hook },
        () => revealArgs(args, info())
      );

      expect(seen.contexts).toHaveLength(1);
      expect(seen.contexts[0]?.name).toBe('handler');
      expect(seen.contexts[0]?.tags?.['requestId']).toBe('r-1');
      expect(seen.contexts[0]?.tags?.['model']).toBe('User');
    });

    it('does not put the revealed value in the context', () => {
      const seen = captureContexts();
      withRevealContext({ name: 'handler', auditReveal: seen.hook }, () =>
        revealArgs({ data: { email: new SensitiveString(CANARY, 'sensitive') } }, info())
      );

      expect(JSON.stringify(seen.contexts[0]?.tags)).not.toContain(CANARY);
    });

    it('restores the ambient context after the walk', () => {
      const seen = captureContexts();
      withRevealContext({ name: 'handler', auditReveal: seen.hook }, () => {
        revealArgs({ data: { email: new SensitiveString(CANARY, 'sensitive') } }, info());
        expect(getCurrentRevealContext()?.tags?.['path']).toBeUndefined();
      });
    });
  });
});

describe('buildRevealContext', () => {
  it('falls back to the extension default with no ambient context', () => {
    const ctx = buildRevealContext(info());

    expect(ctx.name).toBe('prisma');
    expect(ctx.reason).toBe('create on User');
    expect(ctx.tags).toEqual({ model: 'User', operation: 'create' });
  });

  it('omits the model tag and the "on <Model>" reason for a raw operation', () => {
    const ctx = buildRevealContext(info({ model: undefined, operation: '$executeRaw' }));

    expect(ctx.reason).toBe('$executeRaw');
    expect(ctx.tags).toEqual({ operation: '$executeRaw' });
  });

  it('uses the supplied name and reason when no ambient context is active', () => {
    const ctx = buildRevealContext({
      model: 'User',
      operation: 'create',
      name: 'prisma-write',
      reason: 'database persistence',
    });

    expect(ctx.name).toBe('prisma-write');
    expect(ctx.reason).toBe('database persistence');
  });

  // Open question 8, decided: the caller's unit of work outranks a static
  // string, and the model and field are not lost because they are in the tags.
  it('lets an ambient name and reason outrank the supplied ones', () => {
    const ctx = withRevealContext({ name: 'password-reset', reason: 'user request' }, () =>
      buildRevealContext({
        model: 'User',
        operation: 'update',
        name: 'prisma-write',
        reason: 'database persistence',
      })
    );

    expect(ctx.name).toBe('password-reset');
    expect(ctx.reason).toBe('user request');
    expect(ctx.tags).toMatchObject({ model: 'User', operation: 'update' });
  });

  it('falls back to a bare description with no attribution at all', () => {
    const ctx = buildRevealContext({});

    expect(ctx.name).toBe('prisma');
    expect(ctx.reason).toBe('database argument');
    expect(ctx.tags).toEqual({});
  });

  it('fills in only the half the ambient context left unset', () => {
    const ctx = withRevealContext({ name: 'password-reset' }, () =>
      buildRevealContext(info({ operation: 'update' }))
    );

    expect(ctx.name).toBe('password-reset');
    expect(ctx.reason).toBe('update on User');
  });
});

describe('revealRawArgs', () => {
  it('reveals the bound values of a tagged template and keeps the statement', () => {
    const sql = new FakeSql(
      ['UPDATE users SET hash = ', ' WHERE id = ', ''],
      [new SensitiveString(CANARY, 'credential'), 7]
    );
    const out = revealRawArgs(sql, info({ model: undefined, operation: '$executeRaw' }));

    expect(out).not.toBe(sql);
    expect(out).toBeInstanceOf(FakeSql);
    expect((out as FakeSql).values).toEqual([CANARY, 7]);
    expect((out as FakeSql).sql).toBe(sql.sql);
    expect((out as FakeSql).strings).toBe(sql.strings);
    expect(sql.values[0]).toBeInstanceOf(SensitiveString);
  });

  it('returns the same Sql when it binds nothing sensitive', () => {
    const sql = new FakeSql(['SELECT 1'], []);
    expect(revealRawArgs(sql, info({ model: undefined, operation: '$queryRaw' }))).toBe(sql);
  });

  // One instance bound at two positions is two reads and so two reveals, each
  // tagged with the position it was bound at. The memo does not apply: it keys
  // containers, and an instance is a leaf the walk reveals before it looks.
  it('reveals an instance bound twice once per position', () => {
    const seen = captureContexts();
    const one = new SensitiveString(CANARY, 'credential');
    const sql = new FakeSql(['SELECT ', ', ', ''], [one, one]);

    const out = withRevealContext({ name: 'job', auditReveal: seen.hook }, () =>
      revealRawArgs(sql, info({ model: undefined, operation: '$queryRaw' }))
    );

    expect((out as FakeSql).values).toEqual([CANARY, CANARY]);
    expect(seen.contexts.map((ctx) => ctx?.tags?.['path'])).toEqual(['values.0', 'values.1']);
  });

  // Revealing here would write the secret into SQL rather than binding it.
  it('refuses a SensitiveString as the statement text', () => {
    const args = [new SensitiveString(CANARY, 'credential')];

    expect(() =>
      revealRawArgs(args, info({ model: undefined, operation: '$queryRawUnsafe' }))
    ).toThrow(PrismaUnsafeStatementError);
    try {
      revealRawArgs(args, info({ model: undefined, operation: '$queryRawUnsafe' }));
    } catch (error) {
      expect(String((error as Error).message)).not.toContain(CANARY);
      expect((error as PrismaUnsafeStatementError).code).toBe('PRISMA_SENSITIVE_STATEMENT');
    }
  });

  it('tags a raw reveal with the value position', () => {
    const seen = captureContexts();
    const sql = new FakeSql(
      ['SET a = ', ', b = ', ''],
      [1, new SensitiveString(CANARY, 'credential')]
    );

    withRevealContext({ name: 'job', auditReveal: seen.hook }, () =>
      revealRawArgs(sql, info({ model: undefined, operation: '$executeRaw' }))
    );

    expect(seen.contexts[0]?.tags).toEqual({ operation: '$executeRaw', path: 'values.1' });
  });

  // Prisma copies the parameters of an Unsafe call before the hook runs, so
  // there is nothing left to unwrap by then. The array is returned untouched
  // and the guard is what refuses the wreckage.
  it('leaves an Unsafe argument array alone', () => {
    const args = ['UPDATE users SET hash = ?', 'already-a-string', 7];
    expect(revealRawArgs(args, info({ model: undefined, operation: '$executeRawUnsafe' }))).toBe(
      args
    );
  });

  it('leaves an ordinary object argument alone', () => {
    const args = { insert: 'users', documents: [{ token: 'plain' }] };
    expect(revealRawArgs(args, info({ model: undefined, operation: '$runCommandRaw' }))).toBe(args);
  });

  it('unwraps a TypedSql, which carries sql and values rather than strings', () => {
    class FakeTypedSql {
      constructor(
        readonly sql: string,
        readonly values: unknown[]
      ) {}
    }
    const typed = new FakeTypedSql('SELECT $1', [new SensitiveString(CANARY, 'credential')]);
    const out = revealRawArgs(typed, info({ model: undefined, operation: '$queryRawTyped' }));

    expect(out).toBeInstanceOf(FakeTypedSql);
    expect((out as FakeTypedSql).values).toEqual([CANARY]);
    expect((out as FakeTypedSql).sql).toBe('SELECT $1');
  });
});
