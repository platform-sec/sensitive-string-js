import {
  SensitiveString,
  createChildContext,
  withRevealContext,
} from '@platform-sec/sensitive-string-core';
import type { RevealContext } from '@platform-sec/sensitive-string-core';
import { describe, expect, it, vi } from 'vitest';
import { buildWriteContext } from './context.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

describe('buildWriteContext', () => {
  it('names itself when nothing is ambient', () => {
    const context = buildWriteContext({
      sink: 'drizzle',
      table: 'users',
      column: 'email',
      operation: 'insert',
    });

    expect(context.name).toBe('drizzle:users.email');
    expect(context.reason).toBe('column insert');
    expect(context.tags).toMatchObject({
      sink: 'drizzle',
      table: 'users',
      column: 'email',
      operation: 'insert',
    });
  });

  it('defers to an ambient name and reason, and keeps its own tags', () => {
    withRevealContext({ name: 'checkout', reason: 'placing an order' }, () => {
      const context = buildWriteContext({
        sink: 'typeorm',
        table: 'orders',
        column: 'card',
        operation: 'unknown',
      });

      // Replacing the ambient name with a constant would flatten a
      // request-scoped audit trail into one bucket per column.
      expect(context.name).toBe('checkout');
      expect(context.reason).toBe('placing an order');
      expect(context.tags).toMatchObject({ sink: 'typeorm', column: 'card' });
    });
  });

  it('keeps the ambient audit hook, which a fresh context would drop', () => {
    const auditReveal = vi.fn();

    withRevealContext({ name: 'request', auditReveal }, () => {
      const secret = new SensitiveString(CANARY, 'sensitive', 'users.email');
      const context = buildWriteContext({
        sink: 'drizzle',
        table: 'users',
        column: 'email',
        operation: 'insert',
        klass: 'sensitive',
      });

      expect(secret.reveal(context)).toBe(CANARY);
    });

    expect(auditReveal).toHaveBeenCalledTimes(1);
    const [, , recorded] = auditReveal.mock.calls[0] as [unknown, unknown, RevealContext];
    expect(recorded.tags).toMatchObject({ sink: 'drizzle', operation: 'insert' });
  });

  it('keeps a caller tag that the ambient context set', () => {
    withRevealContext({ name: 'request', tags: { requestId: 'abc' } }, () => {
      const context = buildWriteContext({ sink: 'prisma', operation: 'update' });
      expect(context.tags).toMatchObject({ requestId: 'abc', sink: 'prisma' });
    });
  });

  it('is audited under a child context rather than the installed one', () => {
    // The contract that makes the tags reach a sink at all: the hook's third
    // argument is the context the operation ran under, which is the child this
    // built rather than the one the hook was installed on.
    const seen: string[] = [];
    const parent = createChildContext({
      name: 'outer',
      auditReveal: (_v, _d, ctx) => {
        const operation: unknown = ctx.tags?.['operation'];
        seen.push(typeof operation === 'string' ? operation : 'none');
      },
    });

    withRevealContext(parent, () => {
      const secret = new SensitiveString(CANARY, 'sensitive');
      secret.reveal(buildWriteContext({ sink: 'kysely', operation: 'predicate' }));
    });

    expect(seen).toEqual(['predicate']);
  });

  it('describes every operation without naming a value', () => {
    for (const operation of [
      'insert',
      'update',
      'delete',
      'predicate',
      'change-detection',
      'unknown',
    ] as const) {
      const context = buildWriteContext({ sink: 's', column: CANARY, operation });
      expect(context.reason).toBeTruthy();
      expect(context.reason).not.toContain('undefined');
    }
  });
});
