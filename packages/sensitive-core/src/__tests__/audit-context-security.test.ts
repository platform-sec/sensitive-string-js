/**
 * The audit hook's context argument, treated as a disclosure channel.
 *
 * The hook runs inside the raw-value gate, so anything newly handed to it is a
 * reference an audit sink can walk, stringify, or ship to a log aggregator. The
 * question these tests answer is whether the context is a way to reach a value
 * that `reveal()` would have gated.
 */
import * as util from 'node:util';
import { beforeEach, describe, expect, it } from 'vitest';
import {
  SensitiveString,
  createChildContext,
  resetPolicies,
  safeStringify,
  withRevealContext,
} from '../index.js';
import type { AuditContext, RevealContext } from '../index.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

/** Everything a sink could plausibly do with the object it is handed. */
function everythingASinkCouldPrint(context: AuditContext): string {
  return [
    String(context.name),
    String(context.reason),
    util.inspect(context, { depth: 10 }),
    safeStringify(context),
    JSON.stringify(context, (_key, value: unknown) => value) ?? '',
    Object.entries(context.tags ?? {})
      .map(([key, value]) => `${key}=${String(value)}`)
      .join(','),
  ].join('\n');
}

describe('the audit context as a disclosure channel', () => {
  beforeEach(() => {
    resetPolicies();
  });

  it('carries nothing of the value being audited', () => {
    let printed = '';
    const ctx: RevealContext = {
      name: 'audit',
      reason: 'unit test',
      tags: { requestId: 'r-1' },
      auditReveal: (_value, _details, context) => {
        printed = everythingASinkCouldPrint(context);
      },
    };

    const revealed = new SensitiveString(CANARY, 'credential', 'api_key').reveal(ctx);

    expect(revealed).toBe(CANARY);
    expect(printed).not.toContain(CANARY);
    expect(printed).toContain('r-1');
  });

  it('redacts a sensitive value a caller put in the tags, as any other structure would', () => {
    let printed = '';
    const ctx: RevealContext = {
      name: 'audit',
      // A caller tagging a context with an instance rather than a string. The
      // context is handed over by reference, so this is the one shape that
      // could carry a value into a sink; it redacts on the way out like
      // everything else.
      tags: { actor: new SensitiveString(CANARY, 'sensitive', 'email') },
      auditReveal: (_value, _details, context) => {
        printed = everythingASinkCouldPrint(context);
      },
    };

    new SensitiveString(CANARY, 'credential').reveal(ctx);

    expect(printed).not.toContain(CANARY);
    expect(printed).toContain('[REDACTED');
  });

  it('gives a sink no reveal it did not already have', () => {
    const reachable: string[] = [];
    const ctx: RevealContext = {
      name: 'audit',
      auditReveal: (_value, _details, context) => {
        for (const key of Reflect.ownKeys(context)) {
          const property: unknown = (context as unknown as Record<string | symbol, unknown>)[key];
          // `auditReveal` is the one function on the object, and it is the
          // hook itself. Nothing here reads a value; nothing here is a
          // `SensitiveString`.
          if (typeof property === 'function') reachable.push(String(key));
        }
      },
    };

    new SensitiveString(CANARY, 'credential').reveal(ctx);

    expect(reachable).toEqual(['auditReveal']);
  });

  it('is shared across the reveals made under it, which is why a sink must not write to it', () => {
    const seen: (Record<string, unknown> | undefined)[] = [];
    const ctx: RevealContext = {
      name: 'audit',
      tags: { requestId: 'r-1' },
      auditReveal: (_value, _details, context) => {
        seen.push({ ...context.tags });
        // A sink doing the thing the contract forbids.
        (context.tags as Record<string, unknown>)['requestId'] = 'rewritten';
      },
    };

    const value = new SensitiveString(CANARY, 'sensitive');
    value.reveal(ctx);
    value.reveal(ctx);

    // Measured rather than asserted as safe: the second record carries the
    // first sink's edit. Copy out what a record keeps.
    expect(seen[0]).toEqual({ requestId: 'r-1' });
    expect(seen[1]).toEqual({ requestId: 'rewritten' });
  });

  it('reports the child a reveal ran under, not a context the caller never authorized against', () => {
    const seen: string[] = [];
    const outer: RevealContext = {
      name: 'request',
      auditReveal: (_value, _details, context) => {
        const column = context.tags?.['column'];
        seen.push(typeof column === 'string' ? column : 'none');
      },
    };

    withRevealContext(outer, () => {
      const value = new SensitiveString(CANARY, 'sensitive');
      value.reveal(createChildContext({ name: 'request', tags: { column: 'users.email' } }));
      value.reveal();
    });

    expect(seen).toEqual(['users.email', 'none']);
  });
});
