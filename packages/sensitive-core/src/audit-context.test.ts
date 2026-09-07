/**
 * The context an audit hook is handed, for every operation that records one.
 *
 * The hook used to receive the value and the operation and nothing more, so a
 * sink could not tell which unit of work a reveal belonged to unless the caller
 * installed the context ambiently around every single read. Integrations did
 * exactly that, one `AsyncLocalStorage` entry per value, to get a table name or
 * an argument path as far as a log line. These tests pin the third argument
 * that replaced the workaround.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  SensitiveString,
  createChildContext,
  getCurrentRevealContext,
  registerPolicy,
  resetPolicies,
  withAuditedReveals,
  withRevealContext,
} from './index.js';
import type { AuditContext, RevealContext, RevealDetails } from './index.js';

const CANARY = 'CANARY-AUDIT-CONTEXT-90210';

/** The third argument of the single call a hook recorded. */
function contextSeenBy(spy: ReturnType<typeof vi.fn>): AuditContext {
  expect(spy).toHaveBeenCalledTimes(1);
  return spy.mock.calls[0]?.[2] as AuditContext;
}

describe('the context handed to an audit hook', () => {
  beforeEach(() => {
    resetPolicies();
  });

  describe('which context arrives', () => {
    it('is the explicit one when the call passes a context', () => {
      const auditReveal = vi.fn();
      const ctx: RevealContext = { name: 'explicit', reason: 'unit test', auditReveal };

      new SensitiveString(CANARY, 'sensitive').reveal(ctx);

      expect(contextSeenBy(auditReveal)).toBe(ctx);
    });

    it('is the ambient one when the call passes none', () => {
      const auditReveal = vi.fn();
      const ctx: RevealContext = { name: 'ambient', auditReveal };

      withRevealContext(ctx, () => {
        new SensitiveString(CANARY, 'sensitive').reveal();
      });

      expect(contextSeenBy(auditReveal)).toBe(ctx);
    });

    it('is the explicit one when both exist, matching what the policy was asked to authorize', () => {
      const auditReveal = vi.fn();
      const authorized: (RevealContext | null)[] = [];

      registerPolicy(
        {
          name: 'sensitive',
          redact: () => '[REDACTED:sensitive]',
          checkRevealAllowed: (ctx) => {
            authorized.push(ctx);
          },
        },
        { overwrite: true }
      );

      const explicit: RevealContext = { name: 'explicit', auditReveal };
      const ambient: RevealContext = { name: 'ambient', auditReveal: vi.fn() };

      withRevealContext(ambient, () => new SensitiveString(CANARY, 'sensitive').reveal(explicit));

      // The two hooks are told the same thing, which is what makes an audit
      // record and an authorization decision comparable after the fact.
      expect(contextSeenBy(auditReveal)).toBe(explicit);
      expect(authorized).toEqual([explicit]);
    });

    it('is the live context object rather than a copy of it', () => {
      const auditReveal = vi.fn();
      const ctx: RevealContext = { name: 'identity', tags: { requestId: 'r-1' }, auditReveal };

      new SensitiveString(CANARY, 'sensitive').reveal(ctx);

      const seen = contextSeenBy(auditReveal);
      expect(seen).toBe(ctx);
      expect(seen.tags).toBe(ctx.tags);
    });
  });

  describe('a hook inherited by a child context', () => {
    it('is called with the child, not with the context it was installed on', () => {
      const auditReveal = vi.fn();
      const outer: RevealContext = { name: 'request', tags: { requestId: 'r-1' }, auditReveal };

      withRevealContext(outer, () => {
        const child = createChildContext({ name: 'request', tags: { column: 'users.email' } });
        new SensitiveString(CANARY, 'sensitive').reveal(child);
      });

      const seen = contextSeenBy(auditReveal);
      expect(seen.tags).toEqual({ requestId: 'r-1', column: 'users.email' });
    });

    it('reports what the reveal was for, where the ambient context reports where the caller stood', () => {
      const seen: { fromArgument?: unknown; fromAmbient?: unknown } = {};
      const outer: RevealContext = {
        name: 'request',
        auditReveal: (_value, _details, context) => {
          seen.fromArgument = context.tags;
          seen.fromAmbient = getCurrentRevealContext()?.tags;
        },
      };

      withRevealContext(outer, () => {
        const child = createChildContext({ name: 'request', tags: { path: 'data.token' } });
        new SensitiveString(CANARY, 'sensitive').reveal(child);
      });

      // The distinction the third argument exists for: without it, an
      // integration has to install `child` ambiently for a sink to see `path`.
      expect(seen.fromArgument).toEqual({ path: 'data.token' });
      expect(seen.fromAmbient).toBeUndefined();
    });
  });

  describe('every operation that records one', () => {
    function auditedContextFor(
      run: (value: SensitiveString<'sensitive'>, ctx: RevealContext) => void
    ): {
      details: RevealDetails;
      context: AuditContext;
    } {
      const auditReveal = vi.fn();
      const ctx: RevealContext = { name: 'operations', tags: { unit: 'test' }, auditReveal };
      run(new SensitiveString(CANARY, 'sensitive', 'label', { ttl: 60_000 }), ctx);

      expect(auditReveal).toHaveBeenCalledTimes(1);
      const call = auditReveal.mock.calls[0] as [unknown, RevealDetails, AuditContext];
      return { details: call[1], context: call[2] };
    }

    it('reveal', () => {
      const seen = auditedContextFor((value, ctx) => void value.reveal(ctx));
      expect(seen.details.operation).toBe('reveal');
      expect(seen.context.name).toBe('operations');
    });

    it('mask', () => {
      const seen = auditedContextFor((value, ctx) => void value.mask({ showLast: 2 }, ctx));
      expect(seen.details.operation).toBe('mask');
      expect(seen.context.tags).toEqual({ unit: 'test' });
    });

    it('hash', () => {
      const seen = auditedContextFor((value, ctx) => void value.hash('sha256', {}, ctx));
      expect(seen.details.operation).toBe('hash');
      expect(seen.context.name).toBe('operations');
    });

    it('renew', () => {
      const seen = auditedContextFor((value, ctx) => value.renew(60_000, {}, ctx));
      expect(seen.details.operation).toBe('renew');
      expect(seen.context.name).toBe('operations');
    });

    it('revoke', () => {
      const seen = auditedContextFor((value, ctx) => value.revoke('rotated', ctx));
      expect(seen.details.operation).toBe('revoke');
      expect(seen.context.name).toBe('operations');
    });
  });

  describe('withAuditedReveals', () => {
    it('hands its own context to the callback', () => {
      let seen: AuditContext | undefined;

      withAuditedReveals(
        'convenience',
        (_value, _details, context) => {
          seen = context;
        },
        () => {
          new SensitiveString(CANARY, 'sensitive').reveal();
        }
      );

      expect(seen?.name).toBe('convenience');
    });
  });

  describe('a hook written before the parameter existed', () => {
    it('still receives its two arguments and ignores the third', () => {
      const twoParameterHook = vi.fn((_value: unknown, _details: RevealDetails) => undefined);
      const ctx: RevealContext = { name: 'legacy', auditReveal: twoParameterHook };

      const revealed = new SensitiveString(CANARY, 'sensitive').reveal(ctx);

      expect(revealed).toBe(CANARY);
      expect(twoParameterHook).toHaveBeenCalledTimes(1);
    });
  });
});
