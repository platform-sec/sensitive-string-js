/**
 * Operation Policy Enforcement Tests
 *
 * Verifies that all operations that access the #value field respect policy controls,
 * including checkRevealAllowed and auditReveal callbacks.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  SensitiveString,
  ISensitiveString,
  RevealAccess,
  RevealContext,
  RevealDetails,
  registerPolicy,
  resetPolicies,
  withRevealContext,
} from '../index.js';

const CANARY = 'POLICY_ENFORCEMENT_CANARY_xyz789';

describe('Policy Enforcement Security', () => {
  beforeEach(() => {
    resetPolicies();
  });

  // All operations that access #value
  const VALUE_ACCESSING_OPERATIONS: Array<{
    name: string;
    execute: (s: SensitiveString<'credential'>, ctx?: RevealContext) => unknown;
    /** The audit record the operation reports. Defaults to a full reveal. */
    auditDetails?: RevealDetails;
  }> = [
    {
      name: 'reveal()',
      execute: (s, ctx) => s.reveal(ctx),
    },
    {
      name: 'mask()',
      execute: (s, ctx) => s.mask({ showLast: 2 }, ctx),
      auditDetails: {
        operation: 'mask',
        strategy: 'positional',
        showFirst: 0,
        showLast: 2,
        minMasked: 8,
        maskChar: '*',
      },
    },
    {
      name: 'equals(string)',
      execute: (s, ctx) => s.equals('test', ctx),
    },
    {
      name: 'equals(SensitiveString)',
      execute: (s, ctx) => s.equals(new SensitiveString('test', 'credential'), ctx),
    },
    {
      name: 'substring()',
      execute: (s, ctx) => s.substring(0, 3, ctx),
    },
    {
      name: 'trim()',
      execute: (s, ctx) => s.trim(ctx),
    },
    {
      name: 'trimStart()',
      execute: (s, ctx) => s.trimStart(ctx),
    },
    {
      name: 'trimEnd()',
      execute: (s, ctx) => s.trimEnd(ctx),
    },
    {
      name: 'toLowerCase()',
      execute: (s, ctx) => s.toLowerCase(ctx),
    },
    {
      name: 'toUpperCase()',
      execute: (s, ctx) => s.toUpperCase(ctx),
    },
    {
      name: 'padStart()',
      execute: (s, ctx) => s.padStart(40, '*', ctx),
    },
    {
      name: 'padEnd()',
      execute: (s, ctx) => s.padEnd(40, '*', ctx),
    },
    {
      name: 'slice()',
      execute: (s, ctx) => s.slice(0, 3, ctx),
    },
    {
      name: 'startsWith()',
      execute: (s, ctx) => s.startsWith('test', 0, ctx),
    },
    {
      name: 'endsWith()',
      execute: (s, ctx) => s.endsWith('test', undefined, ctx),
    },
    {
      name: 'includes()',
      execute: (s, ctx) => s.includes('test', 0, ctx),
    },
    {
      name: 'indexOf()',
      execute: (s, ctx) => s.indexOf('test', 0, ctx),
    },
    {
      name: 'lastIndexOf()',
      execute: (s, ctx) => s.lastIndexOf('test', undefined, ctx),
    },
    {
      name: 'test()',
      execute: (s, ctx) => s.test(/test/, ctx),
    },
    {
      name: 'search()',
      execute: (s, ctx) => s.search(/test/, ctx),
    },
    {
      name: 'match()',
      execute: (s, ctx) => s.match(/test/, ctx),
    },
    {
      name: 'matchGroups()',
      execute: (s, ctx) => s.matchGroups(/(?<value>test)/, ctx),
    },
    {
      name: 'matchAll()',
      execute: (s, ctx) => s.matchAll(/test/g, ctx),
    },
    {
      name: 'split()',
      execute: (s, ctx) => s.split('-', undefined, ctx),
    },
    {
      name: 'replace()',
      execute: (s, ctx) => s.replace('test', 'replacement', ctx),
    },
    {
      name: 'replaceAll()',
      execute: (s, ctx) => s.replaceAll('test', 'replacement', ctx),
    },
    {
      name: 'charAt()',
      execute: (s, ctx) => s.charAt(0, ctx),
    },
    {
      name: 'at()',
      execute: (s, ctx) => s.at(-1, ctx),
    },
    {
      name: 'map()',
      execute: (s, ctx) => s.map((v) => v.toUpperCase(), ctx),
    },
    {
      name: 'concat(string)',
      execute: (s, ctx) => s.concat('suffix', ctx),
    },
    {
      name: 'concat(SensitiveString)',
      execute: (s, ctx) => s.concat(new SensitiveString('suffix', 'credential'), ctx),
    },
    {
      name: 'reclassify()',
      execute: (s, ctx) => s.reclassify('sensitive', undefined, ctx),
    },
    {
      name: 'serialize()',
      execute: (s, ctx) => s.serialize(ctx),
    },
  ];

  describe('checkRevealAllowed is enforced', () => {
    beforeEach(() => {
      // Register a policy that requires context for all reveals
      registerPolicy(
        {
          name: 'credential',
          redact: () => '[REDACTED:credential]',
          allowPartialQueries: true,
          allowMask: true,
          checkRevealAllowed: (ctx) => {
            if (!ctx) {
              throw new Error('Context required for credential access');
            }
            if (ctx.name === 'forbidden') {
              throw new Error('Access forbidden for this context');
            }
          },
        },
        { overwrite: true }
      );
    });

    for (const op of VALUE_ACCESSING_OPERATIONS) {
      it(`${op.name} throws without context`, () => {
        const s = new SensitiveString(CANARY, 'credential');
        expect(() => op.execute(s)).toThrow('Context required for credential access');
      });

      it(`${op.name} succeeds with valid ALS context`, () => {
        const s = new SensitiveString(CANARY, 'credential');
        const ctx: RevealContext = { name: 'valid-context' };

        withRevealContext(ctx, () => {
          expect(() => op.execute(s)).not.toThrow();
        });
      });

      it(`${op.name} throws with forbidden context`, () => {
        const s = new SensitiveString(CANARY, 'credential');
        const ctx: RevealContext = { name: 'forbidden' };

        withRevealContext(ctx, () => {
          expect(() => op.execute(s)).toThrow('Access forbidden for this context');
        });
      });

      it(`${op.name} succeeds with explicit context`, () => {
        const s = new SensitiveString(CANARY, 'credential');
        const ctx: RevealContext = { name: 'explicit-context' };

        expect(() => op.execute(s, ctx)).not.toThrow();
      });

      it(`${op.name} explicit context overrides ALS context`, () => {
        const s = new SensitiveString(CANARY, 'credential');
        const forbiddenCtx: RevealContext = { name: 'forbidden' };
        const allowedCtx: RevealContext = { name: 'allowed' };

        // ALS has forbidden context, but explicit context is allowed
        withRevealContext(forbiddenCtx, () => {
          expect(() => op.execute(s, allowedCtx)).not.toThrow();
        });
      });
    }
  });

  describe('auditReveal is called', () => {
    beforeEach(() => {
      registerPolicy(
        {
          name: 'credential',
          redact: () => '[REDACTED:credential]',
          requireConstantTimeEquals: true,
          allowPartialQueries: true,
          allowMask: true,
        },
        { overwrite: true }
      );
    });

    for (const op of VALUE_ACCESSING_OPERATIONS) {
      const expectedAuditCount = op.name.startsWith('equals(')
        ? 0
        : op.name === 'concat(SensitiveString)'
          ? 2
          : 1;
      const shouldAudit = expectedAuditCount > 0;
      const auditDetails: RevealDetails = op.auditDetails ?? { operation: 'reveal' };

      if (shouldAudit) {
        it(`${op.name} calls auditReveal via ALS context`, () => {
          const s = new SensitiveString(CANARY, 'credential');
          const auditSpy = vi.fn();

          const ctx: RevealContext = {
            name: 'audit-test',
            auditReveal: auditSpy,
          };

          withRevealContext(ctx, () => {
            op.execute(s);
          });

          expect(auditSpy).toHaveBeenCalledTimes(expectedAuditCount);
          expect(auditSpy).toHaveBeenCalledWith(s, auditDetails, ctx);
        });

        it(`${op.name} calls auditReveal via explicit context`, () => {
          const s = new SensitiveString(CANARY, 'credential');
          const auditSpy = vi.fn();

          const ctx: RevealContext = {
            name: 'explicit-audit',
            auditReveal: auditSpy,
          };

          op.execute(s, ctx);

          expect(auditSpy).toHaveBeenCalledTimes(expectedAuditCount);
          expect(auditSpy).toHaveBeenCalledWith(s, auditDetails, ctx);
        });

        it(`${op.name} explicit context audit overrides ALS context audit`, () => {
          const s = new SensitiveString(CANARY, 'credential');
          const alsAuditSpy = vi.fn();
          const explicitAuditSpy = vi.fn();

          const alsCtx: RevealContext = {
            name: 'als',
            auditReveal: alsAuditSpy,
          };

          const explicitCtx: RevealContext = {
            name: 'explicit',
            auditReveal: explicitAuditSpy,
          };

          withRevealContext(alsCtx, () => {
            op.execute(s, explicitCtx);
          });

          expect(alsAuditSpy).not.toHaveBeenCalled();
          expect(explicitAuditSpy).toHaveBeenCalledTimes(expectedAuditCount);
        });
      } else {
        it(`${op.name} authorizes access without auditing it as a reveal`, () => {
          const s = new SensitiveString(CANARY, 'credential');
          const auditSpy = vi.fn();

          op.execute(s, { name: 'comparison', auditReveal: auditSpy });

          expect(auditSpy).not.toHaveBeenCalled();
        });
      }
    }
  });

  describe('audit callback receives correct instance', () => {
    it('auditReveal receives the original SensitiveString instance', () => {
      const s = new SensitiveString(CANARY, 'credential', 'test_label');
      let receivedInstance: unknown = null;

      const ctx: RevealContext = {
        name: 'instance-test',
        auditReveal: (instance) => {
          receivedInstance = instance;
        },
      };

      s.reveal(ctx);

      expect(receivedInstance).toBe(s);
      expect((receivedInstance as SensitiveString<'credential'>).klass).toBe('credential');
      expect((receivedInstance as SensitiveString<'credential'>).label).toBe('test_label');
    });

    it('auditReveal can access klass and label but not value', () => {
      const s = new SensitiveString(CANARY, 'credential', 'api_key');
      let klassValue: string | null = null;
      let labelValue: string | undefined | null = null;
      let toStringValue: string | null = null;

      const ctx: RevealContext = {
        name: 'access-test',
        auditReveal: (instance) => {
          klassValue = instance.klass;
          labelValue = instance.label;
          toStringValue = instance.toString();
        },
      };

      s.reveal(ctx);

      expect(klassValue).toBe('credential');
      expect(labelValue).toBe('api_key');
      expect(toStringValue).toBe('[REDACTED:credential]');
      expect(toStringValue).not.toContain(CANARY);
    });
  });

  describe('policy enforcement per class', () => {
    it('different classes can have different policies', () => {
      registerPolicy(
        {
          name: 'credential',
          redact: () => '[REDACTED:credential]',
          checkRevealAllowed: (ctx) => {
            if (!ctx) throw new Error('Credential requires context');
          },
        },
        { overwrite: true }
      );

      // sensitive class keeps default policy (no checkRevealAllowed)

      const credential = new SensitiveString(CANARY, 'credential');
      const sensitive = new SensitiveString(CANARY, 'sensitive');

      // credential requires context
      expect(() => credential.reveal()).toThrow('Credential requires context');

      // sensitive does not require context
      expect(() => sensitive.reveal()).not.toThrow();
      expect(sensitive.reveal()).toBe(CANARY);
    });

    it('policy changes affect existing instances', () => {
      const s = new SensitiveString(CANARY, 'credential');

      // Initially, no context required
      expect(s.reveal()).toBe(CANARY);

      // Register stricter policy
      registerPolicy(
        {
          name: 'credential',
          redact: () => '[REDACTED:credential]',
          checkRevealAllowed: (ctx) => {
            if (!ctx) throw new Error('Now requires context');
          },
        },
        { overwrite: true }
      );

      // Same instance now requires context
      expect(() => s.reveal()).toThrow('Now requires context');
    });
  });

  describe('nested operations', () => {
    it('nested reveal calls each trigger audit', () => {
      const s1 = new SensitiveString('first', 'credential');
      const s2 = new SensitiveString('second', 'credential');
      const auditedInstances: ISensitiveString[] = [];

      const ctx: RevealContext = {
        name: 'nested-test',
        auditReveal: (instance) => {
          // Track which instances were audited (don't call reveal() here to avoid recursion)
          auditedInstances.push(instance);
        },
      };

      // Concatenating two SensitiveStrings audits both inputs.
      s1.concat(s2, ctx);

      expect(auditedInstances).toHaveLength(2);
      expect(auditedInstances).toContain(s1);
      expect(auditedInstances).toContain(s2);
    });

    it('chained operations maintain context', () => {
      const s = new SensitiveString(CANARY, 'credential');
      const auditSpy = vi.fn();

      const ctx: RevealContext = {
        name: 'chain-test',
        auditReveal: auditSpy,
      };

      withRevealContext(ctx, () => {
        s.substring(0, 3)
          .map((v) => v.toUpperCase())
          .concat('suffix');
      });

      // Each operation should trigger audit
      expect(auditSpy).toHaveBeenCalledTimes(3);
    });
  });

  describe('error handling in policy', () => {
    it('checkRevealAllowed errors do not leak value', () => {
      registerPolicy(
        {
          name: 'credential',
          redact: () => '[REDACTED:credential]',
          checkRevealAllowed: () => {
            throw new Error('Access denied');
          },
        },
        { overwrite: true }
      );

      const s = new SensitiveString(CANARY, 'credential');

      try {
        s.reveal();
        expect.fail('Should have thrown');
      } catch (e) {
        expect((e as Error).message).not.toContain(CANARY);
        expect((e as Error).stack ?? '').not.toContain(CANARY);
      }
    });

    it('auditReveal errors propagate but do not leak value', () => {
      const s = new SensitiveString(CANARY, 'credential');

      const ctx: RevealContext = {
        name: 'error-test',
        auditReveal: () => {
          throw new Error('Audit failed');
        },
      };

      try {
        s.reveal(ctx);
        expect.fail('Should have thrown');
      } catch (e) {
        expect((e as Error).message).not.toContain(CANARY);
        expect((e as Error).message).toBe('Audit failed');
      }
    });

    it('auditReveal error occurs after checkRevealAllowed passes', () => {
      const executionOrder: string[] = [];

      registerPolicy(
        {
          name: 'credential',
          redact: () => '[REDACTED:credential]',
          checkRevealAllowed: () => {
            executionOrder.push('checkRevealAllowed');
          },
        },
        { overwrite: true }
      );

      const s = new SensitiveString(CANARY, 'credential');

      const ctx: RevealContext = {
        name: 'order-test',
        auditReveal: () => {
          executionOrder.push('auditReveal');
          throw new Error('Audit error');
        },
      };

      try {
        s.reveal(ctx);
      } catch {
        // Expected
      }

      expect(executionOrder).toEqual(['checkRevealAllowed', 'auditReveal']);
    });
  });

  describe('checkRevealAllowed receives the value and the access kind', () => {
    /** Record every authorization the policy for `credential` is asked for. */
    function recordCalls(): Array<{ value: ISensitiveString; access: RevealAccess }> {
      const calls: Array<{ value: ISensitiveString; access: RevealAccess }> = [];

      registerPolicy(
        {
          name: 'credential',
          redact: () => '[REDACTED:credential]',
          allowMask: true,
          allowPartialQueries: true,
          checkRevealAllowed: (_ctx, value, access) => {
            calls.push({ value, access });
          },
        },
        { overwrite: true }
      );

      return calls;
    }

    it('names the instance being read, not a copy of it', () => {
      const calls = recordCalls();
      const s = new SensitiveString(CANARY, 'credential', 'api_key');

      s.reveal();

      expect(calls).toHaveLength(1);
      expect(calls[0]?.value).toBe(s);
      expect(calls[0]?.value.label).toBe('api_key');
      expect(calls[0]?.value.klass).toBe('credential');
    });

    it.each([
      ['reveal()', (s: SensitiveString<'credential'>) => s.reveal(), 'expose'],
      ['mask()', (s: SensitiveString<'credential'>) => s.mask({ showLast: 2 }), 'expose'],
      ['serialize()', (s: SensitiveString<'credential'>) => s.serialize(), 'expose'],
      ['substring()', (s: SensitiveString<'credential'>) => s.substring(0, 3), 'expose'],
      ['reclassify()', (s: SensitiveString<'credential'>) => s.reclassify('credential'), 'expose'],
      ['equals()', (s: SensitiveString<'credential'>) => s.equals('other'), 'compare'],
    ])('%s authorizes with access %s', (_name, operation, expected) => {
      const calls = recordCalls();

      operation(new SensitiveString(CANARY, 'credential'));

      expect(calls.map((call) => call.access)).toEqual([expected]);
    });

    it('reports renew() as its own kind rather than as a read', () => {
      const calls = recordCalls();
      const s = new SensitiveString(CANARY, 'credential', 'session', {
        ttl: 60_000,
        allowRenewal: true,
      });

      s.renew(60_000);

      expect(calls.map((call) => call.access)).toEqual(['renew']);
    });

    it('authorizes both operands of a comparison, each as itself', () => {
      const calls = recordCalls();
      const a = new SensitiveString(CANARY, 'credential', 'left');
      const b = new SensitiveString(CANARY, 'credential', 'right');

      a.equals(b);

      expect(calls.map((call) => call.value)).toEqual([a, b]);
      expect(calls.map((call) => call.access)).toEqual(['compare', 'compare']);
    });

    it('names the derived instance, not the value it came from', () => {
      const calls = recordCalls();
      const parent = new SensitiveString(CANARY, 'credential', 'api_key');
      const child = parent.substring(0, 4);

      calls.length = 0;
      child.reveal();

      expect(calls).toHaveLength(1);
      expect(calls[0]?.value).toBe(child);
      expect(calls[0]?.value).not.toBe(parent);
    });

    it('is not consulted for reads that only feed redaction', () => {
      const calls = recordCalls();
      const s = new SensitiveString(CANARY, 'credential');

      String(s);
      JSON.stringify(s);
      void s.length;
      void s.isEmpty();

      expect(calls).toHaveLength(0);
    });

    it('keeps working for a policy that declares only the context', () => {
      // The parameters were added after the context-only form. A hook written
      // against the old signature must still compile and still deny.
      const seen: Array<RevealContext | null> = [];

      registerPolicy(
        {
          name: 'credential',
          redact: () => '[REDACTED:credential]',
          checkRevealAllowed: (ctx) => {
            seen.push(ctx);
            throw new Error('denied');
          },
        },
        { overwrite: true }
      );

      const s = new SensitiveString(CANARY, 'credential');

      expect(() => s.reveal()).toThrow('denied');
      expect(seen).toEqual([null]);
    });

    it('does not hand the raw value to the hook', () => {
      let leaked = '';

      registerPolicy(
        {
          name: 'credential',
          redact: () => '[REDACTED:credential]',
          checkRevealAllowed: (ctx, value, access) => {
            leaked = `${String(value)}|${access}|${JSON.stringify(value)}|${JSON.stringify(ctx)}`;
          },
        },
        { overwrite: true }
      );

      new SensitiveString(CANARY, 'credential').reveal();

      expect(leaked).not.toContain(CANARY);
    });
  });

  describe('context validation', () => {
    it('checkRevealAllowed receives null when no context', () => {
      let receivedCtx: RevealContext | null | undefined = undefined;

      registerPolicy(
        {
          name: 'credential',
          redact: () => '[REDACTED:credential]',
          checkRevealAllowed: (ctx) => {
            receivedCtx = ctx;
          },
        },
        { overwrite: true }
      );

      const s = new SensitiveString(CANARY, 'credential');
      s.reveal();

      expect(receivedCtx).toBeNull();
    });

    it('checkRevealAllowed receives full context object', () => {
      const receivedContexts: Array<RevealContext | null | undefined> = [];

      registerPolicy(
        {
          name: 'credential',
          redact: () => '[REDACTED:credential]',
          checkRevealAllowed: (ctx) => {
            receivedContexts.push(ctx);
          },
        },
        { overwrite: true }
      );

      const s = new SensitiveString(CANARY, 'credential');
      const ctx: RevealContext = {
        name: 'full-context',
        reason: 'unit test',
        tags: { requestId: '123', userId: 'user456' },
      };

      s.reveal(ctx);

      const receivedCtx = receivedContexts[0];
      expect(receivedCtx).toEqual(ctx);
      expect(receivedCtx?.name).toBe('full-context');
      expect(receivedCtx?.reason).toBe('unit test');
      expect(receivedCtx?.tags).toEqual({ requestId: '123', userId: 'user456' });
    });
  });
});
