import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  createChildContext,
  resetPolicies,
  withRevealContext,
} from '@platform-sec/sensitive-string-core';
import type { ISensitiveString, RevealDetails } from '@platform-sec/sensitive-string-core';
import { createMockAuditLog, mockRevealContext } from './mocks.js';
import type { AuditRevealFn } from './mocks.js';
import { createTestSecret } from './create-test-secret.js';

const CANARY = 'MOCKS_CANARY_5e39';

describe('mockRevealContext', () => {
  beforeEach(() => {
    resetPolicies();
  });

  // TST-TU-MOC-001
  it('records a reveal made through it', () => {
    const ctx = mockRevealContext('test-handler');
    const secret = createTestSecret('credential', 'api_key');

    secret.reveal(ctx);

    expect(ctx.calls).toHaveLength(1);
    expect(ctx.calls[0]?.value.klass).toBe('credential');
    expect(ctx.calls[0]?.value.label).toBe('api_key');
    expect(ctx.calls[0]?.details.operation).toBe('reveal');
    expect(ctx.calls[0]?.timestamp).toBeInstanceOf(Date);
  });

  it('records a mask as a mask, with the options that produced it', () => {
    const ctx = mockRevealContext('support-screen');
    const email = createTestSecret('sensitive', 'email', { value: 'jane@example.com' });

    email.mask({ showFirst: 1, showLast: 4 }, ctx);

    const details = ctx.calls[0]?.details as Extract<RevealDetails, { operation: 'mask' }>;

    expect(details.operation).toBe('mask');
    expect(details.showFirst).toBe(1);
    expect(details.showLast).toBe(4);
  });

  it('records reveals made under it through AsyncLocalStorage', () => {
    const ctx = mockRevealContext('request-scope');
    const secret = createTestSecret('sensitive', 'email');

    withRevealContext(ctx, () => {
      secret.reveal();
      secret.reveal();
    });

    expect(ctx.calls).toHaveLength(2);
  });

  it('records nothing for a value never accessed through it', () => {
    const ctx = mockRevealContext('unused');
    createTestSecret('credential', 'api_key').reveal();

    expect(ctx.calls).toHaveLength(0);
  });

  it('records the context each operation ran under, as a copy', () => {
    const ctx = mockRevealContext('request-scope', { tags: { requestId: 'r-1' } });
    const secret = createTestSecret('sensitive', 'email');

    secret.reveal(ctx);
    const recorded = ctx.calls[0]?.context;

    expect(recorded?.name).toBe('request-scope');
    expect(recorded?.tags).toEqual({ requestId: 'r-1' });
    // A copy, or the log would point back at the context that holds it.
    expect(recorded).not.toBe(ctx);
    expect(() => JSON.stringify(ctx.calls)).not.toThrow();
  });

  it('records the child a reveal ran under, not the context the hook came from', () => {
    const ctx = mockRevealContext('request-scope');
    const secret = createTestSecret('sensitive', 'email');

    withRevealContext(ctx, () => {
      secret.reveal(createChildContext({ name: 'db-write', tags: { column: 'users.email' } }));
    });

    expect(ctx.calls[0]?.context.name).toBe('db-write');
    expect(ctx.calls[0]?.context.tags).toEqual({ column: 'users.email' });
  });

  it('records a call from a caller that forwards the hook with two arguments', () => {
    const ctx = mockRevealContext('request-scope');
    const secret = createTestSecret('sensitive', 'email');

    // What a forwarder compiled against the two-argument hook does, and what
    // core itself did before it carried the context. It runs inside the reveal
    // gate, so throwing here would surface as a failing reveal in someone
    // else's test rather than as a missing tag.
    const forwarded = ctx.auditReveal as (value: ISensitiveString, details: RevealDetails) => void;
    forwarded(secret, { operation: 'reveal' });

    expect(ctx.calls).toHaveLength(1);
    expect(ctx.calls[0]?.context.name).toBe('request-scope');
    expect(ctx.calls[0]?.context.tags).toBeUndefined();
  });

  it('holds the instance rather than the raw value', () => {
    const ctx = mockRevealContext('test-handler');
    const secret = createTestSecret('credential', 'api_key');

    secret.reveal(ctx);

    expect(JSON.stringify(ctx.calls)).not.toContain(secret.reveal());
  });

  it('carries a reason and tags onto the context', () => {
    const ctx = mockRevealContext('billing', {
      reason: 'charging a card',
      tags: { requestId: 'req-1' },
    });

    expect(ctx.reason).toBe('charging a card');
    expect(ctx.tags).toEqual({ requestId: 'req-1' });
  });

  it('omits a reason and tags that were not given', () => {
    const ctx = mockRevealContext('plain');

    expect('reason' in ctx).toBe(false);
    expect('tags' in ctx).toBe(false);
  });

  // TST-TU-MOC-002
  it('clears recorded calls on reset', () => {
    const ctx = mockRevealContext('test-handler');
    const secret = createTestSecret('sensitive');

    secret.reveal(ctx);
    expect(ctx.calls).toHaveLength(1);

    ctx.reset();

    expect(ctx.calls).toHaveLength(0);
  });

  it('keeps working after a reset', () => {
    const ctx = mockRevealContext('test-handler');
    const secret = createTestSecret('sensitive');

    secret.reveal(ctx);
    ctx.reset();
    secret.reveal(ctx);

    expect(ctx.calls).toHaveLength(1);
  });

  // TST-TU-MOC-003
  describe('with a Vitest spy factory', () => {
    it('makes auditReveal a spy the framework can assert on', () => {
      const ctx = mockRevealContext('test-handler', { fn: vi.fn });
      const secret = createTestSecret('credential', 'api_key');

      secret.reveal(ctx);

      expect(ctx.auditReveal).toHaveBeenCalledTimes(1);
      expect(ctx.calls).toHaveLength(1);
    });

    it('clears the spy as well as the call list on reset', () => {
      const ctx = mockRevealContext('test-handler', { fn: vi.fn });
      const secret = createTestSecret('sensitive');

      secret.reveal(ctx);
      ctx.reset();

      expect(ctx.auditReveal).toHaveBeenCalledTimes(0);
      expect(ctx.calls).toHaveLength(0);
    });
  });

  // TST-TU-MOC-004
  describe('with a foreign spy factory', () => {
    /**
     * Jest is not installed in this repository, so this stands in for it: the
     * factory contract is a callable that forwards to the implementation and
     * exposes `mockClear`, which is what `jest.fn` provides.
     */
    function fakeJestFn(implementation: AuditRevealFn): AuditRevealFn {
      const calls: unknown[][] = [];
      const spy = ((...args: Parameters<AuditRevealFn>) => {
        calls.push(args);
        implementation(...args);
      }) as AuditRevealFn & { mock: { calls: unknown[][] }; mockClear: () => void };

      spy.mock = { calls };
      spy.mockClear = () => {
        calls.length = 0;
      };

      return spy;
    }

    it('records through the spy and clears it on reset', () => {
      const ctx = mockRevealContext('test-handler', { fn: fakeJestFn });
      const secret = createTestSecret('sensitive');
      const spy = ctx.auditReveal as AuditRevealFn & { mock: { calls: unknown[][] } };

      secret.reveal(ctx);

      expect(spy.mock.calls).toHaveLength(1);
      expect(ctx.calls).toHaveLength(1);

      ctx.reset();

      expect(spy.mock.calls).toHaveLength(0);
      expect(ctx.calls).toHaveLength(0);
    });

    it('tolerates a factory whose result is not a spy at all', () => {
      const ctx = mockRevealContext('test-handler', { fn: (impl) => impl });
      const secret = createTestSecret('sensitive');

      secret.reveal(ctx);

      expect(() => ctx.reset()).not.toThrow();
      expect(ctx.calls).toHaveLength(0);
    });
  });
});

describe('createMockAuditLog', () => {
  beforeEach(() => {
    resetPolicies();
  });

  // TST-TU-MOC-005
  it('captures an entry per access', () => {
    const audit = createMockAuditLog();
    const secret = createTestSecret('credential', 'api_key');

    withRevealContext(audit.context, () => {
      secret.reveal();
      secret.reveal();
    });

    expect(audit.entries).toHaveLength(2);
    expect(audit.entries[0]?.klass).toBe('credential');
    expect(audit.entries[0]?.label).toBe('api_key');
    expect(audit.entries[0]?.operation).toBe('reveal');
    expect(audit.entries[0]?.contextName).toBe('mock-audit-log');
  });

  it('uses a caller-supplied context name', () => {
    const audit = createMockAuditLog('payment-handler');
    createTestSecret('sensitive').reveal(audit.context);

    expect(audit.entries[0]?.contextName).toBe('payment-handler');
  });

  it('names the context the reveal ran under, not the log it was installed on', () => {
    const audit = createMockAuditLog('payment-handler');

    // What an integration does to attribute a reveal: nest a child, keep the
    // hook. The entry says where the reveal happened rather than where the
    // sink was installed, which is the whole point of asserting on it.
    withRevealContext(audit.context, () => {
      createTestSecret('sensitive').reveal(createChildContext({ name: 'card-gateway' }));
    });

    expect(audit.entries[0]?.contextName).toBe('card-gateway');
  });

  it('names itself when a two-argument caller forwards the hook', () => {
    const audit = createMockAuditLog('payment-handler');
    const secret = createTestSecret('credential', 'api_key');

    // Called through the context, which is what a forwarder does and what core
    // itself did: `ambient.auditReveal?.(value, details)`.
    const forwarder = audit.context as unknown as {
      auditReveal: (value: ISensitiveString, details: RevealDetails) => void;
    };

    forwarder.auditReveal(secret, { operation: 'reveal' });

    expect(audit.entries).toHaveLength(1);
    expect(audit.entries[0]?.contextName).toBe('payment-handler');
  });

  it('records a mask and a renewal alongside a reveal', () => {
    const audit = createMockAuditLog();
    const email = createTestSecret('sensitive', 'email', {
      value: 'jane@example.com',
      ttl: 60_000,
    });

    withRevealContext(audit.context, () => {
      email.reveal();
      email.mask({ strategy: 'email' });
      email.renew(60_000);
    });

    expect(audit.entries.map((entry) => entry.operation)).toEqual(['reveal', 'mask', 'renew']);
  });

  it('keeps no raw value and no reference to the instance', () => {
    const audit = createMockAuditLog();
    const secret = createTestSecret('credential', 'api_key');

    secret.reveal(audit.context);

    expect(JSON.stringify(audit.entries)).not.toContain(secret.reveal());
    expect(Object.values(audit.entries[0] ?? {})).not.toContain(secret);
  });

  // TST-TU-MOC-006
  it('filters entries by label', () => {
    const audit = createMockAuditLog();

    withRevealContext(audit.context, () => {
      createTestSecret('credential', 'api_key').reveal();
      createTestSecret('sensitive', 'email').reveal();
      createTestSecret('credential', 'api_key').reveal();
    });

    expect(audit.getEntriesFor('api_key')).toHaveLength(2);
    expect(audit.getEntriesFor('email')).toHaveLength(1);
    expect(audit.getEntriesFor('missing')).toHaveLength(0);
  });

  // TST-TU-MOC-007
  it('filters entries by class', () => {
    const audit = createMockAuditLog();

    withRevealContext(audit.context, () => {
      createTestSecret('credential', 'api_key').reveal();
      createTestSecret('sensitive', 'email').reveal();
      createTestSecret('sensitive', 'phone').reveal();
    });

    expect(audit.getEntriesByClass('credential')).toHaveLength(1);
    expect(audit.getEntriesByClass('sensitive')).toHaveLength(2);
  });

  it('forgets every entry on clear', () => {
    const audit = createMockAuditLog();
    createTestSecret('sensitive').reveal(audit.context);

    audit.clear();

    expect(audit.entries).toHaveLength(0);
    expect(audit.getEntriesByClass('sensitive')).toHaveLength(0);
  });

  it('records nothing when no value was accessed', () => {
    const audit = createMockAuditLog();
    createTestSecret('sensitive', 'email', { value: CANARY });

    expect(audit.entries).toHaveLength(0);
  });
});
