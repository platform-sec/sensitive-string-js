import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { createCanary } from '@platform-sec/sensitive-string-scrub/testing';
import { describe, expect, it, vi } from 'vitest';

import { sensitiveAttributes } from '../attributes.js';

/**
 * The scalar coercion helper.
 *
 * Measured on `newrelic` 14.3.10: `VALID_ATTR_TYPES` is `string`, `number`,
 * `boolean`, and an attribute of any other type is dropped with a debug log
 * and nothing else. `canary.test.ts` proves the drop against the real agent.
 * This file is about what arrives instead once the value has been through this
 * function.
 */

describe('sensitiveAttributes', () => {
  it('turns a wrapped value into its marker, where the agent would drop it', () => {
    const canary = createCanary();
    const secret = new SensitiveString(canary, 'credential', 'tok');

    expect(sensitiveAttributes({ token: secret })).toEqual({ token: '[REDACTED:credential]' });
  });

  it('turns a serialize() result into its marker', () => {
    const canary = createCanary();
    const secret = new SensitiveString(canary, 'credential');

    const out = sensitiveAttributes({ session: secret.serialize() });

    expect(out['session']).toBe('[REDACTED:credential]');
  });

  it('never carries a label, which is what the agent would otherwise transmit', () => {
    const secret = new SensitiveString(createCanary(), 'credential', 'stripe-live-key');

    expect(JSON.stringify(sensitiveAttributes({ token: secret }))).not.toContain('stripe-live-key');
  });

  it('censors a raw value whose key name says it is a credential', () => {
    const canary = createCanary();

    expect(sensitiveAttributes({ password: canary })).toEqual({ password: '[SCRUBBED]' });
  });

  it('passes the three accepted types through untouched', () => {
    expect(sensitiveAttributes({ tenant: 'acme', count: 3, ok: true })).toEqual({
      tenant: 'acme',
      count: 3,
      ok: true,
    });
  });

  it('does not modify the caller bag', () => {
    const secret = new SensitiveString(createCanary(), 'credential');
    const bag = { token: secret, tenant: 'acme' };

    sensitiveAttributes(bag);

    expect(bag.token).toBe(secret);
  });
});

describe('coercion of what the agent will not take', () => {
  it('omits undefined and null rather than inventing a value for them', () => {
    expect(sensitiveAttributes({ a: undefined, b: null, c: 1 })).toEqual({ c: 1 });
  });

  it('omits a function and a symbol', () => {
    expect(sensitiveAttributes({ fn: () => undefined, sym: Symbol('s'), c: 1 })).toEqual({ c: 1 });
  });

  it('omits NaN and the infinities, which encode as null anyway', () => {
    expect(sensitiveAttributes({ a: Number.NaN, b: Number.POSITIVE_INFINITY, c: 1 })).toEqual({
      c: 1,
    });
  });

  it('renders a bigint in decimal rather than throwing on it', () => {
    expect(sensitiveAttributes({ big: 10n })).toEqual({ big: '10' });
  });

  it('encodes a nested structure the agent would have dropped whole', () => {
    const out = sensitiveAttributes({ ctx: { plan: 'pro', seats: 4 } });

    expect(out['ctx']).toBe('{"plan":"pro","seats":4}');
  });

  it('scrubs inside that structure before encoding it', () => {
    const canary = createCanary();
    const secret = new SensitiveString(canary, 'credential');

    const out = sensitiveAttributes({ ctx: { token: secret, password: canary, plan: 'pro' } });

    expect(out['ctx']).not.toContain(canary);
    expect(out['ctx']).toContain('[REDACTED:credential]');
    expect(out['ctx']).toContain('[SCRUBBED]');
  });

  it('omits a cycle rather than replacing it with a censor that would lie', () => {
    const cyclic: Record<string, unknown> = { plan: 'pro' };
    cyclic['self'] = cyclic;

    expect(sensitiveAttributes({ ctx: cyclic, c: 1 })).toEqual({ c: 1 });
  });

  it('omits a value whose own toJSON throws', () => {
    const hostile = {
      toJSON() {
        throw new Error('no');
      },
    };

    expect(sensitiveAttributes({ ctx: hostile, c: 1 })).toEqual({ c: 1 });
  });
});

describe('policy handling', () => {
  it('takes a caller denylist', () => {
    const canary = createCanary();

    expect(sensitiveAttributes({ 'x-thing': canary }, { denyKeys: ['x-thing'] })).toEqual({
      'x-thing': '[SCRUBBED]',
    });
  });

  it('reuses a policy object rather than resolving it per call', () => {
    // Reuse goes by object identity, the same rule core's classification memo
    // follows. Two equal policy objects resolve separately; the same object
    // resolves once.
    const policy = { denyKeys: ['x-thing'] };
    const first = sensitiveAttributes({ 'x-thing': 'a' }, policy);
    const second = sensitiveAttributes({ 'x-thing': 'b' }, policy);

    expect(first).toEqual(second);
  });

  it('reports once per call', () => {
    const onScrub = vi.fn();
    const secret = new SensitiveString(createCanary(), 'credential');

    sensitiveAttributes({ token: secret, password: 'raw' }, { onScrub });

    expect(onScrub).toHaveBeenCalledTimes(1);

    const report = onScrub.mock.calls[0]?.[0] as {
      instances: number;
      deniedKeys: readonly string[];
    };

    expect(report.instances).toBe(1);
    expect(report.deniedKeys).toContain('password');
  });

  it('survives an onScrub that throws', () => {
    expect(() =>
      sensitiveAttributes(
        { a: 1 },
        {
          onScrub: () => {
            throw new Error('metrics are down');
          },
        }
      )
    ).not.toThrow();
  });
});
