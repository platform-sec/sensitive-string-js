import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  SensitiveString,
  getPolicy,
  registerPolicy,
  resetPolicies,
  withRevealContext,
} from '../index.js';
import type { SensitiveStringOptions } from '../index.js';

describe('Phase 0 cross-cutting rules', () => {
  beforeEach(() => {
    resetPolicies();
  });

  it('defines conservative partial-query and masking defaults', () => {
    expect(getPolicy('sensitive')).toMatchObject({
      allowPartialQueries: true,
      allowMask: true,
    });
    expect(getPolicy('credential')).toMatchObject({
      allowPartialQueries: false,
      allowMask: false,
    });
  });

  it('accepts the shared options object in all direct construction helpers', () => {
    const options: SensitiveStringOptions = {};

    expect(new SensitiveString('value', 'sensitive', 'label', options).reveal()).toBe('value');
    expect(SensitiveString.fromOptional('value', 'credential', 'label', options)?.reveal()).toBe(
      'value'
    );
  });

  it('shares the policy registry across separate module evaluations', async () => {
    const replacement = {
      name: 'sensitive' as const,
      redact: () => '[SHARED]',
      allowPartialQueries: false,
      allowMask: false,
    };
    registerPolicy(replacement, { overwrite: true });

    vi.resetModules();
    const reloadedPolicyModule = await import('../policy.js');

    expect(reloadedPolicyModule.getPolicy('sensitive')).toBe(replacement);
  });

  it('shares reveal context across separate module evaluations', async () => {
    vi.resetModules();
    const reloadedContextModule = await import('../context.js');
    const ctx = { name: 'shared-context' };

    withRevealContext(ctx, () => {
      expect(reloadedContextModule.getCurrentRevealContext()).toBe(ctx);
    });
  });
});
