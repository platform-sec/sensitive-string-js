import { describe, expect, it, vi } from 'vitest';
import { withRevealContext } from '@platform-sec/sensitive-string-core';

import { buildAttemptContext } from './context.js';
import type { RequestDescriptor } from './types.js';

const request: RequestDescriptor = {
  method: 'POST',
  url: 'https://api.example.com/charges',
  host: 'api.example.com',
  attempt: 1,
  hop: 1,
};

describe('buildAttemptContext', () => {
  it('names the call and tags the sink, the host, the client and the attempt', () => {
    const ctx = buildAttemptContext(request, 'axios', undefined, undefined);

    expect(ctx.name).toBe('POST https://api.example.com/charges');
    expect(ctx.tags).toMatchObject({
      sink: 'http',
      host: 'api.example.com',
      client: 'axios',
      attempt: 1,
      hop: 1,
    });
  });

  it('inherits the ambient context and its audit sink', () => {
    const auditReveal = vi.fn();

    withRevealContext(
      { name: 'request-handler', reason: 'checkout', auditReveal, tags: { requestId: 'r1' } },
      () => {
        const ctx = buildAttemptContext(request, 'got', undefined, undefined);

        expect(ctx.reason).toBe('checkout');
        // The assertion is about the reference being carried forward, which is
        // what makes an ambient audit sink reach an outbound call at all.
        // eslint-disable-next-line @typescript-eslint/unbound-method
        expect(ctx.auditReveal).toBe(auditReveal);
        expect(ctx.tags).toMatchObject({ requestId: 'r1', sink: 'http', host: 'api.example.com' });
      }
    );
  });

  it('does not overwrite an inherited reason with undefined', () => {
    withRevealContext({ name: 'handler', reason: 'checkout' }, () => {
      const ctx = buildAttemptContext(request, 'ky', { name: 'outbound' }, undefined);

      // `createChildContext` merges by spread, so a `reason` key present with
      // the value `undefined` would have replaced 'checkout' with undefined.
      expect(ctx.reason).toBe('checkout');
      expect(ctx.name).toBe('outbound');
    });
  });

  it('takes a factory and tells it what request it is naming', () => {
    const factory = vi.fn(() => ({ name: 'charge', reason: 'billing sync' }));
    const ctx = buildAttemptContext(
      { ...request, attempt: 3, hop: 2 },
      'fetch',
      factory,
      undefined
    );

    expect(factory).toHaveBeenCalledWith({ ...request, attempt: 3, hop: 2 });
    expect(ctx.name).toBe('charge');
    expect(ctx.reason).toBe('billing sync');
    expect(ctx.tags).toMatchObject({ attempt: 3, hop: 2 });
  });

  it('lets the reason shorthand through when no context object supplies one', () => {
    expect(buildAttemptContext(request, 'undici', undefined, 'rotation').reason).toBe('rotation');
  });

  it('invents no parent when there is no ambient context', () => {
    const ctx = buildAttemptContext(request, 'axios', undefined, undefined);

    // The assertion is about the reference being carried forward, which is
    // what makes an ambient audit sink reach an outbound call at all.
    // eslint-disable-next-line @typescript-eslint/unbound-method
    expect(ctx.auditReveal).toBeUndefined();
  });
});
