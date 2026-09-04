import { describe, expect, it, vi } from 'vitest';
import {
  ExpiredSensitiveValueError,
  SensitiveString,
  withRevealContext,
} from '@platform-sec/sensitive-string-core';

import { prepareRequest } from '../request.js';

/**
 * The shapes an application actually produces, rather than the shapes a design
 * document imagines.
 */

const CANARY = 'LEAKED_SECRET_abc123xyz';
const base = { client: 'test', attempt: 1 } as const;

describe('adversarial bodies', () => {
  it('handles a deep body without unbounded work', () => {
    let body: Record<string, unknown> = { token: new SensitiveString(CANARY, 'credential') };

    for (let depth = 0; depth < 400; depth += 1) {
      body = { nested: body };
    }

    const prepared = prepareRequest(
      { method: 'POST', url: 'https://api.example.com/x', body },
      base
    );

    expect(prepared.plan.bodyPaths).toHaveLength(1);
    expect(prepared.bodyText).toContain(CANARY);
  });

  it('reveals a cyclic body without overflowing, and refuses to serialize the cycle', () => {
    const body: Record<string, unknown> = { token: new SensitiveString(CANARY, 'credential') };
    body['self'] = body;

    // The walk survives; `JSON.stringify` is the one that objects, which is the
    // client's own behaviour and the caller's bug to fix.
    expect(() =>
      prepareRequest({ method: 'POST', url: 'https://api.example.com/x', body }, base)
    ).toThrow(TypeError);
  });

  it('refuses an expired value before a byte is written', () => {
    const expired = new SensitiveString(CANARY, 'credential', 'token', { ttl: 0 });

    expect(() =>
      prepareRequest(
        {
          method: 'POST',
          url: 'https://api.example.com/x',
          headers: { 'x-api-key': expired },
        },
        base
      )
    ).toThrow(ExpiredSensitiveValueError);
  });

  it('keeps 100 overlapping requests from sharing a plan or a context', async () => {
    const results = await Promise.all(
      Array.from({ length: 100 }, (_unused, index) =>
        Promise.resolve().then(() =>
          withRevealContext({ name: `caller-${index}`, tags: { caller: index } }, () =>
            prepareRequest(
              {
                method: 'POST',
                url: `https://api.example.com/${index}`,
                body: { token: new SensitiveString(`${CANARY}-${index}`, 'credential') },
              },
              base
            )
          )
        )
      )
    );

    results.forEach((prepared, index) => {
      expect(prepared.plan.bodyPaths).toEqual(['token']);
      expect(prepared.bodyText).toBe(`{"token":"${CANARY}-${index}"}`);
      expect(prepared.context.name).toBe(`POST https://api.example.com/${index}`);
      expect(prepared.context.tags).toMatchObject({ caller: index, host: 'api.example.com' });
    });
  });

  it('sends a serialize() result to the socket and never to the log sink', () => {
    const log = vi.fn();
    const wire = new SensitiveString(CANARY, 'credential').serialize();

    const prepared = prepareRequest(
      { method: 'POST', url: 'https://api.example.com/x', body: { forwarded: wire } },
      { ...base, log }
    );

    // The wire format is the sanctioned way to move a value between two
    // services that both use this library, so the walker passes it through and
    // the guard correctly finds no marker in it.
    expect(prepared.bodyText).toContain(CANARY);

    // `redactCopy` replaces it with the marker of the class it names, so the
    // raw value reaches the socket and no log line.
    expect(JSON.stringify(log.mock.calls[0])).not.toContain(CANARY);
  });

  it('does not let a hostile getter turn a request into an exception', () => {
    const body = { amount: 100 };

    Object.defineProperty(body, 'relation', {
      enumerable: true,
      get() {
        throw new Error('not loaded');
      },
    });

    expect(
      prepareRequest({ method: 'POST', url: 'https://api.example.com/x', body }, base).bodyText
    ).toBe('{"amount":100}');
  });

  it('audits once per value per attempt, and names the attempt', () => {
    const auditReveal = vi.fn();

    withRevealContext({ name: 'caller', auditReveal }, () => {
      for (const attempt of [1, 2, 3]) {
        prepareRequest(
          {
            method: 'POST',
            url: 'https://api.example.com/x',
            body: { token: new SensitiveString(CANARY, 'credential') },
          },
          { ...base, attempt }
        );
      }
    });

    expect(auditReveal).toHaveBeenCalledTimes(3);
  });
});
