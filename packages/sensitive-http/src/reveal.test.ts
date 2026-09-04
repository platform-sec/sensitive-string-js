import { describe, expect, it, vi } from 'vitest';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import type { RevealContext } from '@platform-sec/sensitive-string-core';

import { UnserializableBodyError } from './errors.js';
import { revealOutgoing } from './reveal.js';
import { PlanBuilder } from './scrub.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';
const ctx: RevealContext = { name: 'test' };

function walk(value: unknown): { out: unknown; builder: PlanBuilder } {
  const builder = new PlanBuilder();

  return { out: revealOutgoing(value, ctx, builder.section('body')), builder };
}

describe('revealOutgoing', () => {
  it('reveals an instance and records its path', () => {
    const { out, builder } = walk({ card: { number: new SensitiveString(CANARY, 'credential') } });

    expect(out).toEqual({ card: { number: CANARY } });
    expect(builder.build().bodyPaths).toEqual(['card.number']);
  });

  it('records an array index in the path syntax the scrub reads back', () => {
    const { builder } = walk({ tokens: [new SensitiveString(CANARY, 'credential')] });

    expect(builder.build().bodyPaths).toEqual(['tokens[0]']);
  });

  it('does not mutate the caller structure', () => {
    const secret = new SensitiveString(CANARY, 'credential');
    const body = { card: { number: secret } };

    walk(body);

    expect(body.card.number).toBe(secret);
  });

  it('descends into a class instance, which the sketch in INTEGRATION_IDEAS would have shipped', () => {
    class ChargeDto {
      constructor(
        readonly amount: number,
        readonly token: SensitiveString<'credential'>
      ) {}
    }

    const { out } = walk(new ChargeDto(100, new SensitiveString(CANARY, 'credential')));

    expect(out).toEqual({ amount: 100, token: CANARY });
    expect(JSON.stringify(out)).not.toContain('[REDACTED:');
  });

  it('refuses a Map rather than letting a client turn it into {}', () => {
    expect(() => walk({ m: new Map([['token', CANARY]]) })).toThrow(UnserializableBodyError);
    expect(() => walk({ m: new Map() })).toThrow(/body path 'm' is a Map/);
  });

  it('refuses a Set, a WeakMap, a Promise and a function value', () => {
    expect(() => walk({ s: new Set([1]) })).toThrow(/is a Set/);
    expect(() => walk({ w: new WeakMap() })).toThrow(/is a WeakMap/);
    expect(() => walk({ p: Promise.resolve(1) })).toThrow(/is a Promise/);
    expect(() => walk({ f: () => 1 })).toThrow(/is a Function/);
  });

  it('passes a Date through instead of destroying it', () => {
    const when = new Date('2026-09-04T00:00:00.000Z');
    const { out } = walk({ when });

    expect((out as { when: Date }).when).toBe(when);
    expect(JSON.stringify(out)).toBe('{"when":"2026-09-04T00:00:00.000Z"}');
  });

  it('passes Buffer, URL, URLSearchParams and a Readable through', async () => {
    const { Readable } = await import('node:stream');
    const parts = {
      buffer: Buffer.from('bytes'),
      url: new URL('https://api.example.com/x'),
      params: new URLSearchParams({ a: '1' }),
      stream: Readable.from(['chunk']),
    };

    const { out } = walk(parts) as { out: typeof parts };

    expect(out.buffer).toBe(parts.buffer);
    expect(out.url).toBe(parts.url);
    expect(out.params).toBe(parts.params);
    expect(out.stream).toBe(parts.stream);
  });

  it('resolves a cycle to the partially built copy rather than overflowing', () => {
    const body: Record<string, unknown> = { token: new SensitiveString(CANARY, 'credential') };
    body['self'] = body;

    const { out } = walk(body) as { out: Record<string, unknown> };

    expect(out['token']).toBe(CANARY);
    expect(out['self']).toBe(out);
  });

  it('walks a shared reference once and returns the same copy', () => {
    const shared = { token: new SensitiveString(CANARY, 'credential') };
    const { out } = walk({ a: shared, b: shared }) as { out: Record<string, unknown> };

    expect(out['a']).toBe(out['b']);
  });

  it('does not visit a prototype getter, matching redactInStructure', () => {
    const getter = vi.fn(() => new SensitiveString(CANARY, 'credential'));

    class WithProtoGetter {
      readonly plain = 'visible';

      get token(): SensitiveString<'credential'> {
        return getter();
      }
    }

    const { out, builder } = walk(new WithProtoGetter());

    expect(out).toEqual({ plain: 'visible' });
    expect(builder.build().bodyPaths).toEqual([]);
    expect(getter).not.toHaveBeenCalled();
  });

  it('treats an own getter that throws as absence rather than failing the request', () => {
    const body = { safe: 'here' };

    Object.defineProperty(body, 'relation', {
      enumerable: true,
      get() {
        throw new Error('relation not loaded');
      },
    });

    expect(walk(body).out).toEqual({ safe: 'here' });
  });

  it('audits once per revealed value, under the context it was given', () => {
    const auditReveal = vi.fn();
    const builder = new PlanBuilder();

    revealOutgoing(
      {
        a: new SensitiveString(CANARY, 'credential'),
        b: new SensitiveString('other', 'sensitive'),
      },
      { name: 'attempt', auditReveal },
      builder.section('body')
    );

    expect(auditReveal).toHaveBeenCalledTimes(2);

    // The sink receives the instance, never a raw value, so an audit log that
    // stringifies its argument records the marker.
    for (const [value] of auditReveal.mock.calls) {
      expect(String(value)).not.toContain(CANARY);
    }
  });

  it('passes a serialize() result through untouched, because it is the sanctioned wire format', () => {
    const wire = new SensitiveString(CANARY, 'credential').serialize();
    const { out, builder } = walk({ forwarded: wire });

    expect(out).toEqual({ forwarded: { ...wire } });
    expect(builder.build().entries).toEqual([]);
  });
});
