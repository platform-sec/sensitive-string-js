import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { describe, expect, it } from 'vitest';
import { resolveScrubPolicy } from '../policy.js';
import { createCanary, expectCanaryPresent, expectNoCanary, findCanary } from '../testing.js';
import { scrubPayload } from '../walk.js';
import type { PayloadKind } from '../types.js';

const KINDS: readonly PayloadKind[] = [
  'event',
  'breadcrumb',
  'transaction',
  'span',
  'log',
  'metric',
  'session',
];

const policy = resolveScrubPolicy({ urlKeys: ['request.url', 'request.query_string', 'url'] });

/**
 * One position a canary can occupy in a captured payload.
 *
 * Two flags, because a sweep that only asserts absence would keep passing if
 * the scrubber were deleted and the fixture were wrong:
 *
 * - `proof` says how the fixture proves it really held the canary. A raw
 *   string is structurally visible before scrubbing. A wrapped one is not, and
 *   cannot be: the value lives in an ES2022 private field that no structural
 *   search reaches, which is the property the library exists for. Those prove
 *   themselves by the marker they leave behind instead.
 * - `serializable` is false for a genuine cycle. `redactCopy` produces a
 *   cyclic copy that fails at `JSON.stringify` exactly as the original would,
 *   so the envelope check does not apply to it.
 */
interface Position {
  readonly name: string;
  readonly build: () => unknown;
  readonly proof: 'raw' | 'wrapped';
  readonly serializable?: false;
}

function positions(canary: string): readonly Position[] {
  return [
    {
      name: 'header, at any depth',
      proof: 'raw',
      build: () => ({ request: { headers: { authorization: `Bearer ${canary}` } } }),
    },
    {
      name: 'cookie header',
      proof: 'raw',
      build: () => ({ request: { headers: { cookie: `session=${canary}` } } }),
    },
    {
      name: 'parsed cookies, denied by path',
      proof: 'raw',
      build: () => ({ request: { cookies: { session: canary } } }),
    },
    {
      name: 'url query parameter',
      proof: 'raw',
      build: () => ({ request: { url: `https://api.test/pay?token=${canary}` } }),
    },
    {
      name: 'bare query string',
      proof: 'raw',
      build: () => ({ request: { query_string: `token=${canary}&page=2` } }),
    },
    {
      name: 'url userinfo password',
      proof: 'raw',
      build: () => ({ request: { url: `https://u:${canary}@api.test/pay` } }),
    },
    {
      name: 'body field',
      proof: 'raw',
      build: () => ({ request: { data: { client_secret: canary } } }),
    },
    {
      name: 'wrapped value',
      proof: 'wrapped',
      build: () => ({ extra: { s: new SensitiveString(canary, 'credential') } }),
    },
    {
      name: 'wrapped value in an array',
      proof: 'wrapped',
      build: () => ({ extra: { list: [new SensitiveString(canary, 'sensitive')] } }),
    },
    {
      name: 'wrapped value behind a class instance',
      proof: 'wrapped',
      build: () => ({
        contexts: {
          user: Object.assign(Object.create({ kind: 'user' }) as object, {
            credential: new SensitiveString(canary, 'credential'),
          }),
        },
      }),
    },
    {
      name: 'serialize() result',
      proof: 'raw',
      build: () => ({ extra: { t: new SensitiveString(canary, 'credential').serialize() } }),
    },
    {
      name: 'serialize() result in a request body',
      proof: 'raw',
      build: () => ({
        request: { data: { payload: new SensitiveString(canary, 'credential').serialize() } },
      }),
    },
    {
      name: 'nested stack frame variable',
      proof: 'raw',
      build: () => ({
        exception: {
          values: [{ stacktrace: { frames: [{ vars: { opts: { refresh_token: canary } } }] } }],
        },
      }),
    },
    {
      name: 'breadcrumb data',
      proof: 'raw',
      build: () => ({ breadcrumbs: [{ data: { access_token: canary } }] }),
    },
    {
      name: 'deeply nested denied key',
      proof: 'raw',
      build: () => ({ a: { b: { c: { d: { e: { passwd: canary } } } } } }),
    },
    {
      name: 'denied key holding an object',
      proof: 'raw',
      build: () => ({ extra: { secret: { inner: canary } } }),
    },
    {
      name: 'denied key holding an array',
      proof: 'raw',
      build: () => ({ extra: { credentials: [canary, canary] } }),
    },
    {
      name: 'shared reference held twice',
      proof: 'raw',
      build: () => {
        const shared = { private_key: canary };
        return { extra: { a: shared, b: shared } };
      },
    },
    {
      name: 'value inside a cycle',
      proof: 'raw',
      serializable: false,
      build: () => {
        const node: Record<string, unknown> = { api_key: canary };
        node['self'] = node;
        return { extra: node };
      },
    },
  ];
}

describe('canary sweep', () => {
  for (const kind of KINDS) {
    describe(`payload kind: ${kind}`, () => {
      const canary = createCanary(kind);

      for (const position of positions(canary)) {
        // TEST-SCRUB-CANARY
        it(`does not emit the canary from ${position.name}`, () => {
          const payload = position.build();

          if (position.proof === 'raw') {
            // The sweep proves nothing about a position the fixture never held.
            expectCanaryPresent(payload, canary, `${kind} input at ${position.name}`);
          }

          const { payload: scrubbed, report } = scrubPayload(payload, policy, kind);

          if (position.proof === 'wrapped') {
            // A wrapped canary is unreachable by any structural search even
            // before scrubbing, so presence is proved by the instance count.
            expect(report.instances).toBeGreaterThan(0);
          }

          expectNoCanary(scrubbed, canary, `${kind} payload at ${position.name}`);

          if (position.serializable !== false) {
            expectNoCanary(
              JSON.stringify(scrubbed),
              canary,
              `${kind} envelope at ${position.name}`
            );
          }
        });
      }
    });
  }
});

describe('the report carries no value', () => {
  // TEST-SCRUB-CANARY-REPORT
  it('keeps the canary out of the report, the classes, the labels and the keys', () => {
    const canary = createCanary('report');
    const payload = {
      request: { headers: { authorization: `Bearer ${canary}` } },
      extra: { s: new SensitiveString(canary, 'credential', 'stripe_key') },
      captured: { body: '[REDACTED:credential]' },
    };

    const { report } = scrubPayload(payload, resolveScrubPolicy({ reportLabels: true }), 'event');

    expect(report.instances).toBe(1);
    expect(report.deniedKeys).toEqual(['authorization']);
    expect(report.markersSeen).toBe(1);
    expectNoCanary(report, canary, 'report');
    expectNoCanary(
      [...report.classes, ...(report.labels ?? []), ...report.deniedKeys],
      canary,
      'report lists'
    );
  });
});

describe('the harness itself', () => {
  it('finds a canary through a Buffer, which is what a transport sees', () => {
    const canary = createCanary('bytes');

    expect(findCanary({ body: Buffer.from(`x${canary}y`) }, canary)).toHaveLength(1);
  });

  it('finds a canary in a Map and a Set', () => {
    const canary = createCanary('collections');

    expect(findCanary(new Map([['k', canary]]), canary)).toHaveLength(1);
    expect(findCanary(new Set([canary]), canary)).toHaveLength(1);
  });

  it('finds a canary in an error message', () => {
    const canary = createCanary('error');

    expect(findCanary(new Error(`failed for ${canary}`), canary).length).toBeGreaterThan(0);
  });

  it('does not reprint the canary in the failure it raises', () => {
    const canary = createCanary('elide');

    expect(() => expectNoCanary({ a: canary }, canary)).toThrow(/<CANARY>/);
    expect(() => expectNoCanary({ a: canary }, canary)).not.toThrow(new RegExp(canary));
  });

  it('survives a getter that throws', () => {
    const hostile = {};
    Object.defineProperty(hostile, 'boom', {
      enumerable: true,
      get() {
        throw new Error('nope');
      },
    });

    expect(() => findCanary(hostile, 'x')).not.toThrow();
  });

  it('makes a unique canary per call', () => {
    expect(createCanary('u')).not.toBe(createCanary('u'));
  });

  it('refuses a position the payload never held', () => {
    expect(() => expectCanaryPresent({ a: 1 }, 'ABSENT')).toThrow(/proves nothing/);
  });
});
