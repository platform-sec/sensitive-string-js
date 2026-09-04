import * as http from 'node:http';
import * as Sentry from '@sentry/node';
import type { NodeOptions } from '@sentry/node';
import { createCanary, expectNoCanary } from '@platform-sec/sensitive-string-scrub/testing';
import { describe, expect, it, vi } from 'vitest';

import { withSensitiveScrubbing } from '../install.js';
import { SENTRY_URL_KEYS } from '../paths.js';
import { SCRUB_FAILED_TAG, type SentrySpan, buildSpanStub, dropPayload } from '../stub.js';
import { createCapture, runIsolated } from './fixtures.js';

/**
 * The tracing seams, which the event-shaped sweep does not reach.
 *
 * A span is built by the SDK's own instrumentation rather than by anything the
 * application wrote, so a fixture that assembles an event by hand never sees
 * what an HTTP span actually carries. Driving a real request is what found the
 * leak these tests now guard: one `http.get` put the query token into
 * `url.full`, `http.url`, `http.target`, `http.query` and `url.query`, and an
 * earlier version of the URL key list carried only the second of those.
 */

/** Run one real outbound request under tracing and return every envelope. */
async function traceRequest(
  canary: string,
  options: Parameters<typeof withSensitiveScrubbing>[0] = {},
  policy: Parameters<typeof withSensitiveScrubbing>[1] = {}
): Promise<unknown[]> {
  const { capture, transport } = createCapture();
  const server = http.createServer((_req, res) => res.end('ok'));

  await new Promise<void>((resolve) => server.listen(0, resolve));

  const address = server.address();
  const port = typeof address === 'object' && address !== null ? address.port : 0;

  try {
    await runIsolated(
      withSensitiveScrubbing(
        {
          transport,
          tracesSampleRate: 1,
          // The one default integration these cases need. Enabling all of
          // them would patch `http` for every other case in the process.
          integrations: [Sentry.httpIntegration()] as never,
          ...options,
        },
        policy
      ),
      async () => {
        await Sentry.startSpan({ name: 'root' }, async () => {
          await new Promise<void>((resolve) => {
            http.get(`http://127.0.0.1:${port}/pay?token=${canary}&page=2`, (res) => {
              res.resume();
              res.on('end', resolve);
            });
          });
        });
      }
    );
  } finally {
    server.close();
  }

  return capture.envelopes;
}

describe('span URL attributes', () => {
  // TEST-SENTRY-SPAN-URL
  it('does not send a query token from any span attribute', async () => {
    const canary = createCanary('spanurl');
    const envelopes = await traceRequest(canary);

    expect(envelopes.length).toBeGreaterThan(0);
    expectNoCanary(envelopes, canary, 'tracing envelope');
    expectNoCanary(JSON.stringify(envelopes), canary, 'serialized tracing envelope');
  });

  it('leaks that token without the scrubbing, so this position proves something', async () => {
    const canary = createCanary('spanbare');
    const { capture, transport } = createCapture();
    const server = http.createServer((_req, res) => res.end('ok'));

    await new Promise<void>((resolve) => server.listen(0, resolve));

    const address = server.address();
    const port = typeof address === 'object' && address !== null ? address.port : 0;

    try {
      await runIsolated(
        { transport, tracesSampleRate: 1, integrations: [Sentry.httpIntegration()] as never },
        async () => {
          await Sentry.startSpan({ name: 'root' }, async () => {
            await new Promise<void>((resolve) => {
              http.get(`http://127.0.0.1:${port}/pay?token=${canary}&page=2`, (res) => {
                res.resume();
                res.on('end', resolve);
              });
            });
          });
        }
      );
    } finally {
      server.close();
    }

    expect(JSON.stringify(capture.envelopes)).toContain(canary);
  });

  it('keeps the route and the parameters that were not denied', async () => {
    const canary = createCanary('spankeep');
    const serialized = JSON.stringify(await traceRequest(canary));

    expect(serialized).toContain('/pay');
    expect(serialized).toContain('page=2');
  });
});

describe('pinning: which span attributes carry a URL', () => {
  // TEST-SENTRY-PIN-SPANATTRS
  it('names the attributes the SDK puts a query string into', async () => {
    // The canary tests above fail if the SDK starts using an attribute this
    // package does not cover. This one says which attribute, so the failure is
    // diagnosable instead of just red. Measured on @sentry/node 10.73.0.
    const canary = createCanary('spanattrs');
    const { capture, transport } = createCapture();
    const server = http.createServer((_req, res) => res.end('ok'));

    await new Promise<void>((resolve) => server.listen(0, resolve));

    const address = server.address();
    const port = typeof address === 'object' && address !== null ? address.port : 0;

    try {
      await runIsolated(
        { transport, tracesSampleRate: 1, integrations: [Sentry.httpIntegration()] as never },
        async () => {
          await Sentry.startSpan({ name: 'root' }, async () => {
            await new Promise<void>((resolve) => {
              http.get(`http://127.0.0.1:${port}/pay?token=${canary}&page=2`, (res) => {
                res.resume();
                res.on('end', resolve);
              });
            });
          });
        }
      );
    } finally {
      server.close();
    }

    const carrying = new Set<string>();

    for (const match of JSON.stringify(capture.envelopes).matchAll(
      new RegExp(`"([a-z._]+)":"[^"]*${canary}[^"]*"`, 'g')
    )) {
      if (match[1] !== undefined) {
        carrying.add(match[1]);
      }
    }

    expect([...carrying].sort()).toEqual(
      ['http.query', 'http.target', 'http.url', 'url.full', 'url.query'].sort()
    );

    // Everything the SDK emits must be in the list this package scrubs.
    for (const attribute of carrying) {
      expect(
        SENTRY_URL_KEYS,
        `the SDK puts a URL in '${attribute}' and we do not cover it`
      ).toContain(attribute);
    }
  });
});

describe('beforeSendSpan never answers null', () => {
  // TEST-SENTRY-SPAN-NONULL
  it('sends the scrubbed span when a caller hook asks to drop one', async () => {
    // Measured on @sentry/node 10.73.0: returning null from beforeSendSpan is
    // disallowed, and the SDK's response is to push the ORIGINAL, unscrubbed
    // span into the envelope. A caller's drop must not become a raw send.
    //
    // The SDK's own type says the return is a span, so reaching this needs a
    // cast. That is not a reason to skip it: an application on plain
    // JavaScript, or one following the SDK's null-returning `beforeSend`
    // convention, writes exactly this.
    const canary = createCanary('spandrop');
    const dropSpan = (() => null) as unknown as NonNullable<NodeOptions['beforeSendSpan']>;
    const envelopes = await traceRequest(canary, { beforeSendSpan: dropSpan });

    expectNoCanary(JSON.stringify(envelopes), canary, 'envelope after a caller drop');
  });

  it('sends the scrubbed span when a caller hook throws', async () => {
    const canary = createCanary('spanthrow');
    const envelopes = await traceRequest(canary, {
      beforeSendSpan: () => {
        throw new Error('caller span hook exploded');
      },
    });

    expectNoCanary(JSON.stringify(envelopes), canary, 'envelope after a caller throw');
  });

  it('passes the scrubbed span to a caller hook', async () => {
    const canary = createCanary('spanseen');
    const seen: SentrySpan[] = [];

    await traceRequest(canary, {
      beforeSendSpan: (span) => {
        seen.push(span);
        return span;
      },
    });

    expect(seen.length).toBeGreaterThan(0);
    expectNoCanary(seen, canary, 'span handed to the caller hook');
  });
});

describe('span streaming', () => {
  // TEST-SENTRY-SPAN-STREAMED
  it('marks its own hook so installing it does not disable streaming', () => {
    // spanStreamingIntegration resets traceLifecycle to 'static' when it finds
    // a beforeSendSpan the SDK did not mark. This package installs one
    // unconditionally, so without the marker it turns streaming off for every
    // caller who opted in.
    const wrapped = withSensitiveScrubbing({});
    const hook = wrapped.beforeSendSpan as (typeof wrapped)['beforeSendSpan'] & {
      _streamed?: true;
    };

    expect(hook?._streamed).toBe(true);
    expect(Object.keys(hook as object)).not.toContain('_streamed');
  });

  it('carries a caller"s marker through', () => {
    const userHook = Sentry.withStreamedSpan((span) => span);
    const wrapped = withSensitiveScrubbing({ beforeSendSpan: userHook });
    const hook = wrapped.beforeSendSpan as { _streamed?: true };

    expect(hook._streamed).toBe(true);
  });

  it('does not mark a caller"s unmarked hook, leaving the SDK"s own warning to fire', () => {
    // The fallback and its warning are aimed at the caller. Suppressing them
    // would silently run their stream-unaware callback under streaming.
    const wrapped = withSensitiveScrubbing({ beforeSendSpan: (span) => span });
    const hook = wrapped.beforeSendSpan as { _streamed?: true };

    expect(hook._streamed).toBeUndefined();
  });
});

describe('the failure behaviour of each payload kind', () => {
  /**
   * A span the walk cannot finish, because writing the copy fails.
   *
   * A write, deliberately, and not a read. `core`'s walks now degrade rather
   * than throw for every hook an object controls on the way in, the throwing
   * enumerable getter this used to use included. `redactCopy` keeps each
   * object's prototype and then assigns onto the new object, so a prototype
   * whose setter refuses fails on the way out, which no read-guarding can
   * absorb.
   */
  function unwalkableSpan(canary: string): SentrySpan {
    const prototype = {};

    Object.defineProperty(prototype, 'url.full', {
      set(): never {
        throw new Error('write refused');
      },
      get(): undefined {
        return undefined;
      },
      configurable: true,
    });

    const data = Object.create(prototype) as Record<string, unknown>;

    Object.defineProperty(data, 'url.full', {
      value: `https://pay.example/checkout?token=${canary}`,
      enumerable: true,
      writable: true,
      configurable: true,
    });

    return {
      span_id: 'aaaaaaaaaaaaaaaa',
      trace_id: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      parent_span_id: 'cccccccccccccccc',
      start_timestamp: 1,
      timestamp: 2,
      op: 'http.client',
      description: `GET /pay?token=${canary}`,
      data,
    } as SentrySpan;
  }

  // TEST-SENTRY-SPAN-STUB
  it('replaces a span it could not scrub, keeping its place in the trace', () => {
    const canary = createCanary('spanstub');
    const hook = withSensitiveScrubbing({}).beforeSendSpan;
    const result = hook?.(unwalkableSpan(canary));

    // Never null: the SDK answers a null here by sending the original span.
    expect(result).not.toBeNull();
    expect(result).toBeDefined();
    expect(result?.span_id).toBe('aaaaaaaaaaaaaaaa');
    expect(result?.trace_id).toBe('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');
    expect(result?.op).toBe('http.client');
    expect(result?.data).toEqual({ [SCRUB_FAILED_TAG]: true });
    expectNoCanary(result, canary, 'span stub');
  });

  it('reports the failure so a scrubber broken on spans is visible', () => {
    const canary = createCanary('spanreport');
    const onScrub = vi.fn();
    const hook = withSensitiveScrubbing({}, { onScrub }).beforeSendSpan;

    hook?.(unwalkableSpan(canary));

    const reports = onScrub.mock.calls.map((call) => call[0] as { failed: boolean; kind: string });

    expect(reports.some((report) => report.failed && report.kind === 'span')).toBe(true);
    expectNoCanary(onScrub.mock.calls, canary, 'onScrub arguments');
  });

  it('builds a span stub that keeps the ids and drops the content', () => {
    const canary = createCanary('stubshape');

    const stub = buildSpanStub({
      span_id: 'aaaa',
      trace_id: 'bbbb',
      parent_span_id: 'cccc',
      start_timestamp: 1,
      timestamp: 2,
      op: 'http.client',
      status: 'ok',
      description: `GET /pay?token=${canary}`,
      data: { 'url.full': `http://x/pay?token=${canary}` },
    });

    expect(stub.span_id).toBe('aaaa');
    expect(stub.trace_id).toBe('bbbb');
    expect(stub.parent_span_id).toBe('cccc');
    expect(stub.op).toBe('http.client');
    expect(stub.data).toEqual({ [SCRUB_FAILED_TAG]: true });
    expectNoCanary(stub, canary, 'span stub');
  });

  it('survives a span whose every field refuses to be read', () => {
    const hostile = new Proxy({} as SentrySpan, {
      get() {
        throw new Error('nope');
      },
    });

    expect(() => buildSpanStub(hostile)).not.toThrow();
  });

  it('drops a log, a metric and a transaction rather than sending a malformed one', () => {
    // A stub for these would have to be a valid payload of its own shape, and
    // an event-shaped one is not: measured, a log needs a body, a metric a
    // name, and a transaction a trace context. All three accept null.
    expect(dropPayload()).toBeNull();
  });
});
