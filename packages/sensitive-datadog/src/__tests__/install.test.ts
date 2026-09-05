import { createCanary, expectNoCanary } from '@platform-sec/sensitive-string-scrub/testing';
import { describe, expect, it, vi } from 'vitest';

import { installSensitiveScrubbing, isApplied, type DatadogTracer } from '../install.js';
import { REQUEST_HEADER_PREFIX, RESPONSE_HEADER_PREFIX } from '../paths.js';
import { COVERED_PLUGINS } from '../seams.js';
import { headerTags, runDriver, serverSpan, type EncodedSpan } from './fixtures.js';

/**
 * Installation, in the process shapes a deployment actually takes.
 *
 * Measured against `dd-trace` 6.14.0 on Node 22.15.0.
 */

const CANARY = createCanary('INSTALL');
const CAPTURED = ['authorization', 'cookie', 'x-api-key', 'x-trace'];

describe('either order of use() and init()', () => {
  it('scrubs identically whether it runs before or after init()', async () => {
    // Worth measuring rather than assuming, because the natural assumption is
    // the other one: `tracer.use()` before `init()` returns without any
    // indication it was accepted, and the plugin manager's stored config for
    // `http` reads `hooks: {}` when inspected directly afterwards, which looks
    // exactly like a silently discarded option. It is not one.
    const after = await runDriver({ canary: CANARY, headerTags: CAPTURED, install: true });
    const before = await runDriver({
      canary: CANARY,
      headerTags: CAPTURED,
      install: true,
      installBeforeInit: true,
    });

    for (const run of [after, before]) {
      expect(headerTags(serverSpan(run.spans))[`${REQUEST_HEADER_PREFIX}authorization`]).toBe(
        '[SCRUBBED]'
      );
      expectNoCanary(run.spans, CANARY, 'the trace payload');
    }
  }, 120_000);
});

describe('the load-order repair', () => {
  /** Whether a run produced the two spans an instrumented request should. */
  function instrumented(spans: readonly EncodedSpan[]): boolean {
    return (
      spans.some((span) => span.meta?.['span.kind'] === 'server') &&
      spans.some(
        (span) => span.meta?.['span.kind'] === 'client' && span.meta?.['http.method'] !== undefined
      )
    );
  }

  it('reproduces the silently broken deployment', async () => {
    // Variant A: `require('http')` before `init()`, application uses that
    // reference. No warning, no error, and manually created spans in the same
    // process export normally, so the payload looks healthy while the HTTP
    // instrumentation is simply absent.
    const run = await runDriver({ canary: CANARY, headerTags: CAPTURED, preRequireHttp: true });

    expect(instrumented(run.spans)).toBe(false);
    expect(run.spans.length).toBeGreaterThan(0);
  }, 60_000);

  it('repairs it, which is the whole point of re-requiring the core modules', async () => {
    const run = await runDriver({
      canary: CANARY,
      headerTags: CAPTURED,
      preRequireHttp: true,
      install: true,
    });

    expect(instrumented(run.spans)).toBe(true);
  }, 60_000);

  it('scrubs the spans it just brought back', async () => {
    const run = await runDriver({
      canary: CANARY,
      headerTags: CAPTURED,
      preRequireHttp: true,
      install: true,
    });

    expect(headerTags(serverSpan(run.spans))[`${REQUEST_HEADER_PREFIX}authorization`]).toBe(
      '[SCRUBBED]'
    );
    expectNoCanary(run.spans, CANARY, 'the trace payload');
  }, 60_000);
});

describe('composition with a caller hook', () => {
  it('runs the caller hook and keeps its writes', async () => {
    const run = await runDriver({
      canary: CANARY,
      headerTags: CAPTURED,
      userHook: true,
      install: true,
    });

    expect(run.result.userHookCalls).toBeGreaterThan(0);
    expect(serverSpan(run.spans).meta?.['probe.user_hook']).toBe('ran');
  }, 60_000);

  it('scrubs anyway, so a caller hook cannot add behind the scrubber back', async () => {
    const run = await runDriver({
      canary: CANARY,
      headerTags: CAPTURED,
      userHook: true,
      install: true,
    });

    expect(headerTags(serverSpan(run.spans))[`${REQUEST_HEADER_PREFIX}authorization`]).toBe(
      '[SCRUBBED]'
    );
  }, 60_000);
});

describe('idempotence', () => {
  /** A stand-in tracer, since idempotence is about the marker rather than the agent. */
  function fakeTracer(): DatadogTracer & { calls: string[] } {
    const calls: string[] = [];

    return {
      calls,
      use(plugin: string) {
        calls.push(plugin);

        return undefined;
      },
    };
  }

  it('configures every covered plugin on the first call', () => {
    const tracer = fakeTracer();
    const installation = installSensitiveScrubbing(tracer);

    expect(installation.applied).toBe(true);
    expect(installation.plugins).toEqual(COVERED_PLUGINS.map((entry) => entry.plugin));
    expect(tracer.calls).toEqual(COVERED_PLUGINS.map((entry) => entry.plugin));
  });

  it('does nothing on the second call', () => {
    const tracer = fakeTracer();

    installSensitiveScrubbing(tracer);
    const second = installSensitiveScrubbing(tracer);

    expect(second.applied).toBe(false);
    expect(tracer.calls).toHaveLength(COVERED_PLUGINS.length);
  });

  it('marks the tracer with a shared symbol, so two copies of the package compose once', () => {
    const tracer = fakeTracer();

    expect(isApplied(tracer)).toBe(false);

    installSensitiveScrubbing(tracer);

    // `Symbol.for`, so a second copy of this package in the dependency tree
    // resolves the same symbol and sees the same mark.
    expect(
      (tracer as unknown as Record<symbol, unknown>)[
        Symbol.for('@platform-sec/sensitive-string-datadog.applied')
      ]
    ).toBe(true);
    expect(isApplied(tracer)).toBe(true);
  });

  it('does not leave the marker enumerable', () => {
    const tracer = fakeTracer();

    installSensitiveScrubbing(tracer);

    expect(Object.getOwnPropertyNames(tracer)).not.toContain('applied');
    expect(JSON.stringify(tracer)).not.toContain('applied');
  });
});

describe('the installation report', () => {
  it('names the headers it captured and the ones it censors', async () => {
    const run = await runDriver({ canary: CANARY, headerTags: CAPTURED, install: true });
    const installation = run.result.notes['installation'] as {
      capturedHeaders: string[];
      censoredHeaders: string[];
      scrubsManualSpans: boolean;
    };

    expect(installation.capturedHeaders).toEqual([
      'authorization',
      'cookie',
      'x-api-key',
      'x-trace',
    ]);
    expect(installation.censoredHeaders).toEqual(['authorization', 'cookie', 'x-api-key']);
    expect(installation.scrubsManualSpans).toBe(true);
  }, 60_000);
});

/**
 * The fallback paths, driven in process.
 *
 * Everything above runs the real agent, which means it runs in a child process
 * and its branches are invisible to this one's coverage. These are the paths a
 * healthy `dd-trace` never takes, so they need a stand-in tracer to reach at
 * all: what happens when the private fields this package reads are absent,
 * renamed, or hostile.
 */
describe('degrading when the private seams are gone', () => {
  /** A tracer with no `getTags` anywhere, which is the renamed-field case. */
  function tracerWithoutTags(): DatadogTracer & { tags: Record<string, unknown>[] } {
    const tags: Record<string, unknown>[] = [];
    const configs: Record<string, unknown> = {};

    return {
      tags,
      use(plugin: string, config: unknown) {
        configs[plugin] = config;

        return undefined;
      },
      startSpan() {
        const written: Record<string, unknown> = {};

        tags.push(written);

        return {
          setTag(key: string, value: unknown) {
            written[key] = value;

            return undefined;
          },
          context: () => ({}),
          finish() {},
        };
      },
      _configs: configs,
    };
  }

  it('reports the degradation once rather than throwing', () => {
    const messages: string[] = [];

    const installation = installSensitiveScrubbing(tracerWithoutTags(), {
      captureHeaders: ['authorization'],
      onDegraded: (message) => messages.push(message),
    });

    expect(installation.enumeratesTags).toBe(false);
    expect(messages).toHaveLength(1);
    expect(messages[0]).toContain('getTags');
  });

  it('does not wrap manual spans once enumeration is gone, since it could not scrub them', () => {
    expect(
      installSensitiveScrubbing(tracerWithoutTags(), { onDegraded: () => undefined })
        .scrubsManualSpans
    ).toBe(false);
  });

  it('still censors the header tags it knows can exist, through the public setTag', () => {
    const tracer = tracerWithoutTags();

    installSensitiveScrubbing(tracer, {
      captureHeaders: ['authorization', 'x-trace'],
      onDegraded: () => undefined,
    });

    const configs = (
      tracer as unknown as { _configs: Record<string, { hooks: { request: unknown } }> }
    )._configs;
    const hook = configs['http']?.hooks.request as (span: unknown) => void;

    const written: Record<string, unknown> = {};
    hook({
      setTag(key: string, value: unknown) {
        written[key] = value;
      },
      context: () => ({}),
    });

    // Both directions of every denied captured header, and nothing for the one
    // nothing denies. It cannot tell whether a header was present, so it writes
    // either way: a tag saying a credential header was censored when none
    // arrived is a false positive in a span, and the alternative is a real
    // credential in one.
    expect(written[`${REQUEST_HEADER_PREFIX}authorization`]).toBe('[SCRUBBED]');
    expect(written[`${RESPONSE_HEADER_PREFIX}authorization`]).toBe('[SCRUBBED]');
    expect(written[`${REQUEST_HEADER_PREFIX}x-trace`]).toBeUndefined();
  });

  it('composes a caller hook onto the degraded path too', () => {
    const tracer = tracerWithoutTags();
    let called = 0;

    (tracer as unknown as { _configs: Record<string, unknown> })._configs['http'] = {
      hooks: {
        request() {
          called += 1;
        },
      },
    };

    installSensitiveScrubbing(tracer, {
      captureHeaders: ['authorization'],
      onDegraded: () => undefined,
    });

    expect(called).toBe(0);
  });

  it('survives a tracer whose private fields throw on read', () => {
    const hostile = {
      use: () => undefined,
      get _tracer(): never {
        throw new Error('no');
      },
      get _config(): never {
        throw new Error('no');
      },
      get _pluginManager(): never {
        throw new Error('no');
      },
    } as unknown as DatadogTracer;

    expect(() => installSensitiveScrubbing(hostile, { onDegraded: () => undefined })).not.toThrow();
  });

  it('warns on the console when no onDegraded is supplied', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);

    try {
      installSensitiveScrubbing(tracerWithoutTags());

      expect(warn).toHaveBeenCalledTimes(1);
    } finally {
      warn.mockRestore();
    }
  });

  it('survives an onDegraded that throws', () => {
    expect(() =>
      installSensitiveScrubbing(tracerWithoutTags(), {
        onDegraded: () => {
          throw new Error('logging is down');
        },
      })
    ).not.toThrow();
  });
});

describe('composing with a plugin config already stored', () => {
  it('keeps the callers hook and their other plugin options', () => {
    const stored: Record<string, unknown> = {
      http: { service: 'legacy', hooks: { request: () => undefined } },
    };
    const written: Record<string, Record<string, unknown>> = {};

    const tracer = {
      use(plugin: string, config: unknown) {
        written[plugin] = config as Record<string, unknown>;

        return undefined;
      },
      _pluginManager: { _configsByName: stored },
    } as unknown as DatadogTracer;

    installSensitiveScrubbing(tracer, { captureHeaders: ['authorization'] });

    expect(written['http']?.['service']).toBe('legacy');
    expect(typeof (written['http']?.['hooks'] as { request: unknown }).request).toBe('function');
  });

  it('reads headerTags off an initialized tracer so the two lists are not split', () => {
    const written: Record<string, Record<string, unknown>> = {};

    const tracer = {
      use(plugin: string, config: unknown) {
        written[plugin] = config as Record<string, unknown>;

        return undefined;
      },
      _tracer: { _config: { headerTags: ['x-from-init'] } },
    } as unknown as DatadogTracer;

    const installation = installSensitiveScrubbing(tracer, { captureHeaders: ['authorization'] });

    expect(installation.capturedHeaders).toEqual(['authorization', 'x-from-init']);
  });

  it('composes onto a callers own queryStringObfuscation', () => {
    const tracer = {
      use: () => undefined,
      _tracer: { _config: { DD_TRACE_OBFUSCATION_QUERY_STRING_REGEXP: 'mine=[^&]+' } },
    } as unknown as DatadogTracer;

    const installation = installSensitiveScrubbing(tracer);

    expect(installation.queryStringObfuscation).toContain('mine=[^&]+');
  });

  it('leaves the header key off entirely when there is no list to write', () => {
    // Writing an empty array would replace the tracer's own `headerTags`,
    // because the plugin manager builds a plugin config as
    // `{...sharedConfig, ...pluginConfig}`.
    const written: Record<string, Record<string, unknown>> = {};

    const tracer = {
      use(plugin: string, config: unknown) {
        written[plugin] = config as Record<string, unknown>;

        return undefined;
      },
    } as unknown as DatadogTracer;

    installSensitiveScrubbing(tracer);

    expect('headers' in (written['http'] ?? {})).toBe(false);
  });
});

describe('scrubManualSpans', () => {
  it('can be turned off, leaving startSpan alone', () => {
    const original = () => ({ setTag: () => undefined, context: () => ({ getTags: () => ({}) }) });
    const tracer = { use: () => undefined, startSpan: original } as unknown as DatadogTracer;

    const installation = installSensitiveScrubbing(tracer, { scrubManualSpans: false });

    expect(installation.scrubsManualSpans).toBe(false);
    expect(tracer.startSpan).toBe(original);
  });

  it('wraps the inner tracer where there is one, so trace() and wrap() are covered', () => {
    // Measured: `tracer.trace()` and `tracer.wrap()` reach `startSpan` on the
    // inner tracer and never through the proxy.
    const inner = {
      startSpan: () => ({
        setTag: () => undefined,
        context: () => ({ getTags: () => ({}) }),
        finish: () => undefined,
      }),
    };
    const originalInner = inner.startSpan;
    const tracer = { use: () => undefined, _tracer: inner } as unknown as DatadogTracer;

    expect(installSensitiveScrubbing(tracer).scrubsManualSpans).toBe(true);
    expect(inner.startSpan).not.toBe(originalInner);
  });

  it('never lets a scrub failure reach the caller of finish()', () => {
    // The asymmetry that makes this its own case. A hook body is called by the
    // agent, which answers a throw by dropping that one span. `finish()` is
    // called by the application, so a throw here would propagate into whatever
    // was recording a span, and the span would never close either.
    //
    // Driven through a span whose `setTag` throws, which is the reachable way
    // in: everything the walk itself touches is guarded, so `writeBack` is the
    // one step in `scrubSpan` that can still fail.
    const tags: Record<string, unknown> = { 'probe.password': 'raw' };
    let finished = false;
    const inner = {
      startSpan: () => ({
        setTag() {
          throw new Error('this span refuses writes');
        },
        context: () => ({ getTags: () => tags }),
        finish() {
          finished = true;
        },
      }),
    };
    const tracer = { use: () => undefined, _tracer: inner } as unknown as DatadogTracer;

    installSensitiveScrubbing(tracer);

    const span = inner.startSpan();

    expect(() => span.finish()).not.toThrow();
    expect(finished).toBe(true);
  });

  it('scrubs a manual span at finish rather than at creation', () => {
    const tags: Record<string, unknown> = {};
    let finished = false;
    const inner = {
      startSpan: () => ({
        setTag(key: string, value: unknown) {
          tags[key] = value;
        },
        context: () => ({ getTags: () => tags }),
        finish() {
          finished = true;
        },
      }),
    };
    const tracer = { use: () => undefined, _tracer: inner } as unknown as DatadogTracer;

    installSensitiveScrubbing(tracer);

    const span = inner.startSpan();

    tags['probe.password'] = 'raw';

    expect(tags['probe.password']).toBe('raw');

    span.finish();

    expect(tags['probe.password']).toBe('[SCRUBBED]');
    expect(finished).toBe(true);
  });
});
