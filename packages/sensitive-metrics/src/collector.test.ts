import { inspect } from 'node:util';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  ExpiredSensitiveValueError,
  RevealDuringRedactionError,
  SensitiveString,
  RevokedSensitiveValueError,
  getCurrentRevealContext,
  redactInStructure,
  safeStringify,
  setMemoryHygiene,
  resetMemoryHygiene,
  withRevealContext,
} from '@platform-sec/sensitive-string-core';
import type {
  AuditContext,
  ISensitiveString,
  RevealDetails,
} from '@platform-sec/sensitive-string-core';
import { MetricsCollector, createMetricsCollector } from './collector.js';
import { OVERFLOW_LABEL } from './types.js';

const CANARY = 'LEAKED_SECRET_metrics_collector_qwerty';

/** Every collector a test starts, so no subscription survives into the next one. */
const running: MetricsCollector[] = [];

function collector(...args: ConstructorParameters<typeof MetricsCollector>): MetricsCollector {
  const created = createMetricsCollector(...args);
  running.push(created);
  return created;
}

afterEach(() => {
  for (const created of running.splice(0)) {
    created.stop();
  }
});

describe('createMetricsCollector', () => {
  it('resolves every default', () => {
    expect(collector().config).toEqual({
      trackRedactions: true,
      trackReveals: true,
      trackRefusals: true,
      trackInstances: false,
      dimensions: ['label'],
      maxSeries: 1000,
      onCardinalityExceeded: 'aggregate',
    });
  });

  it('leaves the context name off by default, because a context name is free-form call-site text', () => {
    expect(collector().config.dimensions).not.toContain('context');
  });

  it.each([
    [{ trackReveals: 'yes' }, 'trackReveals'],
    [{ dimensions: 'label' }, 'dimensions'],
    [{ dimensions: ['class'] }, "unknown dimension 'class'"],
    [{ maxSeries: 0 }, 'maxSeries'],
    [{ maxSeries: 1.5 }, 'maxSeries'],
    [{ onCardinalityExceeded: 'explode' }, 'onCardinalityExceeded'],
  ])('refuses %o at construction', (config, message) => {
    expect(() => createMetricsCollector(config as never)).toThrow(message);
  });

  it('refuses anything that is not a configuration object', () => {
    expect(() => createMetricsCollector(null as never)).toThrow(TypeError);
  });
});

describe('redaction counting', () => {
  // MET-T001 in the design's table, renamed: the first counter is redactions,
  // not reveals. ADR-009.
  it('counts a coercion under the toString surface', () => {
    const metrics = collector();
    metrics.start();

    const secret = new SensitiveString(CANARY, 'credential', 'api_key');
    void `${String(secret)}`;

    expect(metrics.getRedactionCount()).toBe(1);
    expect(metrics.getRedactionCount({ surface: 'toString' })).toBe(1);
    expect(metrics.getRedactionCount({ klass: 'credential', label: 'api_key' })).toBe(1);
  });

  it('tells the four surfaces apart, which is what makes the number readable', () => {
    const metrics = collector();
    metrics.start();

    const secret = new SensitiveString(CANARY, 'sensitive', 'email');

    void String(secret);
    void JSON.stringify({ secret });
    void inspect(secret);
    void safeStringify({ secret });

    expect(metrics.getSnapshot().redactions.bySurface).toEqual({
      toString: 1,
      toJSON: 1,
      inspect: 1,
      structure: 1,
    });
  });

  it('counts a walker replacement under structure rather than as a coercion', () => {
    const metrics = collector();
    metrics.start();

    redactInStructure({ nested: { secret: new SensitiveString(CANARY, 'credential', 'token') } });

    expect(metrics.getRedactionCount({ surface: 'structure' })).toBe(1);
    expect(metrics.getRedactionCount({ surface: 'toString' })).toBe(0);
  });

  it('records no label for a serialize() result a walker replaced, since that label is data off the wire', () => {
    const metrics = collector();
    metrics.start();

    const wire = new SensitiveString(CANARY, 'credential', 'api_key').serialize();
    redactInStructure({ wire });

    expect(metrics.getRedactionCount({ surface: 'structure' })).toBe(1);
    expect(metrics.getSnapshot().redactions.byLabel['api_key']).toBeUndefined();
  });

  it('stops counting after stop(), and keeps what it counted', () => {
    const metrics = collector();
    const stop = metrics.start();

    const secret = new SensitiveString(CANARY, 'credential');
    void String(secret);
    stop();
    void String(secret);

    expect(metrics.getRedactionCount()).toBe(1);
    expect(metrics.started).toBe(false);
  });

  it('subscribes once however many times start() is called', () => {
    const metrics = collector();
    metrics.start();
    metrics.start();

    void String(new SensitiveString(CANARY, 'credential'));

    expect(metrics.getRedactionCount()).toBe(1);
  });

  // MET-T012, in the half of it a test can assert. The timing half belongs to
  // the benchmark suite for the same reason no other wall-clock verdict gates
  // this repository's tests.
  it('subscribes to nothing when redaction tracking is off', () => {
    const metrics = collector({ trackRedactions: false });
    metrics.start();

    void String(new SensitiveString(CANARY, 'credential'));

    expect(metrics.getRedactionCount()).toBe(0);
    expect(metrics.started).toBe(true);
  });
});

describe('audited operation counting', () => {
  it('counts a reveal made under a metered context', () => {
    const metrics = collector({ dimensions: ['label', 'context'] });

    const secret = new SensitiveString(CANARY, 'credential', 'api_key');

    metrics.withMeteredReveals({ name: 'payment-handler' }, () => {
      expect(secret.reveal()).toBe(CANARY);
    });

    expect(metrics.getRevealCount()).toBe(1);
    expect(metrics.getRevealCount({ operation: 'reveal', context: 'payment-handler' })).toBe(1);
  });

  it('distinguishes the operations core audits', () => {
    const metrics = collector();
    const secret = new SensitiveString(CANARY, 'sensitive', 'email');

    metrics.withMeteredReveals({ name: 'support' }, () => {
      secret.reveal();
      secret.mask({ showLast: 2 });
      secret.hash('sha256');
    });

    expect(metrics.getSnapshot().reveals.byOperation).toEqual({ reveal: 1, mask: 1, hash: 1 });
  });

  it('counts nothing for a reveal made outside a metered context, and says so rather than pretending otherwise', () => {
    const metrics = collector();
    const secret = new SensitiveString(CANARY, 'credential', 'api_key');

    secret.reveal();
    withRevealContext({ name: 'unmetered' }, () => secret.reveal());

    expect(metrics.getRevealCount()).toBe(0);
  });

  it('chains onto the audit hook already in force instead of replacing it', () => {
    const metrics = collector();
    const outer = vi.fn();
    const secret = new SensitiveString(CANARY, 'credential', 'api_key');

    withRevealContext({ name: 'request', auditReveal: outer }, () => {
      metrics.withMeteredReveals({ name: 'payment' }, () => {
        secret.reveal();
      });
    });

    expect(outer).toHaveBeenCalledTimes(1);
    expect(metrics.getRevealCount()).toBe(1);
  });

  it('calls an inherited hook with its own context as `this`, the way core does', () => {
    // `auditReveal` is declared as a method, so a sink may be written as one
    // and read `this`. Extracting the function to chain it would call it
    // unbound and break that sink on the path meant to preserve it.
    const metrics = collector();
    const seen: unknown[] = [];

    const outer = {
      name: 'request',
      marker: 'the installed context',
      auditReveal(this: { marker?: string }) {
        seen.push(this?.marker);
      },
    };

    withRevealContext(outer, () => {
      metrics.withMeteredReveals({ name: 'payment' }, () => {
        new SensitiveString(CANARY, 'credential').reveal();
      });
    });

    expect(seen).toEqual(['the installed context']);
  });

  it('inherits the ambient tags, the way createChildContext does', () => {
    const metrics = collector();
    const seen: (AuditContext | undefined)[] = [];

    withRevealContext({ name: 'request', tags: { requestId: 'r-1' } }, () => {
      metrics.withMeteredReveals(
        { name: 'payment', auditReveal: (_v, _d, ctx) => seen.push(ctx) },
        () => {
          new SensitiveString(CANARY, 'credential').reveal();
        }
      );
    });

    expect(seen[0]?.name).toBe('payment');
    expect(seen[0]?.tags).toEqual({ requestId: 'r-1' });
  });

  it('counts last, so a reveal an upstream audit sink refused is not counted as one that happened', () => {
    const metrics = collector();
    const secret = new SensitiveString(CANARY, 'credential');

    const refuse = () => {
      throw new Error('this reveal is not allowed');
    };

    expect(() =>
      withRevealContext({ name: 'request', auditReveal: refuse }, () => {
        metrics.withMeteredReveals({ name: 'payment' }, () => secret.reveal());
      })
    ).toThrow('this reveal is not allowed');

    expect(metrics.getRevealCount()).toBe(0);
  });

  it('leaves the ambient context in place for code outside the metered scope', () => {
    const metrics = collector();

    withRevealContext({ name: 'request' }, () => {
      metrics.withMeteredReveals({ name: 'payment' }, () => {
        expect(getCurrentRevealContext()?.name).toBe('payment');
      });

      expect(getCurrentRevealContext()?.name).toBe('request');
    });
  });

  it('records an operation it does not recognise as unknown rather than losing it', () => {
    const metrics = collector();
    const value: ISensitiveString = new SensitiveString(CANARY, 'credential', 'api_key');

    metrics.auditReveal(value, { operation: 'teleport' } as unknown as RevealDetails, {
      name: 'x',
    });

    expect(metrics.getSnapshot().reveals.byOperation).toEqual({ unknown: 1 });
  });

  it('counts nothing when reveal tracking is off', () => {
    const metrics = collector({ trackReveals: false });

    metrics.withMeteredReveals({ name: 'payment' }, () => {
      new SensitiveString(CANARY, 'credential').reveal();
    });

    expect(metrics.getRevealCount()).toBe(0);
  });
});

describe('refusal counting', () => {
  it('counts a refusal by its code', () => {
    const metrics = collector();
    const secret = new SensitiveString(CANARY, 'credential', 'otp', { ttl: 0 });

    expect(() => metrics.meterRefusals(() => secret.reveal(), 'credential')).toThrow(
      ExpiredSensitiveValueError
    );

    expect(metrics.getSnapshot().refusals).toEqual({
      total: 1,
      byClass: { credential: 1 },
      byCode: { 'expired-value': 1 },
      byLabel: { otp: 1 },
    });
    expect(metrics.getRefusalCount({ label: 'otp', code: 'expired-value' })).toBe(1);
  });

  it('rethrows the error untouched, so it is a tee and not a handler', () => {
    const metrics = collector();
    const thrown = new RevokedSensitiveValueError('rotated', new Date(0), 'api_key');

    expect(() =>
      metrics.meterRefusals(() => {
        throw thrown;
      })
    ).toThrow(thrown);
  });

  it('ignores an error that is not one of this library refusals', () => {
    const metrics = collector();

    expect(metrics.recordRefusal(new Error('a database timed out'))).toBe(false);
    expect(metrics.recordRefusal('not even an error')).toBe(false);
    expect(metrics.getSnapshot().refusals.total).toBe(0);
  });

  it('reads the class off the error where it carries one, over the one passed in', () => {
    const metrics = collector();

    // A refusal that names the class it refused for is more trustworthy than
    // whatever the catch site guessed, which is often the class of a different
    // value in the same block.
    metrics.recordRefusal(new RevealDuringRedactionError('credential', 'api_key'), 'sensitive');

    expect(metrics.getSnapshot().refusals.byClass).toEqual({ credential: 1 });
  });

  it("records 'unknown' where neither the error nor the caller names a class", () => {
    const metrics = collector();
    const error = new RevokedSensitiveValueError('rotated', new Date(0), 'api_key');

    metrics.recordRefusal(error);

    expect(metrics.getSnapshot().refusals.byClass).toEqual({ unknown: 1 });
  });

  it('counts nothing when refusal tracking is off', () => {
    const metrics = collector({ trackRefusals: false });

    expect(metrics.recordRefusal(new RevokedSensitiveValueError('r', new Date(0)))).toBe(false);
  });
});

describe('never breaking the thing it measures (INV-MET-003)', () => {
  // MET-T011. The reveal has to survive a recording that cannot complete,
  // because the audit hook is the one path core does not wrap: a hook that
  // throws stops the reveal.
  // Core does not validate the label's type, so a symbol reaches the event and
  // the audit record as one. That is the recording failure this package can
  // actually be handed, rather than an invented one: a symbol has no length
  // and throws on string coercion, so building a series key from it fails.
  const symbolLabelled = () =>
    new SensitiveString(CANARY, 'credential', Symbol('api_key') as unknown as string);

  it('swallows a recording failure and lets the reveal through', () => {
    const metrics = collector();
    const secret = symbolLabelled();
    let revealed: string | undefined;

    metrics.withMeteredReveals({ name: 'payment' }, () => {
      revealed = secret.reveal();
    });

    expect(revealed).toBe(CANARY);
    expect(metrics.getSnapshot().meta.recordingErrors).toBe(1);
    expect(metrics.getRevealCount()).toBe(0);
  });

  it('renders a redaction even when the collector cannot record it', () => {
    const metrics = collector();
    metrics.start();

    const secret = symbolLabelled();

    expect(String(secret)).toBe('[REDACTED:credential]');
    expect(metrics.getSnapshot().meta.recordingErrors).toBe(1);
  });

  it('reports a recording failure rather than a wrong number', () => {
    const metrics = collector();
    metrics.start();

    void String(symbolLabelled());
    void String(new SensitiveString(CANARY, 'credential', 'api_key'));

    const snapshot = metrics.getSnapshot();

    expect(snapshot.redactions.total).toBe(1);
    expect(snapshot.meta.recordingErrors).toBe(1);
  });
});

describe('cardinality, seen from the collector', () => {
  // MET-T010.
  it('folds a runaway label and keeps the total, reporting how much it folded', () => {
    const metrics = collector({ maxSeries: 5 });
    metrics.start();

    for (let index = 0; index < 100; index++) {
      void String(new SensitiveString(CANARY, 'credential', `user_${String(index)}`));
    }

    const snapshot = metrics.getSnapshot();

    expect(snapshot.redactions.total).toBe(100);
    expect(snapshot.redactions.byLabel[OVERFLOW_LABEL]).toBeGreaterThan(0);
    expect(snapshot.meta.eventsAggregated).toBeGreaterThan(0);
    expect(snapshot.meta.eventsDropped).toBe(0);
  });

  it("loses the total under 'drop', and says how much", () => {
    const metrics = collector({ maxSeries: 2, onCardinalityExceeded: 'drop' });
    metrics.start();

    for (let index = 0; index < 20; index++) {
      void String(new SensitiveString(CANARY, 'credential', `user_${String(index)}`));
    }

    const snapshot = metrics.getSnapshot();

    expect(snapshot.redactions.total).toBe(2);
    expect(snapshot.meta.eventsDropped).toBe(18);
  });
});

describe('bounding a dimension value, not just the number of them', () => {
  // The cardinality cap bounds how many series a counter holds and says
  // nothing about how big one is. Without a length bound, a thousand legal
  // series still make a scrape as large as the caller's labels are long.
  it('truncates a runaway label rather than storing it whole', () => {
    const metrics = collector();
    metrics.start();

    void String(new SensitiveString(CANARY, 'credential', 'x'.repeat(50_000)));

    const [label] = Object.keys(metrics.getSnapshot().redactions.byLabel);

    expect(label?.length).toBe(200);
  });

  it('truncates a context name and an error label the same way', () => {
    const metrics = collector({ dimensions: ['label', 'context'] });

    metrics.withMeteredReveals({ name: 'c'.repeat(5000) }, () => {
      new SensitiveString(CANARY, 'credential', 'key').reveal();
    });
    metrics.recordRefusal(
      new RevokedSensitiveValueError('rotated', new Date(0), 'l'.repeat(5000)),
      'credential'
    );

    const snapshot = metrics.getSnapshot();

    expect(Object.keys(snapshot.reveals.byContext)[0]?.length).toBe(200);
    expect(Object.keys(snapshot.refusals.byLabel)[0]?.length).toBe(200);
    expect(
      metrics
        .collect()
        .some((family) =>
          family.series.some((series) =>
            Object.values(series.labels).some((value) => value.length > 200)
          )
        )
    ).toBe(false);
  });

  it('bounds the whole scrape, which is the point of bounding one value', () => {
    const metrics = collector({ maxSeries: 50 });
    metrics.start();

    for (let index = 0; index < 50; index++) {
      void String(
        new SensitiveString(CANARY, 'credential', `${'x'.repeat(20_000)}${String(index)}`)
      );
    }

    // 50 series of 20 KB each would be a megabyte of labels.
    expect(JSON.stringify(metrics.collect()).length).toBeLessThan(30_000);
  });

  it('makes two labels that share a truncated prefix one series, everywhere', () => {
    // The reason truncation is at ingest rather than in an exporter: the
    // truncated value is the series identity, so nothing downstream can be
    // handed two distinct series that render identically.
    const metrics = collector();
    metrics.start();

    void String(new SensitiveString(CANARY, 'credential', `${'y'.repeat(300)}_first`));
    void String(new SensitiveString(CANARY, 'credential', `${'y'.repeat(300)}_second`));

    expect(Object.keys(metrics.getSnapshot().redactions.byLabel)).toHaveLength(1);
    expect(metrics.getRedactionCount()).toBe(2);
  });
});

describe('the tracked-values gauge', () => {
  beforeEach(() => {
    resetMemoryHygiene();
  });

  afterEach(() => {
    resetMemoryHygiene();
  });

  it('is absent unless asked for', () => {
    expect(collector().getSnapshot().valuesTracked).toBeNull();
    expect(
      collector()
        .collect()
        .map((family) => family.name)
    ).not.toContain('sensitive_values_tracked');
  });

  it('reads core hygiene registry when both switches are on', () => {
    setMemoryHygiene({ trackInstances: true });
    const metrics = collector({ trackInstances: true });

    const held = [
      new SensitiveString(CANARY, 'credential', 'a'),
      new SensitiveString(CANARY, 'credential', 'b'),
    ];

    expect(metrics.getSnapshot().valuesTracked).toBe(2);
    expect(held).toHaveLength(2);
  });

  it('publishes a flat zero when core is not tracking, which is what the config warns about', () => {
    const metrics = collector({ trackInstances: true });

    void new SensitiveString(CANARY, 'credential', 'a');

    expect(metrics.getSnapshot().valuesTracked).toBe(0);
  });
});

describe('the snapshot', () => {
  // MET-T007.
  it('is plain JSON, so it survives a structured log line unchanged', () => {
    const metrics = collector({ dimensions: ['label', 'context'] });
    metrics.start();

    const secret = new SensitiveString(CANARY, 'credential', 'api_key');
    void String(secret);
    metrics.withMeteredReveals({ name: 'payment' }, () => secret.reveal());

    const snapshot = metrics.getSnapshot();

    expect(JSON.parse(JSON.stringify(snapshot))).toEqual(snapshot);
    expect(snapshot).toMatchObject({
      redactions: { total: 1, byClass: { credential: 1 }, bySurface: { toString: 1 } },
      reveals: { total: 1, byContext: { payment: 1 } },
      meta: { started: true, eventsAggregated: 0, eventsDropped: 0, recordingErrors: 0 },
    });
  });

  it('reports every metric family even when nothing has happened, which is what a first deployment scrapes', () => {
    expect(
      collector()
        .collect()
        .map((family) => family.name)
    ).toEqual([
      'sensitive_redactions_total',
      'sensitive_reveals_total',
      'sensitive_refusals_total',
      'sensitive_metrics_events_aggregated_total',
      'sensitive_metrics_events_dropped_total',
      'sensitive_metrics_recording_errors_total',
    ]);
  });
});

describe('lifecycle', () => {
  it('resubscribes after a stop, keeping what it already counted', () => {
    // Keeping the counts is the point. A counter that reset here would look
    // like a process restart to every rate() reading it.
    const metrics = collector();

    metrics.start();
    void String(new SensitiveString(CANARY, 'credential', 'api_key'));
    metrics.stop();
    void String(new SensitiveString(CANARY, 'credential', 'api_key'));
    metrics.start();
    void String(new SensitiveString(CANARY, 'credential', 'api_key'));

    expect(metrics.getRedactionCount()).toBe(2);
    expect(metrics.started).toBe(true);
  });

  it('survives being stopped twice, and stopped without ever starting', () => {
    const metrics = collector();

    expect(() => {
      metrics.stop();
    }).not.toThrow();

    metrics.start();
    metrics.stop();

    expect(() => {
      metrics.stop();
    }).not.toThrow();
    expect(metrics.started).toBe(false);
  });

  it('counts nothing rendered before start(), which is what the coverage claim says', () => {
    const metrics = collector();

    void String(new SensitiveString(CANARY, 'credential', 'api_key'));
    metrics.start();

    expect(metrics.getRedactionCount()).toBe(0);
  });

  it('keeps two collectors in one isolate independent', () => {
    const first = collector();
    const second = collector();

    first.start();
    void String(new SensitiveString(CANARY, 'credential', 'api_key'));
    second.start();
    void String(new SensitiveString(CANARY, 'credential', 'api_key'));
    first.stop();
    void String(new SensitiveString(CANARY, 'credential', 'api_key'));

    expect(first.getRedactionCount()).toBe(2);
    expect(second.getRedactionCount()).toBe(2);
  });

  it('attributes interleaved async reveals to the context each one actually ran under', () => {
    // AsyncLocalStorage is what makes this work, and getting it wrong would
    // mis-attribute quietly rather than fail: the total would still be right.
    const metrics = collector({ dimensions: ['label', 'context'] });
    const secret = new SensitiveString(CANARY, 'credential', 'api_key');

    const inContext = async (name: string, rounds: number): Promise<void> =>
      metrics.withMeteredReveals({ name }, async () => {
        for (let round = 0; round < rounds; round++) {
          await Promise.resolve();
          secret.reveal();
        }
      });

    return Promise.all([inContext('alpha', 3), inContext('beta', 5)]).then(() => {
      expect(metrics.getSnapshot().reveals.byContext).toEqual({ alpha: 3, beta: 5 });
    });
  });
});

describe('reset', () => {
  it('drops the counts and keeps the subscription', () => {
    const metrics = collector();
    metrics.start();

    void String(new SensitiveString(CANARY, 'credential'));
    metrics.reset();

    expect(metrics.getRedactionCount()).toBe(0);
    expect(metrics.started).toBe(true);

    void String(new SensitiveString(CANARY, 'credential'));

    expect(metrics.getRedactionCount()).toBe(1);
  });
});
