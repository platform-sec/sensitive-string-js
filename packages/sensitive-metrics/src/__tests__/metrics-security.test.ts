import { readdirSync, readFileSync, statSync } from 'node:fs';
import { createSocket } from 'node:dgram';
import type { Socket } from 'node:dgram';
import { resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  RevealLimitExceededError,
  SensitiveString,
  deterministicRedaction,
  observeRedactions,
  registerPolicy,
  resetPolicies,
} from '@platform-sec/sensitive-string-core';
import type { RedactionEvent } from '@platform-sec/sensitive-string-core';
import { createMetricsCollector } from '../collector.js';
import type { MetricsCollector } from '../collector.js';
import { PrometheusExporter } from '../prometheus.js';
import { StatsDExporter } from '../statsd.js';

const CANARY = 'LEAKED_SECRET_metrics_test_qwerty';

const running: MetricsCollector[] = [];
const sockets: Socket[] = [];

function started(...args: ConstructorParameters<typeof MetricsCollector>): MetricsCollector {
  const created = createMetricsCollector(...args);
  running.push(created);
  created.start();
  return created;
}

afterEach(() => {
  for (const created of running.splice(0)) {
    created.stop();
  }
  for (const socket of sockets.splice(0)) {
    socket.close();
  }
  resetPolicies();
});

/**
 * Everything a value can be put through here, so a canary check covers the
 * whole surface rather than the one path a test happened to pick.
 */
function exercise(secret: SensitiveString<'credential'>, metrics: MetricsCollector): void {
  void String(secret);
  void JSON.stringify({ secret });

  metrics.withMeteredReveals({ name: 'payment-handler', reason: 'charging a card' }, () => {
    secret.reveal();
    secret.hash('sha256');
  });
}

describe('INV-MET-001: no metric carries the value', () => {
  // MET-C001.
  it('keeps the value out of the Prometheus output', () => {
    const metrics = started({ dimensions: ['label', 'context'] });
    const secret = new SensitiveString(CANARY, 'credential', 'key');

    exercise(secret, metrics);

    const output = new PrometheusExporter(metrics, { prefix: 'app_' }).export();

    expect(output).not.toContain(CANARY);
    expect(output).toContain('class="credential"');
    expect(output).toContain('label="key"');
    expect(output).toContain('context="payment-handler"');
  });

  // MET-C002, on the bytes that actually left the process.
  it('keeps the value out of a StatsD datagram', async () => {
    const server = createSocket('udp4');
    const packets: string[] = [];

    sockets.push(server);
    server.on('message', (message) => packets.push(message.toString('utf8')));

    const port = await new Promise<number>((done) => {
      server.bind(0, '127.0.0.1', () => done(server.address().port));
    });

    const metrics = started({ dimensions: ['label', 'context'] });
    const statsd = new StatsDExporter(metrics, { host: '127.0.0.1', port });

    exercise(new SensitiveString(CANARY, 'credential', 'key'), metrics);
    statsd.flush();

    await new Promise((done) => setTimeout(done, 50));
    statsd.stop();

    expect(packets.join('\n')).not.toContain(CANARY);
    expect(packets.join('\n')).toContain('label:key');
  });

  // MET-C003.
  it('keeps the value out of the snapshot, including once serialized', () => {
    const metrics = started({ dimensions: ['label', 'context'] });

    exercise(new SensitiveString(CANARY, 'credential', 'key'), metrics);

    const snapshot = metrics.getSnapshot();

    expect(JSON.stringify(snapshot)).not.toContain(CANARY);
    expect(snapshot.redactions.total).toBeGreaterThan(0);
    expect(snapshot.reveals.total).toBe(2);
  });

  it('keeps the value out of the family view an exporter reads', () => {
    const metrics = started({ dimensions: ['label', 'context'] });

    exercise(new SensitiveString(CANARY, 'credential', 'key'), metrics);

    expect(JSON.stringify(metrics.collect())).not.toContain(CANARY);
  });

  it('never receives the rendering, so a deterministic marker cannot become a dimension', () => {
    // Under a deterministic-redaction policy the marker is a pseudonym of the
    // value: stable per value, so a dimension holding it would be a table of
    // every distinct secret in the process, joinable across services. Core
    // withholds the rendering from the event, and this asserts it from the
    // consuming side rather than trusting it.
    const events: RedactionEvent[] = [];
    const stop = observeRedactions((event) => events.push(event));

    try {
      registerPolicy(
        deterministicRedaction('sensitive', { key: 'k'.repeat(32), scope: 'tenant-a' }),
        { overwrite: true }
      );

      const first = new SensitiveString(CANARY, 'sensitive', 'email');
      const second = new SensitiveString(`${CANARY}-other`, 'sensitive', 'email');

      const firstMarker = String(first);
      const secondMarker = String(second);

      // The pseudonym is what makes this worth asserting: it differs per value
      // and is stable per value, which is exactly a dimension nobody wants.
      expect(firstMarker).not.toBe(secondMarker);
      expect(String(first)).toBe(firstMarker);

      const collected = JSON.stringify(events);

      expect(events).toHaveLength(3);
      expect(Object.keys(events[0] ?? {}).sort()).toEqual(['klass', 'label', 'surface']);
      expect(collected).not.toContain(CANARY);
      expect(collected).not.toContain(firstMarker);
      expect(collected).not.toContain(secondMarker);
    } finally {
      stop();
    }
  });
});

describe('MET-C004: what a caller can put in a dimension, and what the library does about it', () => {
  it('adds no dimension derived from the value', () => {
    const metrics = started({ dimensions: ['label', 'context'] });

    exercise(new SensitiveString(CANARY, 'credential', 'key'), metrics);
    // So the refusal counter has a series too, and its dimensions are checked
    // alongside the other two rather than being absent from the assertion.
    expect(() =>
      metrics.meterRefusals(() => {
        new SensitiveString(CANARY, 'credential', 'key', { ttl: 0 }).reveal();
      }, 'credential')
    ).toThrow();

    // The only dimensions on any series are the ones this library names.
    const named = new Set(
      metrics.collect().flatMap((family) => family.series.flatMap((s) => Object.keys(s.labels)))
    );

    expect([...named].sort()).toEqual([
      'class',
      'code',
      'context',
      'label',
      'operation',
      'surface',
    ]);
  });

  it('records a value a caller put in the label, because it cannot tell one from a label', () => {
    // The design's original note called this "a documentation issue, not a
    // library issue". It is a library issue as far as the defaults go, and this
    // is what the library actually does: the value reaches the metric, because
    // a label is a string and nothing distinguishes this one.
    const metrics = started();

    void String(new SensitiveString(CANARY, 'credential', CANARY));

    expect(JSON.stringify(metrics.getSnapshot())).toContain(CANARY);
  });

  it('does not record a context name unless the dimension was asked for, which is why it is off by default', () => {
    // The mitigation the library does have. A context name is chosen at the
    // call site, where a request id or a user identifier is at hand, so it is
    // opt-in and the reveal counter is coarser until you opt in.
    const metrics = started();

    metrics.withMeteredReveals({ name: `handler-${CANARY}` }, () => {
      new SensitiveString(CANARY, 'credential', 'key').reveal();
    });

    expect(JSON.stringify(metrics.getSnapshot())).not.toContain(CANARY);
    expect(metrics.getRevealCount()).toBe(1);
  });

  it('bounds how much of it can accumulate, whatever a caller labels things with', () => {
    const metrics = started({ maxSeries: 4 });

    for (let index = 0; index < 200; index++) {
      void String(new SensitiveString(CANARY, 'credential', `${CANARY}_${String(index)}`));
    }

    expect(Object.keys(metrics.getSnapshot().redactions.byLabel).length).toBeLessThanOrEqual(8);
    expect(metrics.getSnapshot().redactions.total).toBe(200);
  });
});

describe('the collector never reads the value it counts', () => {
  it('does not charge a reveal budget from inside the audit hook', () => {
    // The hook runs inside core's raw-value gate, which is not reentrant.
    // A hook that reads the value recurses until the stack is exhausted, and
    // against a budget it charges the inner read first. One reveal against a
    // budget of one must therefore still succeed, and the second must be the
    // one refused.
    const metrics = started();
    const secret = new SensitiveString(CANARY, 'credential', 'key', { maxReveals: 1 });

    metrics.withMeteredReveals({ name: 'payment' }, () => {
      expect(secret.reveal()).toBe(CANARY);
      expect(() => secret.reveal()).toThrow(RevealLimitExceededError);
    });

    expect(metrics.getRevealCount()).toBe(1);
  });

  it('imports nothing from core that could read a value', () => {
    // The check is on what comes in rather than on what is called, for the
    // reason the scrub package gives: a grep for `reveal` cannot tell
    // `SensitiveString.prototype.map` from `Array.prototype.map`.
    const allowed = new Set([
      'SensitiveStringError',
      'createChildContext',
      'getCurrentRevealContext',
      'observeRedactions',
      'trackedInstanceCount',
      'withRevealContext',
      // Types only.
      'AuditContext',
      'ISensitiveString',
      'RedactionEvent',
      'RedactionSurface',
      'RevealContext',
      'RevealDetails',
      'SensitivityClass',
    ]);

    const imported = coreImports(resolve(process.cwd(), 'packages/sensitive-metrics/src'));

    expect(imported.filter((name) => !allowed.has(name))).toEqual([]);
    // An empty pass is impossible: the walk has to have found the real ones.
    expect(imported).toContain('observeRedactions');
    expect(imported).toContain('trackedInstanceCount');
  });
});

/**
 * Every name shipped source imports from core, tests excluded.
 *
 * Deliberately crude: a regex over the import statements rather than a parse,
 * which is enough because this package has a handful of files and one import
 * style. A name it cannot see is a name in a file written differently, which
 * is a reason to widen the list here rather than to loosen the pattern.
 */
function coreImports(dir: string): string[] {
  const found: string[] = [];

  for (const entry of readdirSync(dir)) {
    const path = `${dir}/${entry}`;

    if (statSync(path).isDirectory()) {
      continue;
    }

    if (!entry.endsWith('.ts') || entry.endsWith('.test.ts')) {
      continue;
    }

    const source = readFileSync(path, 'utf8');
    const pattern =
      /import(?:\s+type)?\s*\{([^}]*)\}\s*from\s*'@platform-sec\/sensitive-string-core'/g;

    for (const match of source.matchAll(pattern)) {
      for (const name of (match[1] ?? '').split(',')) {
        const trimmed = name.trim().replace(/^type\s+/, '');

        if (trimmed !== '') {
          found.push(trimmed);
        }
      }
    }
  }

  return [...new Set(found)].sort();
}
