import { afterEach, describe, expect, it } from 'vitest';
import { RevokedSensitiveValueError, SensitiveString } from '@platform-sec/sensitive-string-core';
import { MetricsCollector, createMetricsCollector } from './collector.js';
import { PROMETHEUS_CONTENT_TYPE, PrometheusExporter } from './prometheus.js';
import { DIMENSION_NAMES } from './types.js';

const CANARY = 'LEAKED_SECRET_metrics_prometheus_qwerty';

const running: MetricsCollector[] = [];

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
});

/** The series lines of one metric, without the HELP and TYPE headers. */
function seriesOf(output: string, metric: string): string[] {
  return output
    .split('\n')
    .filter((line) => line.startsWith(`${metric}{`) || line.startsWith(`${metric} `));
}

describe('PrometheusExporter', () => {
  // MET-T008.
  it('renders the exposition format a Prometheus server parses', () => {
    const metrics = started();
    const secret = new SensitiveString(CANARY, 'credential', 'api_key');

    void String(secret);
    void String(secret);
    void JSON.stringify({ secret });

    const output = new PrometheusExporter(metrics).export();

    expect(output).toContain('# HELP sensitive_redactions_total Renderings of a redaction marker');
    expect(output).toContain('# TYPE sensitive_redactions_total counter');
    expect(seriesOf(output, 'sensitive_redactions_total')).toEqual([
      'sensitive_redactions_total{class="credential",surface="toJSON",label="api_key"} 1',
      'sensitive_redactions_total{class="credential",surface="toString",label="api_key"} 2',
    ]);
    expect(output.endsWith('\n')).toBe(true);
  });

  it('publishes every metric family with its headers before anything has happened', () => {
    const output = new PrometheusExporter(started()).export();

    expect(output).toContain('# TYPE sensitive_redactions_total counter');
    expect(output).toContain('# TYPE sensitive_reveals_total counter');
    expect(output).toContain('# TYPE sensitive_refusals_total counter');
    expect(seriesOf(output, 'sensitive_redactions_total')).toEqual([]);
  });

  it('applies the prefix and the default labels to every series', () => {
    const metrics = started();
    void String(new SensitiveString(CANARY, 'credential', 'api_key'));

    const output = new PrometheusExporter(metrics, {
      prefix: 'myapp_',
      defaultLabels: { service: 'payment-api', env: 'production' },
    }).export();

    expect(output).toContain('# TYPE myapp_sensitive_redactions_total counter');
    expect(output).toContain(
      'myapp_sensitive_redactions_total{env="production",service="payment-api",' +
        'class="credential",surface="toString",label="api_key"} 1'
    );
  });

  it('omits a dimension whose value is empty, the way Prometheus treats an absent label', () => {
    const metrics = started();
    void String(new SensitiveString(CANARY, 'credential'));

    expect(
      seriesOf(new PrometheusExporter(metrics).export(), 'sensitive_redactions_total')
    ).toEqual(['sensitive_redactions_total{class="credential",surface="toString"} 1']);
  });

  it('exposes the content type a scrape endpoint has to set', () => {
    expect(new PrometheusExporter(started()).contentType).toBe(PROMETHEUS_CONTENT_TYPE);
    expect(PROMETHEUS_CONTENT_TYPE).toBe('text/plain; version=0.0.4; charset=utf-8');
  });

  describe('escaping, which is the whole of the defence here', () => {
    // A label value is caller text. Unescaped, the value below closes the
    // brace, ends the line, and writes a metric of its own into the scrape.
    const INJECTION = 'k",surface="forged"} 99\nintruder_total{a="b';

    it('cannot forge a series through a label value', () => {
      const metrics = started();
      void String(new SensitiveString(CANARY, 'credential', INJECTION));

      const output = new PrometheusExporter(metrics).export();
      const lines = output.split('\n').filter((entry) => entry !== '');

      // The injected text is still *in* the output, escaped, inside the quotes
      // of one label. What matters is that it is not a line: every line is
      // either a comment or a series of a metric this exporter declared, so
      // the label value never became a metric of its own.
      expect(lines.some((line) => line.startsWith('intruder_total'))).toBe(false);
      expect(seriesOf(output, 'sensitive_redactions_total')).toHaveLength(1);

      for (const line of lines) {
        expect(line.startsWith('# ') || line.startsWith('sensitive_')).toBe(true);
      }
    });

    it('would forge a series without the escape, which is what makes the test above mean anything', () => {
      // The same value written into the format by hand, to show what the
      // escape prevents rather than asserting only that it did not happen.
      const forged = `sensitive_redactions_total{label="${INJECTION}"} 1`;

      expect(forged.split('\n').some((line) => line.startsWith('intruder_total'))).toBe(true);
    });

    it('escapes the three characters the format defines, and the carriage return too', () => {
      const metrics = started();
      void String(new SensitiveString(CANARY, 'credential', 'a\\b"c\nd\re'));

      expect(new PrometheusExporter(metrics).export()).toContain(String.raw`label="a\\b\"c\nd\re"`);
    });

    it('escapes a default label value the same way', () => {
      const output = new PrometheusExporter(started(), {
        defaultLabels: { env: 'a"b' },
      }).export();

      expect(output).toContain(String.raw`env="a\"b"`);
    });

    it('survives a label value that is a property of Object.prototype', () => {
      const metrics = started();

      void String(new SensitiveString(CANARY, 'credential', 'toString'));
      void String(new SensitiveString(CANARY, 'credential', '__proto__'));

      const output = new PrometheusExporter(metrics).export();

      expect(output).toContain('label="toString"} 1');
      expect(output).toContain('label="__proto__"} 1');

      // Asserted with `hasOwn` rather than against an object literal, because
      // `{ __proto__: 1 }` in a literal sets the prototype instead of creating
      // the key, so the obvious assertion here asserts nothing.
      const byLabel = metrics.getSnapshot().redactions.byLabel;

      expect(Object.hasOwn(byLabel, 'toString')).toBe(true);
      expect(Object.hasOwn(byLabel, '__proto__')).toBe(true);
      expect(Object.getPrototypeOf(byLabel)).toBe(Object.prototype);
      expect(Object.entries(byLabel).sort()).toEqual([
        ['__proto__', 1],
        ['toString', 1],
      ]);
    });
  });

  describe('configuration it refuses at construction rather than at the first scrape', () => {
    it.each(['my app_', '9myapp_', 'my-app_'])('refuses the prefix %o', (prefix) => {
      expect(() => new PrometheusExporter(started(), { prefix })).toThrow('not a legal start');
    });

    it('refuses a default label name the format would not accept', () => {
      expect(
        () => new PrometheusExporter(started(), { defaultLabels: { 'my-label': 'x' } })
      ).toThrow('not a legal label name');
    });

    it.each([...DIMENSION_NAMES])(
      "refuses a default label named '%s', which is one of the collector's dimensions",
      (name) => {
        // Not a cosmetic collision. A series carrying the same label name twice
        // is a scrape Prometheus rejects wholesale, so one such entry takes the
        // entire /metrics endpoint down rather than spoiling one row.
        expect(() => new PrometheusExporter(started(), { defaultLabels: { [name]: 'x' } })).toThrow(
          'may not set'
        );
      }
    );

    it('reserves every dimension the collector can actually emit, so the list cannot drift', () => {
      // The guard that makes the refusal above complete. A dimension added to
      // the collector without being added to DIMENSION_NAMES would be
      // shadowable, and this fails rather than waiting for a broken scrape.
      const metrics = started({ dimensions: ['label', 'context'] });
      const secret = new SensitiveString(CANARY, 'credential', 'key');

      void String(secret);
      metrics.withMeteredReveals({ name: 'payment' }, () => secret.reveal());
      metrics.recordRefusal(new RevokedSensitiveValueError('rotated', new Date(0), 'key'));

      const emitted = new Set(
        metrics
          .collect()
          .flatMap((family) => family.series.flatMap((series) => Object.keys(series.labels)))
      );

      expect([...emitted].filter((name) => !DIMENSION_NAMES.includes(name as never))).toEqual([]);
      expect(emitted.size).toBeGreaterThan(3);
    });

    it('refuses a default label value that is not a string', () => {
      expect(
        () => new PrometheusExporter(started(), { defaultLabels: { n: 1 as unknown as string } })
      ).toThrow('must be a string');
    });
  });

  it('reads the collector afresh on every export, holding no counts of its own', () => {
    const metrics = started();
    const exporter = new PrometheusExporter(metrics);

    expect(seriesOf(exporter.export(), 'sensitive_redactions_total')).toEqual([]);

    void String(new SensitiveString(CANARY, 'credential', 'api_key'));

    expect(seriesOf(exporter.export(), 'sensitive_redactions_total')).toHaveLength(1);
  });

  it('publishes the gauge only when the collector was asked for it', () => {
    expect(new PrometheusExporter(started()).export()).not.toContain('sensitive_values_tracked');
    expect(new PrometheusExporter(started({ trackInstances: true })).export()).toContain(
      '# TYPE sensitive_values_tracked gauge'
    );
  });
});
