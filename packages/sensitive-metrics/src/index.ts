/**
 * @platform-sec/sensitive-string-metrics
 *
 * Aggregated counts of what this library did, with no third-party dependency,
 * no OpenTelemetry, and nothing registered on the `SensitiveString` class.
 *
 * The first metric is `sensitive_redactions_total{class, label, surface}`, and
 * the order is the point. A reveal is the sanctioned path and is audited
 * already; a *redaction* is a place a plain string would have been written and
 * a marker went instead, and until core grew `observeRedactions()` nothing
 * counted it. That is the number a deployment is judged on, and it is the one
 * an enterprise can read before it has wrapped a single field: install the
 * sink side, scrape for a week, and the count says what the library would have
 * stopped.
 *
 * The three counters have three different coverages, which is the one thing to
 * understand before building a dashboard:
 *
 * | Counter | Source | Coverage |
 * |---|---|---|
 * | `sensitive_redactions_total` | core's `observeRedactions()` | every rendering in the process |
 * | `sensitive_reveals_total` | the `auditReveal` hook | only under a context carrying this collector |
 * | `sensitive_refusals_total` | `recordRefusal()` | only what your `catch` hands over |
 *
 * Do not divide one into another. A reveals-per-redaction ratio measures how
 * much of your code you wired up, not how your system behaves.
 *
 * @example
 * ```ts
 * import { createMetricsCollector, PrometheusExporter } from '@platform-sec/sensitive-string-metrics';
 *
 * const metrics = createMetricsCollector({ dimensions: ['label', 'context'] });
 * metrics.start();
 *
 * const exporter = new PrometheusExporter(metrics, { prefix: 'myapp_' });
 *
 * app.get('/metrics', (_req, res) => {
 *   res.set('Content-Type', exporter.contentType).send(exporter.export());
 * });
 * ```
 *
 * @packageDocumentation
 */

export { MetricsCollector, createMetricsCollector } from './collector.js';

export { PrometheusExporter, PROMETHEUS_CONTENT_TYPE } from './prometheus.js';
export type { PrometheusExporterConfig } from './prometheus.js';

export { StatsDExporter } from './statsd.js';
export type { StatsDExporterConfig } from './statsd.js';

// `DIMENSION_NAMES` is exported for the same reason `collect()` is public: a
// third exporter faces the shadowing problem the Prometheus one does, where a
// caller-configured label that collides with a dimension produces output the
// backend rejects rather than a row it merely misreads.
export { DIMENSION_NAMES, OVERFLOW_LABEL } from './types.js';
export type {
  Breakdown,
  CardinalityMode,
  MetricFamily,
  MetricSeries,
  MetricsCollectorConfig,
  MetricsSnapshot,
  OptionalDimension,
  RedactionFilter,
  ResolvedMetricsConfig,
  RevealFilter,
} from './types.js';
