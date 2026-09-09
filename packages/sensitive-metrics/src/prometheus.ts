import type { MetricsCollector } from './collector.js';
import { DIMENSION_NAMES } from './types.js';
import type { MetricFamily } from './types.js';

/**
 * The Prometheus text exposition format, version 0.0.4.
 *
 * The interesting part of this file is the escaping, and the reason is worth
 * stating plainly: one of the label values here is chosen by whoever wrapped
 * the value, and one is chosen by whoever named a reveal context. The format
 * is line-oriented and quote-delimited, so a label value carrying a newline or
 * a quote does not merely render oddly. It forges series:
 *
 * ```
 * new SensitiveString(token, 'credential', 'k",surface="x"} 99\nforged_total{a="b')
 * ```
 *
 * Unescaped, that one label closes the brace, terminates the line, and writes
 * a metric of its own into the scrape. Escaped, it is an ugly label value and
 * nothing else. The escape is the whole of the defence, so it happens in one
 * function that everything goes through.
 */

const NAME_PATTERN = /^[a-zA-Z_:][a-zA-Z0-9_:]*$/;
const PREFIX_PATTERN = /^[a-zA-Z_:][a-zA-Z0-9_:]*$/;
const LABEL_NAME_PATTERN = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

/** How a `/metrics` response must be typed for Prometheus to parse it. */
export const PROMETHEUS_CONTENT_TYPE = 'text/plain; version=0.0.4; charset=utf-8';

export interface PrometheusExporterConfig {
  /**
   * Prepended to every metric name, so `myapp_` yields
   * `myapp_sensitive_redactions_total`.
   *
   * Must be a legal start to a metric name. Validated at construction rather
   * than at scrape time: a malformed prefix produces a scrape a Prometheus
   * server rejects wholesale, and finding that out at the first scrape rather
   * than at boot is the wrong end of the deployment.
   */
  prefix?: string;

  /**
   * Labels added to every series, for the dimensions the process knows about
   * itself: which service this is, which environment, which region.
   *
   * A key here that collides with one of the metric's own dimensions is
   * refused at construction, since silently overwriting `class` would make a
   * dashboard read a lie.
   */
  defaultLabels?: Readonly<Record<string, string>>;
}

/**
 * Escape a label value for the exposition format.
 *
 * Backslash first, or the escapes introduced below would be re-escaped.
 * Prometheus defines exactly these three, and a carriage return is escaped as
 * well rather than left raw: it is not in the specification's list, and a bare
 * CR inside a quoted value is a parser difference waiting to be found.
 */
function escapeLabelValue(value: string): string {
  return value
    .replaceAll('\\', '\\\\')
    .replaceAll('"', '\\"')
    .replaceAll('\n', '\\n')
    .replaceAll('\r', '\\r');
}

/**
 * Render a number the way the format wants it.
 *
 * Every value here is a counter or a gauge holding an integer, so this is
 * mostly `String()`. The infinities and `NaN` are covered anyway, because a
 * counter that somehow reached one should produce a scrape Prometheus accepts
 * rather than one it rejects entirely.
 */
function formatValue(value: number): string {
  if (Number.isNaN(value)) {
    return 'NaN';
  }

  if (value === Infinity) {
    return '+Inf';
  }

  if (value === -Infinity) {
    return '-Inf';
  }

  return String(value);
}

/**
 * Escape the HELP text, which has its own two escapes and not the label ones.
 *
 * Every help string in this package is a literal written here, so this cannot
 * currently be reached with anything needing escaping. It exists so that stays
 * true by construction rather than by inspection.
 */
function escapeHelp(help: string): string {
  return help.replaceAll('\\', '\\\\').replaceAll('\n', '\\n');
}

/**
 * Renders a collector as a Prometheus scrape.
 *
 * Stateless: it holds no counts of its own and reads the collector on every
 * `export()`, so several exporters over one collector are free and a scrape
 * that fails changes nothing.
 *
 * @example
 * ```ts
 * const exporter = new PrometheusExporter(metrics, {
 *   prefix: 'myapp_',
 *   defaultLabels: { service: 'payment-api', env: process.env.NODE_ENV ?? 'unknown' },
 * });
 *
 * app.get('/metrics', (_req, res) => {
 *   res.set('Content-Type', exporter.contentType).send(exporter.export());
 * });
 * ```
 */
export class PrometheusExporter {
  readonly contentType = PROMETHEUS_CONTENT_TYPE;

  readonly #collector: MetricsCollector;
  readonly #prefix: string;
  readonly #defaultLabels: readonly (readonly [string, string])[];

  constructor(collector: MetricsCollector, config: PrometheusExporterConfig = {}) {
    const prefix = config.prefix ?? '';

    if (prefix !== '' && !PREFIX_PATTERN.test(prefix)) {
      throw new TypeError(
        `PrometheusExporter: prefix '${prefix}' is not a legal start to a metric name. ` +
          'A metric name matches [a-zA-Z_:][a-zA-Z0-9_:]*.'
      );
    }

    // Read off the shared list rather than written out here. A dimension
    // missing from this set is not a cosmetic collision: a series carrying the
    // same label name twice is a scrape Prometheus rejects entirely, so one
    // `defaultLabels` entry would take the whole endpoint down.
    const reserved: ReadonlySet<string> = new Set<string>(DIMENSION_NAMES);
    const defaults: (readonly [string, string])[] = [];

    for (const [name, value] of Object.entries(config.defaultLabels ?? {})) {
      if (!LABEL_NAME_PATTERN.test(name)) {
        throw new TypeError(
          `PrometheusExporter: '${name}' is not a legal label name. ` +
            'A label name matches [a-zA-Z_][a-zA-Z0-9_]*.'
        );
      }

      if (reserved.has(name)) {
        throw new TypeError(
          `PrometheusExporter: defaultLabels may not set '${name}', which is one of the ` +
            'dimensions the collector records. Overwriting it would make every series say ' +
            'something the collector did not measure.'
        );
      }

      if (typeof value !== 'string') {
        throw new TypeError(
          `PrometheusExporter: defaultLabels.${name} must be a string, received ${typeof value}`
        );
      }

      defaults.push([name, escapeLabelValue(value)]);
    }

    // Sorted so the rendered label set is stable regardless of insertion order.
    defaults.sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));

    this.#collector = collector;
    this.#prefix = prefix;
    this.#defaultLabels = defaults;
  }

  /**
   * The whole scrape, ending in a newline.
   *
   * A metric with no series still gets its `# HELP` and `# TYPE`. That is what
   * makes the measurement-first deployment legible: a process that has
   * installed this library and wrapped nothing yet scrapes a zero rather than
   * scraping nothing, and a dashboard built on it shows an empty panel rather
   * than a broken query.
   */
  export(): string {
    const lines: string[] = [];

    for (const family of this.#collector.collect()) {
      this.#renderFamily(family, lines);
    }

    return `${lines.join('\n')}\n`;
  }

  #renderFamily(family: MetricFamily, lines: string[]): void {
    const name = `${this.#prefix}${family.name}`;

    // Belt and braces against a future metric name and a validated prefix
    // combining into something illegal.
    if (!NAME_PATTERN.test(name)) {
      throw new TypeError(`PrometheusExporter: '${name}' is not a legal metric name`);
    }

    lines.push(`# HELP ${name} ${escapeHelp(family.help)}`);
    lines.push(`# TYPE ${name} ${family.type}`);

    for (const series of family.series) {
      const rendered = [
        ...this.#defaultLabels.map(([key, value]) => `${key}="${value}"`),
        ...Object.entries(series.labels)
          .filter(([, value]) => value !== '')
          .map(([key, value]) => `${key}="${escapeLabelValue(value)}"`),
      ];

      const labels = rendered.length === 0 ? '' : `{${rendered.join(',')}}`;

      lines.push(`${name}${labels} ${formatValue(series.value)}`);
    }
  }
}
