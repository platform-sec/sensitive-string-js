import type { RedactionSurface, SensitivityClass } from '@platform-sec/sensitive-string-core';

/**
 * The two dimensions whose values this library does not choose.
 *
 * `label` is whatever the wrapping code passed to the constructor, and
 * `context` is the `name` of the reveal context the operation ran under. Both
 * are free-form caller text, both reach a time-series database that keeps them
 * for months, and a series is created per distinct value. That is why they are
 * the configurable ones and the rest are not.
 *
 * `class`, `surface`, `operation` and `code` are always present. They are
 * bounded by the library, and the surface in particular is not a detail: a
 * `toString` rendering is either a prevented log line or an outbound request
 * that carried the marker, and a `structure` rendering is a sink that
 * installed redaction. A dashboard that collapses them misreads both.
 */
export type OptionalDimension = 'label' | 'context';

/**
 * Every dimension name a collector can put on a series.
 *
 * One list, read by the collector that emits them and by the exporters that
 * must not let a caller collide with one. A Prometheus series carrying the same
 * label name twice is not a bad row, it is a scrape the server rejects
 * wholesale, so a `defaultLabels` entry that shadows a dimension takes the
 * whole `/metrics` endpoint down. `metrics-security.test.ts` asserts that
 * nothing the collector emits is missing from this list.
 */
export const DIMENSION_NAMES = [
  'class',
  'label',
  'surface',
  'operation',
  'code',
  'context',
] as const;

/** What to do with an event whose series would exceed {@link MetricsCollectorConfig.maxSeries}. */
export type CardinalityMode = 'aggregate' | 'drop' | 'warn';

/**
 * The label value that stands in for a folded dimension.
 *
 * Chosen to be a legal Prometheus label value and conspicuous in a dashboard:
 * a panel showing a large `__other__` slice is telling you the cap is doing
 * work, which is the only way to notice from the outside.
 */
export const OVERFLOW_LABEL = '__other__';

/** How a collector is configured. Every field has a default; the object may be omitted entirely. */
export interface MetricsCollectorConfig {
  /**
   * Count every rendering of a redaction marker, through core's
   * `observeRedactions()`. Default `true`.
   *
   * This is the one source with complete coverage: it sees every rendering in
   * the process from the moment {@link MetricsCollector.start} runs, with no
   * per-call-site wiring.
   */
  trackRedactions?: boolean;

  /**
   * Count audited operations through {@link MetricsCollector.auditReveal}.
   * Default `true`.
   *
   * Coverage is *not* complete and cannot be: core delivers an audit record to
   * the hook on the context an operation ran under, so a reveal made outside
   * any context, or under one that does not carry this collector's hook, is
   * not counted. See the README on why the two counters must not be divided
   * into one another.
   */
  trackReveals?: boolean;

  /**
   * Count refusals reported through {@link MetricsCollector.recordRefusal}.
   * Default `true`.
   *
   * A refusal throws out of the library before any hook fires, by design: a
   * denied read is not a reveal and must not be logged as one. So there is no
   * emission point for it, and this counter only sees what a caller hands it.
   */
  trackRefusals?: boolean;

  /**
   * Publish `sensitive_values_tracked` from core's memory hygiene registry.
   * Default `false`.
   *
   * Reads `trackedInstanceCount()`, which is `0` unless the process also ran
   * `setMemoryHygiene({ trackInstances: true })`, and which lags collection by
   * an unbounded amount. Turning this on without turning tracking on publishes
   * a flat zero, which is worse than publishing nothing.
   */
  trackInstances?: boolean;

  /**
   * Which caller-supplied dimensions to record. Default `['label']`.
   *
   * `'context'` is off by default because a context name is free-form text
   * chosen at the call site, and a metrics store is a durable, widely readable
   * place for it to end up. Turn it on once you know what your context names
   * are; it is the dimension that makes the reveal counter worth reading.
   */
  dimensions?: readonly OptionalDimension[];

  /**
   * Distinct series each counter may hold before folding starts.
   * Default `1000`.
   */
  maxSeries?: number;

  /**
   * What happens to an event once `maxSeries` is reached. Default `'aggregate'`.
   *
   * - `'aggregate'`: the caller-supplied dimensions are replaced with
   *   {@link OVERFLOW_LABEL} and the event is counted there, so the total
   *   stays right and only the breakdown is lost.
   * - `'drop'`: the event is not counted at all, and
   *   `sensitive_metrics_events_dropped_total` records how many. Totals go
   *   wrong; use it only where a wrong total is better than a wrong breakdown.
   * - `'warn'`: `'aggregate'`, plus one `process.emitWarning` per counter the
   *   first time it folds.
   */
  onCardinalityExceeded?: CardinalityMode;
}

/** A configuration with every default resolved, as {@link MetricsCollector.config} reports it. */
export interface ResolvedMetricsConfig {
  readonly trackRedactions: boolean;
  readonly trackReveals: boolean;
  readonly trackRefusals: boolean;
  readonly trackInstances: boolean;
  readonly dimensions: readonly OptionalDimension[];
  readonly maxSeries: number;
  readonly onCardinalityExceeded: CardinalityMode;
}

/** One labelled value inside a {@link MetricFamily}. */
export interface MetricSeries {
  readonly labels: Readonly<Record<string, string>>;
  readonly value: number;
}

/**
 * One metric and every series under it, which is what an exporter consumes.
 *
 * The seam between collection and export is this shape and nothing else, so a
 * fourth exporter needs no access to the collector's internals.
 */
export interface MetricFamily {
  /** Without any exporter prefix. */
  readonly name: string;
  readonly help: string;
  readonly type: 'counter' | 'gauge';
  readonly series: readonly MetricSeries[];
}

/** A counter's totals broken down one dimension at a time. */
export type Breakdown = Readonly<Record<string, number>>;

/**
 * The programmatic view, for code that wants the numbers without an exporter.
 *
 * Plain JSON: every value is a number or a string, so it survives
 * `JSON.stringify` and a structured log line unchanged.
 */
export interface MetricsSnapshot {
  readonly redactions: {
    readonly total: number;
    readonly byClass: Breakdown;
    readonly bySurface: Breakdown;
    readonly byLabel: Breakdown;
  };
  readonly reveals: {
    readonly total: number;
    readonly byClass: Breakdown;
    readonly byOperation: Breakdown;
    readonly byLabel: Breakdown;
    readonly byContext: Breakdown;
  };
  readonly refusals: {
    readonly total: number;
    readonly byClass: Breakdown;
    readonly byCode: Breakdown;
    /** Empty unless `label` is one of the configured dimensions. */
    readonly byLabel: Breakdown;
  };
  /**
   * `sensitive_values_tracked`, or `null` when `trackInstances` is off.
   *
   * A ceiling rather than a count, for the reasons on core's
   * `trackedInstanceCount()`.
   */
  readonly valuesTracked: number | null;
  /** What the collector itself did, so the numbers above can be trusted or not. */
  readonly meta: {
    /** Whether {@link MetricsCollector.start} has run and not been stopped. */
    readonly started: boolean;
    /** Events folded into an {@link OVERFLOW_LABEL} series by the cardinality cap. */
    readonly eventsAggregated: number;
    /** Events not counted at all, under `onCardinalityExceeded: 'drop'` or the hard ceiling. */
    readonly eventsDropped: number;
    /** Recording attempts that threw and were swallowed. Should be zero. */
    readonly recordingErrors: number;
  };
}

/** A filter for the counting queries on {@link MetricsCollector}. */
export interface RedactionFilter {
  klass?: SensitivityClass;
  label?: string;
  surface?: RedactionSurface;
}

/** A filter for {@link MetricsCollector.getRevealCount}. */
export interface RevealFilter {
  klass?: SensitivityClass;
  label?: string;
  operation?: string;
  context?: string;
}
