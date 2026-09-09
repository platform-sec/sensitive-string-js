import {
  SensitiveStringError,
  createChildContext,
  getCurrentRevealContext,
  observeRedactions,
  trackedInstanceCount,
  withRevealContext,
} from '@platform-sec/sensitive-string-core';
import type {
  AuditContext,
  ISensitiveString,
  RedactionEvent,
  RevealContext,
  RevealDetails,
  SensitivityClass,
} from '@platform-sec/sensitive-string-core';
import { BoundedCounter } from './series.js';
import type { IncrementOutcome } from './series.js';
import type {
  CardinalityMode,
  MetricFamily,
  MetricsCollectorConfig,
  MetricsSnapshot,
  OptionalDimension,
  RedactionFilter,
  ResolvedMetricsConfig,
  RevealFilter,
} from './types.js';

/**
 * The three counters, and what each one is actually able to see.
 *
 * `sensitive_redactions_total` comes from core's `observeRedactions()`. It has
 * complete coverage of the process from {@link MetricsCollector.start} onward,
 * needs no wiring at any call site, and counts the thing this library exists to
 * do: every rendering of a marker is a place a plain string would have been
 * written.
 *
 * `sensitive_reveals_total` comes from the audit hook, so it counts an
 * operation only where a context carrying this collector's hook was in force.
 * That is not a gap to be closed later. Core delivers an audit record through
 * the context an operation ran under and nowhere else, deliberately, so a
 * reveal made under no context is invisible here by construction.
 *
 * `sensitive_refusals_total` counts only what a caller hands to
 * {@link MetricsCollector.recordRefusal}. A refusal leaves the library by
 * throwing, before the audit hook and before anything is charged, precisely so
 * a denied read is not logged as a reveal. There is no hook on that path and
 * this package does not invent one.
 *
 * Divide none of these into the others. They have three different coverages,
 * and a ratio between two of them measures the wiring rather than the system.
 */

/** Fixed by the library, so a fold never has to touch them. */
const REDACTION_DIMENSIONS = ['class', 'surface'] as const;
const REVEAL_DIMENSIONS = ['class', 'operation'] as const;
const REFUSAL_DIMENSIONS = ['class'] as const;

/**
 * The dimensions whose values a caller chooses, and so the ones a fold takes.
 *
 * `code` is here beside the two obvious ones because a caller may hand
 * `recordRefusal` an error of its own: `SensitiveStringError` is exported and
 * extensible, and a subclass may carry any code it likes.
 */
const FOLDABLE = new Set(['label', 'context', 'code']);

/**
 * How long a caller-supplied dimension value may be before it is truncated.
 *
 * The cardinality cap bounds how many series a counter holds and says nothing
 * about how large one is, so without this the collector's memory, and every
 * scrape it produces, is bounded only by how long a caller's labels are. An
 * application labelling values with a serialized request would produce a
 * megabyte-scale `/metrics` response from a thousand perfectly legal series.
 *
 * Truncation happens here, at ingest, and deliberately not in an exporter.
 * A truncated value is then the series' identity, so two labels sharing a
 * prefix become one series everywhere and the two exporters agree. Truncating
 * in the Prometheus exporter instead would render two distinct series with
 * identical label sets, which is a duplicate series and a scrape the server
 * rejects outright.
 *
 * Matches the StatsD tag cap, so a dimension is never shortened twice.
 */
const MAX_DIMENSION_LENGTH = 200;

/** Anything else arriving as an `operation` is folded to this. */
const UNKNOWN_OPERATION = 'unknown';

/** The class recorded for a refusal that names none and where the caller passed none. */
const UNKNOWN_CLASS = 'unknown';

const VALID_DIMENSIONS: readonly OptionalDimension[] = ['label', 'context'];
const VALID_MODES: readonly CardinalityMode[] = ['aggregate', 'drop', 'warn'];

/**
 * The operations core audits, as of core 0.5.0.
 *
 * Validated rather than trusted so `operation` stays a dimension the library
 * bounds: the hook is a public function and a caller can invoke it directly
 * with anything. An unrecognised operation is recorded, under
 * {@link UNKNOWN_OPERATION}, rather than dropped, because a core release that
 * adds a ninth operation should show up in the metric as an unknown rather
 * than vanish from the total.
 */
const KNOWN_OPERATIONS: ReadonlySet<string> = new Set([
  'reveal',
  'mask',
  'hash',
  'hmac',
  'renew',
  'revoke',
  'clear',
  'worker-handoff',
]);

/**
 * A caller-supplied dimension value, cut to a length a metrics store can hold.
 *
 * Not defensive typing: `value` is annotated as a string and arrives as one
 * from core, but a label is whatever a caller passed to the constructor and
 * core does not check its type, so the `.length` read has to be the thing that
 * throws into the recording guard rather than something further downstream.
 */
function bounded(value: string): string {
  return value.length > MAX_DIMENSION_LENGTH ? value.slice(0, MAX_DIMENSION_LENGTH) : value;
}

function describeType(value: unknown): string {
  return value === null ? 'null' : typeof value;
}

function requireBoolean(value: unknown, name: string, fallback: boolean): boolean {
  if (value === undefined) {
    return fallback;
  }

  if (typeof value !== 'boolean') {
    throw new TypeError(
      `createMetricsCollector: ${name} must be a boolean, received ${describeType(value)}`
    );
  }

  return value;
}

function resolveConfig(config: MetricsCollectorConfig): ResolvedMetricsConfig {
  const { dimensions, maxSeries, onCardinalityExceeded } = config;

  let resolvedDimensions: readonly OptionalDimension[] = ['label'];

  if (dimensions !== undefined) {
    if (!Array.isArray(dimensions)) {
      throw new TypeError(
        `createMetricsCollector: dimensions must be an array, received ${describeType(dimensions)}`
      );
    }

    // `Array.isArray` widens to `any[]`, so the entries are treated as unknown
    // from here on and narrowed by the check rather than by the declaration.
    const candidates: readonly unknown[] = dimensions;

    for (const dimension of candidates) {
      if (!VALID_DIMENSIONS.includes(dimension as OptionalDimension)) {
        throw new TypeError(
          `createMetricsCollector: unknown dimension '${String(dimension)}'. The configurable ` +
            `dimensions are ${VALID_DIMENSIONS.join(' and ')}; class, surface, operation and code ` +
            'are always recorded because the library bounds them.'
        );
      }
    }

    resolvedDimensions = [...new Set(candidates as readonly OptionalDimension[])];
  }

  if (maxSeries !== undefined) {
    if (typeof maxSeries !== 'number' || !Number.isInteger(maxSeries) || maxSeries < 1) {
      throw new TypeError(
        `createMetricsCollector: maxSeries must be a positive integer, received ${String(maxSeries)}`
      );
    }
  }

  if (onCardinalityExceeded !== undefined && !VALID_MODES.includes(onCardinalityExceeded)) {
    throw new TypeError(
      `createMetricsCollector: onCardinalityExceeded must be one of ${VALID_MODES.join(', ')}, ` +
        `received '${String(onCardinalityExceeded)}'`
    );
  }

  return Object.freeze({
    trackRedactions: requireBoolean(config.trackRedactions, 'trackRedactions', true),
    trackReveals: requireBoolean(config.trackReveals, 'trackReveals', true),
    trackRefusals: requireBoolean(config.trackRefusals, 'trackRefusals', true),
    trackInstances: requireBoolean(config.trackInstances, 'trackInstances', false),
    dimensions: Object.freeze(resolvedDimensions),
    maxSeries: maxSeries ?? 1000,
    onCardinalityExceeded: onCardinalityExceeded ?? 'aggregate',
  });
}

/**
 * Aggregated counts of what this library did, with no third-party dependency
 * and nothing registered on the `SensitiveString` class.
 *
 * A collector is a subscriber, not a singleton. Core has no idea it exists,
 * which is what lets a process run this collector and an OpenTelemetry
 * exporter side by side, each subscribing for itself, neither knowing about
 * the other. Rule R6 therefore does not apply to it: there is no
 * process-global collector to be reconfigured behind your back, and two
 * collectors in one process are two independent sets of numbers rather than a
 * conflict.
 *
 * Nothing here ever throws at a recording site. A redaction is a log line, and
 * a log line that can fail because a dashboard is misconfigured is worse than
 * no dashboard. Core already swallows a throwing redaction observer; the audit
 * hook is the path core does *not* protect, since a hook that throws stops the
 * reveal, so this collector wraps its own body and counts what it swallowed
 * under `meta.recordingErrors`.
 *
 * @example
 * ```ts
 * const metrics = createMetricsCollector({ dimensions: ['label', 'context'] });
 * metrics.start();
 *
 * app.get('/metrics', (_req, res) => {
 *   const exporter = new PrometheusExporter(metrics, { prefix: 'myapp_' });
 *   res.set('Content-Type', exporter.contentType).send(exporter.export());
 * });
 * ```
 */
export class MetricsCollector {
  readonly config: ResolvedMetricsConfig;

  readonly #redactions: BoundedCounter;
  readonly #reveals: BoundedCounter;
  readonly #refusals: BoundedCounter;

  #unsubscribe: (() => void) | undefined;
  #aggregated = 0;
  #dropped = 0;
  #recordingErrors = 0;

  constructor(config: MetricsCollectorConfig = {}) {
    if (typeof config !== 'object' || config === null) {
      throw new TypeError(
        `createMetricsCollector expects a configuration object; received ${describeType(config)}`
      );
    }

    this.config = resolveConfig(config);

    const { dimensions, maxSeries, onCardinalityExceeded: mode } = this.config;
    const withLabel = dimensions.includes('label') ? (['label'] as const) : [];
    const withContext = dimensions.includes('context') ? (['context'] as const) : [];
    const shared = { foldable: FOLDABLE, maxSeries, mode };

    this.#redactions = new BoundedCounter({
      ...shared,
      name: 'sensitive_redactions_total',
      help:
        'Renderings of a redaction marker, by the surface that rendered it. Each one is a ' +
        'place a plain string would have been written.',
      dimensions: [...REDACTION_DIMENSIONS, ...withLabel],
    });

    this.#reveals = new BoundedCounter({
      ...shared,
      name: 'sensitive_reveals_total',
      help:
        'Audited operations on a sensitive value, by operation. Counts only what ran under a ' +
        'reveal context carrying this collector as its auditReveal hook.',
      dimensions: [...REVEAL_DIMENSIONS, ...withLabel, ...withContext],
    });

    this.#refusals = new BoundedCounter({
      ...shared,
      name: 'sensitive_refusals_total',
      help:
        'Refusals reported to recordRefusal(), by error code. Counts only what the calling ' +
        'code hands over; the library raises these by throwing and fires no hook.',
      dimensions: [...REFUSAL_DIMENSIONS, 'code', ...withLabel],
    });
  }

  /** Whether {@link start} has run and {@link stop} has not. */
  get started(): boolean {
    return this.#unsubscribe !== undefined;
  }

  /**
   * Subscribe to core's redaction stream, and return the function that stops.
   *
   * Idempotent: calling it again while already started subscribes nothing
   * further and returns a function that stops the one subscription there is.
   * Only the redaction counter needs this; the reveal counter is wired by
   * installing {@link auditReveal} on a context, and the refusal counter by
   * calling {@link recordRefusal}.
   *
   * With `trackRedactions: false` this records the started state and
   * subscribes nothing, so an exporter still reports the other counters.
   */
  start(): () => void {
    const stop = (): void => {
      this.stop();
    };

    if (this.#unsubscribe !== undefined) {
      return stop;
    }

    this.#unsubscribe = this.config.trackRedactions
      ? observeRedactions((event) => {
          this.#recordRedaction(event);
        })
      : () => {
          /* nothing was subscribed */
        };

    return stop;
  }

  /** Unsubscribe from the redaction stream. The counts already taken are kept. */
  stop(): void {
    const unsubscribe = this.#unsubscribe;
    this.#unsubscribe = undefined;
    unsubscribe?.();
  }

  /**
   * The audit hook to install on a reveal context, as `auditReveal`.
   *
   * Prefer {@link meteredContext} or {@link withMeteredReveals}, which chain
   * onto the hook already in force. Assigning this one directly into a context
   * object replaces any ambient `auditReveal` for everything inside that scope,
   * so an application that installed an audit logger higher up silently loses
   * it, and a metrics counter is a poor trade for an audit log.
   *
   * Bound, so it can be passed as a value. It reads `klass` and `label` off the
   * value and nothing else: this runs inside core's raw-value gate, which is
   * not reentrant, and reading the value from here recurses until the stack is
   * exhausted.
   */
  readonly auditReveal = (
    value: ISensitiveString,
    details: RevealDetails,
    context: AuditContext
  ): void => {
    if (!this.config.trackReveals) {
      return;
    }

    try {
      const operation = KNOWN_OPERATIONS.has(details.operation)
        ? details.operation
        : UNKNOWN_OPERATION;
      const values: string[] = [value.klass, operation];

      if (this.config.dimensions.includes('label')) {
        values.push(bounded(value.label ?? ''));
      }

      if (this.config.dimensions.includes('context')) {
        values.push(bounded(context.name));
      }

      this.#account(this.#reveals.inc(values));
    } catch {
      this.#recordingErrors++;
    }
  };

  /**
   * A reveal context that counts, without dropping the hook already in force.
   *
   * `withRevealContext({ name, auditReveal: metrics.auditReveal }, fn)` looks
   * equivalent and is not: a context replaces the ambient one wholesale, so
   * that call silently unsubscribes whatever audit sink the application
   * installed further up the stack. This builds the context through
   * `createChildContext`, inherits the ambient tags, and chains the hooks so
   * every one of them runs.
   *
   * Order matters and is deliberate: the inherited hook runs first, then any
   * hook passed in `overrides`, then the counter. A hook that throws stops the
   * reveal, so counting last means a reveal an audit sink refused is not
   * counted as one that happened.
   */
  meteredContext(overrides: Partial<RevealContext> & { name: string }): RevealContext {
    // Both hooks are called through the object they were declared on rather
    // than extracted first. `auditReveal` is a method in `RevealContext`, and
    // core invokes it as `ctx.auditReveal(...)`, so a sink written as a method
    // that reads `this` works there. Pulling the function out would call it
    // with `this` undefined and break exactly that sink, quietly, on the path
    // meant to preserve it.
    const inherited = getCurrentRevealContext();
    const count = this.auditReveal;
    const child = createChildContext(overrides);

    return {
      ...child,
      auditReveal(value: ISensitiveString, details: RevealDetails, context: AuditContext): void {
        inherited?.auditReveal?.(value, details, context);
        overrides.auditReveal?.(value, details, context);
        count(value, details, context);
      },
    };
  }

  /** Run `fn` under a {@link meteredContext}. */
  withMeteredReveals<T>(overrides: Partial<RevealContext> & { name: string }, fn: () => T): T {
    const context = this.meteredContext(overrides);
    return withRevealContext(context, fn);
  }

  /**
   * Count a refusal this library raised.
   *
   * Anything that is not a `SensitiveStringError` is ignored and reported as
   * `false`, so this can sit in a `catch` that also sees ordinary application
   * errors without polluting the metric with them.
   *
   * The class is read off the error when it carries one and taken from `klass`
   * otherwise; a refusal with neither is recorded under `'unknown'` rather than
   * dropped, since the code is the useful half. The code itself is safe to
   * record: core documents it as a stable, greppable slug that never carries a
   * value.
   *
   * @returns Whether the error was recognised and counted.
   *
   * @example
   * ```ts
   * try {
   *   return token.reveal(ctx);
   * } catch (error) {
   *   metrics.recordRefusal(error, 'credential');
   *   throw error;
   * }
   * ```
   */
  recordRefusal(error: unknown, klass?: SensitivityClass): boolean {
    if (!this.config.trackRefusals || !(error instanceof SensitiveStringError)) {
      return false;
    }

    try {
      const carried = (error as { klass?: unknown }).klass;
      const values: string[] = [
        typeof carried === 'string' ? carried : (klass ?? UNKNOWN_CLASS),
        error.code,
      ];

      if (this.config.dimensions.includes('label')) {
        const label = (error as { label?: unknown }).label;
        values.push(typeof label === 'string' ? bounded(label) : '');
      }

      this.#account(this.#refusals.inc(values));
      return true;
    } catch {
      this.#recordingErrors++;
      return false;
    }
  }

  /**
   * Run `fn`, counting any refusal it raises, and rethrow unchanged.
   *
   * The error keeps its identity, its stack and its type: this is a tee, not a
   * handler.
   */
  meterRefusals<T>(fn: () => T, klass?: SensitivityClass): T {
    try {
      return fn();
    } catch (error) {
      this.recordRefusal(error, klass);
      throw error;
    }
  }

  /** Every metric and its series, which is the whole seam an exporter needs. */
  collect(): readonly MetricFamily[] {
    const families: MetricFamily[] = [
      {
        name: this.#redactions.name,
        help: this.#redactions.help,
        type: 'counter',
        series: this.#redactions.collect(),
      },
      {
        name: this.#reveals.name,
        help: this.#reveals.help,
        type: 'counter',
        series: this.#reveals.collect(),
      },
      {
        name: this.#refusals.name,
        help: this.#refusals.help,
        type: 'counter',
        series: this.#refusals.collect(),
      },
      {
        name: 'sensitive_metrics_events_aggregated_total',
        help: 'Events whose caller-supplied dimensions were folded away by the cardinality cap.',
        type: 'counter',
        series: [{ labels: {}, value: this.#aggregated }],
      },
      {
        name: 'sensitive_metrics_events_dropped_total',
        help: 'Events not counted at all, because of the cardinality cap.',
        type: 'counter',
        series: [{ labels: {}, value: this.#dropped }],
      },
      {
        name: 'sensitive_metrics_recording_errors_total',
        help: 'Recording attempts that threw and were swallowed. Should be zero.',
        type: 'counter',
        series: [{ labels: {}, value: this.#recordingErrors }],
      },
    ];

    if (this.config.trackInstances) {
      families.push({
        name: 'sensitive_values_tracked',
        help:
          'Instances in core memory hygiene registry. A ceiling, not a census: it lags ' +
          'collection by an unbounded amount, and is 0 unless trackInstances is on in core too.',
        type: 'gauge',
        series: [{ labels: {}, value: trackedInstanceCount() }],
      });
    }

    return families;
  }

  /** The counts as plain JSON, for code that wants them without an exporter. */
  getSnapshot(): MetricsSnapshot {
    return {
      redactions: {
        total: this.#redactions.total(),
        byClass: this.#redactions.breakdown('class'),
        bySurface: this.#redactions.breakdown('surface'),
        byLabel: this.#redactions.breakdown('label'),
      },
      reveals: {
        total: this.#reveals.total(),
        byClass: this.#reveals.breakdown('class'),
        byOperation: this.#reveals.breakdown('operation'),
        byLabel: this.#reveals.breakdown('label'),
        byContext: this.#reveals.breakdown('context'),
      },
      refusals: {
        total: this.#refusals.total(),
        byClass: this.#refusals.breakdown('class'),
        byCode: this.#refusals.breakdown('code'),
        byLabel: this.#refusals.breakdown('label'),
      },
      valuesTracked: this.config.trackInstances ? trackedInstanceCount() : null,
      meta: {
        started: this.started,
        eventsAggregated: this.#aggregated,
        eventsDropped: this.#dropped,
        recordingErrors: this.#recordingErrors,
      },
    };
  }

  /** Redactions matching every field the filter sets. */
  getRedactionCount(filter: RedactionFilter = {}): number {
    return this.#redactions.total({
      class: filter.klass,
      label: filter.label,
      surface: filter.surface,
    });
  }

  /** Audited operations matching every field the filter sets. */
  getRevealCount(filter: RevealFilter = {}): number {
    return this.#reveals.total({
      class: filter.klass,
      label: filter.label,
      operation: filter.operation,
      context: filter.context,
    });
  }

  /**
   * Refusals matching every field the filter sets.
   *
   * `klass` accepts `'unknown'` as well as a real class, because a refusal that
   * names no class and was reported without one is recorded under that.
   */
  getRefusalCount(
    filter: { klass?: SensitivityClass | 'unknown'; code?: string; label?: string } = {}
  ): number {
    return this.#refusals.total({
      class: filter.klass,
      code: filter.code,
      label: filter.label,
    });
  }

  /**
   * Discard every count, keeping the subscription and the configuration.
   *
   * For tests. A running process that resets its counters gives a scraper a
   * counter that went backwards, which every Prometheus rate function reads as
   * a process restart.
   */
  reset(): void {
    this.#redactions.clear();
    this.#reveals.clear();
    this.#refusals.clear();
    this.#aggregated = 0;
    this.#dropped = 0;
    this.#recordingErrors = 0;
  }

  #recordRedaction(event: RedactionEvent): void {
    // Core swallows a throw from here and warns once, which would leave the
    // collector's own accounting silently wrong rather than merely
    // incomplete. Counting it is what makes meta.recordingErrors readable.
    try {
      const values: string[] = [event.klass, event.surface];

      if (this.config.dimensions.includes('label')) {
        values.push(bounded(event.label ?? ''));
      }

      this.#account(this.#redactions.inc(values));
    } catch {
      this.#recordingErrors++;
    }
  }

  #account(outcome: IncrementOutcome): void {
    if (outcome === 'aggregated') {
      this.#aggregated++;
    } else if (outcome === 'dropped') {
      this.#dropped++;
    }
  }
}

/**
 * Build a collector.
 *
 * @throws TypeError If the configuration, or one of its fields, has the wrong type.
 */
export function createMetricsCollector(config: MetricsCollectorConfig = {}): MetricsCollector {
  return new MetricsCollector(config);
}
