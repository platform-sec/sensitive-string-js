import type { CardinalityMode, MetricSeries } from './types.js';
import { OVERFLOW_LABEL } from './types.js';

/**
 * A counter whose series count cannot grow without bound, which is the whole
 * of INV-MET-002.
 *
 * Two of the dimensions this library records carry caller-supplied text: the
 * label a value was wrapped with, and the name of the context an operation ran
 * under. Neither is chosen by the library, and a metrics store creates a
 * series per distinct value of each, so an application that labels a value
 * with a user id turns a counter into a table of its users. The cap is what
 * stands between that and a time-series database.
 *
 * Folding rather than dropping is the default because a fold keeps the total
 * right. `sensitive_redactions_total` summed across a folded breakdown is the
 * same number it would have been; only the split by label is lost, and it is
 * lost visibly, into a series named {@link OVERFLOW_LABEL}.
 *
 * The bound has two parts. `maxSeries` limits distinct series admitted
 * normally. Folded series are admitted past it, since the point of a fold is
 * that it has somewhere to go, and they are bounded in turn by the number of
 * distinct combinations of the dimensions that do *not* fold, which the
 * library chooses. A hard ceiling of twice `maxSeries` sits under both, so the
 * bound holds even for a caller that hand-feeds `recordRefusal` with an error
 * class of its own carrying arbitrary codes.
 */

interface MutableSeries {
  readonly labels: Readonly<Record<string, string>>;
  value: number;
}

/** How an increment was accounted for, which the collector rolls into its meta counters. */
export type IncrementOutcome = 'recorded' | 'aggregated' | 'dropped';

export interface BoundedCounterOptions {
  readonly name: string;
  readonly help: string;
  /** In the order values are passed to {@link BoundedCounter.inc}. */
  readonly dimensions: readonly string[];
  /** Dimensions replaced by {@link OVERFLOW_LABEL} when the cap is reached. */
  readonly foldable: ReadonlySet<string>;
  readonly maxSeries: number;
  readonly mode: CardinalityMode;
}

/**
 * A series key that cannot collide, whatever the label values contain.
 *
 * Length-prefixed rather than joined on a separator. Every printable
 * separator, and every control character too, is a legal Prometheus label
 * value, so any join at all lets one caller's label forge another tuple's key:
 * with a comma, `{label: 'a,b'}` and `{label: 'a', context: 'b'}` are the same
 * string. A length prefix has no such reading.
 */
function seriesKey(values: readonly string[]): string {
  let key = '';

  for (const value of values) {
    key += `${String(value.length)}:${value}|`;
  }

  return key;
}

export class BoundedCounter {
  readonly name: string;
  readonly help: string;
  readonly dimensions: readonly string[];

  readonly #foldable: readonly boolean[];
  readonly #maxSeries: number;
  readonly #ceiling: number;
  readonly #mode: CardinalityMode;
  readonly #series = new Map<string, MutableSeries>();

  #warned = false;

  constructor(options: BoundedCounterOptions) {
    this.name = options.name;
    this.help = options.help;
    this.dimensions = options.dimensions;
    this.#foldable = options.dimensions.map((dimension) => options.foldable.has(dimension));
    this.#maxSeries = options.maxSeries;
    // Folded series are admitted past `maxSeries`, so the ceiling is what
    // makes the bound provable rather than merely likely.
    this.#ceiling = options.maxSeries * 2;
    this.#mode = options.mode;
  }

  /**
   * Add to the series named by `values`, which align with {@link dimensions}.
   *
   * Never throws for a cardinality reason: the outcome says what happened
   * instead, and the collector counts the outcomes.
   */
  inc(values: readonly string[], by = 1): IncrementOutcome {
    const key = seriesKey(values);
    const existing = this.#series.get(key);

    if (existing !== undefined) {
      existing.value += by;
      return 'recorded';
    }

    if (this.#series.size < this.#maxSeries) {
      this.#create(key, values, by);
      return 'recorded';
    }

    if (this.#mode === 'drop') {
      return 'dropped';
    }

    if (this.#mode === 'warn') {
      this.#warnOnce();
    }

    const folded = values.map((value, index) =>
      this.#foldable[index] === true ? OVERFLOW_LABEL : value
    );
    const foldedKey = seriesKey(folded);

    // Nothing to fold: every dimension of this event is one the library chose,
    // so there is no overflow series to put it in that is not the series it
    // already wanted.
    if (foldedKey === key) {
      return 'dropped';
    }

    const target = this.#series.get(foldedKey);

    if (target !== undefined) {
      target.value += by;
      return 'aggregated';
    }

    if (this.#series.size >= this.#ceiling) {
      return 'dropped';
    }

    this.#create(foldedKey, folded, by);
    return 'aggregated';
  }

  /**
   * Every series, ordered by label value in dimension order.
   *
   * Sorted rather than in insertion order so an exporter's output is stable
   * across scrapes: a diff between two scrapes should show what changed, not
   * which series happened to be created first.
   *
   * Sorted on the values rather than on the internal key, which carries a
   * length prefix per field and would order `zz` before `aaa`. Nothing depends
   * on the order beyond its being stable, but a scrape is read by people.
   */
  collect(): readonly MetricSeries[] {
    return [...this.#series.values()]
      .map((series) => ({
        series,
        order: this.dimensions.map((dimension) => series.labels[dimension] ?? ''),
      }))
      .sort((left, right) => compareValues(left.order, right.order))
      .map(({ series }) => ({ labels: series.labels, value: series.value }));
  }

  /** The sum over every series matching `filter`, whose keys are dimension names. */
  total(filter?: Readonly<Record<string, string | undefined>>): number {
    let sum = 0;

    for (const series of this.#series.values()) {
      if (filter !== undefined && !matches(series.labels, filter)) {
        continue;
      }

      sum += series.value;
    }

    return sum;
  }

  /**
   * The sum per distinct value of one dimension.
   *
   * A dimension this counter does not carry yields an empty object rather than
   * a throw: which dimensions exist is a matter of configuration, and a
   * snapshot asking for a breakdown that was turned off wants no rows, not a
   * failure.
   */
  breakdown(dimension: string): Record<string, number> {
    // Accumulated on a null prototype, because the keys are label values and a
    // label value is caller-chosen text. On an ordinary object `out['toString']`
    // reads the inherited function rather than `undefined`, so a value labelled
    // `toString` accumulates onto a function and the row renders as
    // `"function toString() { [native code] }1"`. `__proto__` is worse: the
    // assignment invokes the setter and changes the object's prototype instead
    // of recording anything.
    const out: Record<string, number> = Object.create(null) as Record<string, number>;

    for (const series of this.#series.values()) {
      const value = series.labels[dimension];

      if (value === undefined) {
        continue;
      }

      out[value] = (out[value] ?? 0) + series.value;
    }

    // Spread rather than the accumulator itself, so what a caller receives has
    // the prototype it expects. Object spread defines properties rather than
    // setting them, so a `__proto__` key survives the copy as an own property.
    return { ...out };
  }

  /** How many distinct series are held. */
  get size(): number {
    return this.#series.size;
  }

  clear(): void {
    this.#series.clear();
    this.#warned = false;
  }

  #create(key: string, values: readonly string[], by: number): void {
    // Dimension *names* are chosen by this library, so nothing here is
    // attacker-controlled the way the accumulator in `breakdown` is. Built the
    // same way regardless, so that stays true by construction if a dimension is
    // ever named from configuration.
    const labels: Record<string, string> = Object.create(null) as Record<string, string>;

    for (const [index, dimension] of this.dimensions.entries()) {
      labels[dimension] = values[index] ?? '';
    }

    this.#series.set(key, { labels: Object.freeze({ ...labels }), value: by });
  }

  #warnOnce(): void {
    if (this.#warned) {
      return;
    }

    this.#warned = true;

    process.emitWarning(
      `Metric ${this.name} reached its ${String(this.#maxSeries)}-series cap and is folding ` +
        `caller-supplied dimensions into '${OVERFLOW_LABEL}'. Totals stay correct; the breakdown ` +
        'does not. Narrow the labels you wrap values with, or raise maxSeries.',
      'SensitiveStringMetricsWarning'
    );
  }
}

function matches(
  labels: Readonly<Record<string, string>>,
  filter: Readonly<Record<string, string | undefined>>
): boolean {
  for (const [dimension, wanted] of Object.entries(filter)) {
    if (wanted === undefined) {
      continue;
    }

    if (labels[dimension] !== wanted) {
      return false;
    }
  }

  return true;
}

/** Lexicographic order over two equal-length tuples of label values. */
function compareValues(left: readonly string[], right: readonly string[]): number {
  for (const [index, value] of left.entries()) {
    const other = right[index] ?? '';

    if (value !== other) {
      return value < other ? -1 : 1;
    }
  }

  return 0;
}
