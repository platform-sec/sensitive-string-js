import { bench, describe } from 'vitest';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { createMetricsCollector } from '../collector.js';
import type { MetricsCollector } from '../collector.js';
import type { MetricsCollectorConfig } from '../types.js';

/**
 * Local rather than shared with core's benchmark fixtures.
 *
 * `packages/sensitive-core/src/__benchmarks__/fixtures.ts` is not reachable
 * from here: it is excluded from core's build, so it is not in `dist`, and a
 * relative import across package boundaries into another package's `src` is
 * not something this repository does. `sensitive-typeorm` came to the same
 * conclusion and declares its own helpers too.
 */

/**
 * Somewhere for a result to go that the optimizer cannot see through.
 *
 * A benchmark whose result is unused can be eliminated wholesale, and then it
 * measures the harness. Writing to a module-level object that is also read
 * keeps the work alive.
 */
export const sink: { value: unknown; length: number } = { value: undefined, length: 0 };

export function consume(value: unknown): void {
  sink.value = value;
  sink.length += typeof value === 'string' ? value.length : 1;
}

const FLOOR_CONSTANT = 'floor';

/**
 * What the harness costs before any of this library runs.
 *
 * Tinybench times each call separately, and that bookkeeping is on the order
 * of a hundred nanoseconds. Every unbatched task in this package is in the
 * same range or below it, so a ratio taken between two of them without
 * subtracting this figure understates the difference, sometimes by a lot.
 *
 * Two members, because every other task ends in `consume`: the second is the
 * subtrahend to use, and the first says how much of it is the sink rather than
 * the harness. Declared per file, since the floor belongs to the run.
 */
export function benchFloor(): void {
  describe('harness floor', () => {
    bench('empty function', () => {
      // Deliberately empty: the harness measuring itself.
    });

    bench('consume a constant', () => {
      consume(FLOOR_CONSTANT);
    });
  });
}

/**
 * A conspicuous prefix, so a value that escapes into benchmark output is
 * recognizable as having come from here.
 */
const CANARY = 'BENCH_CANARY_metrics';

/** A credential whose label is distinct per index, so each one is its own series. */
export function labelled(index: number): SensitiveString<'credential'> {
  return new SensitiveString(`${CANARY}_${String(index)}`, 'credential', `label_${String(index)}`);
}

/**
 * A started collector holding exactly `series` distinct redaction series.
 *
 * Built by rendering real values rather than by reaching into the counter,
 * because the shape being measured downstream is the one the collector
 * actually produces: the same dimensions, the same label lengths, the same
 * insertion order.
 *
 * The caller owns the returned collector and must stop it, or the process
 * accumulates subscriptions across benchmark tasks and every later task
 * measures all of them at once.
 */
export function collectorWithSeries(
  series: number,
  config: MetricsCollectorConfig = {}
): MetricsCollector {
  const collector = createMetricsCollector(config);
  collector.start();

  for (let index = 0; index < series; index++) {
    consume(String(labelled(index)));
  }

  return collector;
}

/** Series counts worth comparing: a small service, a busy one, and one at the default cap. */
export const SERIES_COUNTS = [10, 100, 1000] as const;

/** Batch size for the tasks whose single operation sits below the harness floor. */
export const BATCH = 1000;
