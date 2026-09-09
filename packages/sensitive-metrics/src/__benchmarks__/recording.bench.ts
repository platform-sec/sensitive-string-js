/**
 * What it costs to record, which is the cost a production process pays
 * continuously rather than once per scrape.
 *
 * The first group is the one that matters, and it is deliberately the same
 * shape as core's `redaction observed` group so the two can be read together.
 * Core's version prices a hand-rolled counting observer; this one prices the
 * real collector, and the gap between them is what this package adds over the
 * three lines a reader might otherwise write themselves.
 *
 * Read every group as ratios between its own members. Absolute figures here
 * describe the machine as much as the code, and the unbatched tasks sit near
 * the harness floor, so subtract the `harness floor` group before taking a
 * ratio between two of them. The batched group exists because the operation it
 * measures is well below that floor: it runs {@link BATCH} increments per
 * iteration, so divide its figure by that before comparing it to anything.
 */

import { bench, describe } from 'vitest';
import { observeRedactions } from '@platform-sec/sensitive-string-core';
import { BoundedCounter } from '../series.js';
import type { MetricsCollector } from '../collector.js';
import { BATCH, benchFloor, collectorWithSeries, consume, labelled } from './fixtures.js';

benchFloor();

const credential = labelled(0);

/**
 * One rendering, priced by what is watching it.
 *
 * Four tasks and three gaps, and each gap is a different party's cost. Control
 * to no-op observer is what core charges to notify at all: the length read, the
 * frozen event, one call. No-op to collector is what this package charges to
 * turn that event into a series. Collector to two collectors is what a second
 * subscriber costs, which is the case a process running both this package and
 * an OpenTelemetry exporter is in.
 *
 * `setup` and `teardown` rather than `beforeAll`: Vitest passes the third
 * argument to the `Bench` and silently ignores task-level hooks placed
 * anywhere else, so a fixture built in `beforeAll` is built after the timing
 * has already started.
 */
describe('one redaction, by what is observing it', () => {
  let stop: (() => void) | undefined;
  let first: MetricsCollector | undefined;
  let second: MetricsCollector | undefined;

  bench('nothing observing (control)', () => {
    consume(String(credential));
  });

  bench(
    'one no-op observer, which is core cost alone',
    () => {
      consume(String(credential));
    },
    {
      setup: () => {
        stop = observeRedactions(() => undefined);
      },
      teardown: () => {
        stop?.();
        stop = undefined;
      },
    }
  );

  bench(
    'one metrics collector',
    () => {
      consume(String(credential));
    },
    {
      setup: () => {
        first = collectorWithSeries(0);
      },
      teardown: () => {
        first?.stop();
        first = undefined;
      },
    }
  );

  bench(
    'two metrics collectors, as a process running a second exporter has',
    () => {
      consume(String(credential));
    },
    {
      setup: () => {
        first = collectorWithSeries(0);
        second = collectorWithSeries(0);
      },
      teardown: () => {
        first?.stop();
        second?.stop();
        first = undefined;
        second = undefined;
      },
    }
  );
});

/**
 * The counter itself, batched past the harness floor.
 *
 * Every figure in this group is {@link BATCH} increments. Divide before
 * quoting one.
 *
 * The three cases are the three paths through `inc`: hitting a series that
 * exists, which is the overwhelming production case; creating one, which
 * happens once per distinct label; and folding, which is what every increment
 * does once the cap is reached and is therefore the steady state of a process
 * whose labels ran away.
 */
describe(`bounded counter, ${String(BATCH)} increments per iteration`, () => {
  const dimensions = ['class', 'surface', 'label'];
  const foldable = new Set(['label']);
  const options = {
    name: 'bench_total',
    help: 'bench',
    dimensions,
    foldable,
    maxSeries: 1000,
    mode: 'aggregate' as const,
  };

  const hot = new BoundedCounter(options);
  hot.inc(['credential', 'toString', 'label_0']);

  let capped = new BoundedCounter(options);

  bench('into a series that already exists', () => {
    for (let index = 0; index < BATCH; index++) {
      hot.inc(['credential', 'toString', 'label_0']);
    }
  });

  // The counter is built inside the body, not in `setup`. `setup` runs once per
  // bench rather than once per iteration, so a counter built there would be
  // full after the first iteration and every later one would measure the
  // existing-series path above under this task's name. One allocation per
  // thousand increments is a rounding error next to that.
  bench('creating a new series each time', () => {
    const fresh = new BoundedCounter({ ...options, maxSeries: BATCH * 2 });

    for (let index = 0; index < BATCH; index++) {
      fresh.inc(['credential', 'toString', `label_${String(index)}`]);
    }

    consume(fresh.size);
  });

  bench(
    'folding, which is every increment once the cap is reached',
    () => {
      for (let index = 0; index < BATCH; index++) {
        capped.inc(['credential', 'toString', `label_${String(index)}`]);
      }
    },
    {
      // Here `setup` is right: after the first iteration the overflow series
      // exists, and every fold thereafter increments it. That is the steady
      // state of a capped counter, which is what this task is for.
      setup: () => {
        capped = new BoundedCounter({ ...options, maxSeries: 1 });
        capped.inc(['credential', 'toString', 'seed']);
      },
    }
  );
});
