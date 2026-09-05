/**
 * What development mode costs, on and off.
 *
 * The first two groups are the ones that matter for production: development
 * mode off is what every process that never calls `setDevMode` runs, and the
 * gap between the control and the guarded path is the whole price of the
 * feature being available. It is one property read per construction and one per
 * exposure, so expect the two to be indistinguishable, and read a visible gap
 * as a sign the guard moved rather than as a cost worth optimizing.
 *
 * The remaining groups price the feature when it is on, which is a development
 * cost and not a production one. Stack capture dominates them: `new Error()`
 * followed by a read of `.stack` formats the trace eagerly, and a run where it
 * does not stand out is a run to distrust. Read its ratio and not its absolute
 * figure: the runner installs a source-map-aware `Error.prepareStackTrace`, so
 * a capture measured here costs an order of magnitude more than the same
 * capture in a plain Node process, which was 13.5us against 214us in the run
 * these notes describe.
 *
 * Each benchmark installs its own configuration in the tinybench `setup` hook,
 * which runs before the warmup and the run of that one task and outside both
 * timed regions. Setting it inside the timed function instead would measure the
 * validation rather than the feature.
 *
 * `setup` and not `beforeAll`: Vitest hands a benchmark's third argument to the
 * `Bench` constructor rather than to the `Task`, so the task-level hooks are
 * accepted by the type checker through an object typed as anything but a
 * literal, and then silently ignored. The first version of this file used them,
 * and reported the creation stack as cheaper than capturing no stack at all,
 * because no configuration was ever installed.
 *
 * Every task turns development mode off again in `teardown`. Bench files can
 * share a worker, and leaving it on would quietly measure every later file with
 * it enabled.
 */

import { bench, describe } from 'vitest';
import type { BenchOptions } from 'vitest';

import { SensitiveString } from '../sensitive-string.js';
import { setDevMode } from '../dev-mode.js';
import type { DevModeConfig } from '../dev-mode.js';
import { benchFloor, consume, TOKEN } from './fixtures.js';

/** Overwritten rather than appended to, so the sink cannot grow during a run. */
const sink: string[] = [];
const logger = (message: string): void => {
  sink[0] = message;
};

/** Install a configuration for the whole of one task, and take it back after. */
function using(config: DevModeConfig): BenchOptions {
  return {
    setup: () => setDevMode(config),
    teardown: () => setDevMode({ enabled: false }),
  };
}

/**
 * The same, plus a value constructed under that configuration.
 *
 * A value built before development mode was turned on has no record, and its
 * reveals stop at the lookup that misses. Reusing one instance across the reveal
 * group would therefore have measured the guard six times over rather than the
 * recording, which is what the first version of this file did.
 */
function revealing(config: DevModeConfig): BenchOptions {
  return {
    setup: () => {
      setDevMode(config);
      credential = new SensitiveString(TOKEN, 'credential', 'access_token');
    },
    teardown: () => setDevMode({ enabled: false }),
  };
}

const OFF = using({ enabled: false });

let credential = new SensitiveString(TOKEN, 'credential', 'access_token');

benchFloor();

describe('construction', () => {
  bench(
    'development mode off (control)',
    () => {
      consume(new SensitiveString(TOKEN, 'credential', 'access_token'));
    },
    OFF
  );

  bench(
    'recording',
    () => {
      consume(new SensitiveString(TOKEN, 'credential', 'access_token'));
    },
    using({ enabled: true })
  );

  bench(
    'recording with the creation stack',
    () => {
      consume(new SensitiveString(TOKEN, 'credential', 'access_token'));
    },
    using({ enabled: true, captureCreationStack: true })
  );
});

describe('reveal', () => {
  bench(
    'development mode off (control)',
    () => {
      consume(credential.reveal());
    },
    OFF
  );

  bench(
    'on, over a value it never recorded',
    () => {
      consume(credential.reveal());
    },
    using({ enabled: true })
  );

  bench(
    'recording',
    () => {
      consume(credential.reveal());
    },
    revealing({ enabled: true })
  );

  bench(
    'recording with the repeated-reveal window',
    () => {
      consume(credential.reveal());
    },
    // A threshold no run reaches, so the window is counted and never reported.
    revealing({ enabled: true, warnOnRepeatedReveal: { threshold: 1_000_000_000, window: 60_000 } })
  );

  bench(
    'logging every exposure',
    () => {
      consume(credential.reveal());
    },
    revealing({ enabled: true, logReveals: { enabled: true, logger } })
  );

  bench(
    'logging a partial rendering',
    () => {
      consume(credential.reveal());
    },
    revealing({ enabled: true, logReveals: { enabled: true, logger, showPartialValue: true } })
  );

  bench(
    'capturing the stack of every exposure',
    () => {
      consume(credential.reveal());
    },
    revealing({ enabled: true, captureStackTraces: true })
  );
});
