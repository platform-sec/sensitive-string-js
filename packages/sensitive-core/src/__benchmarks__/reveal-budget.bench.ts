/**
 * Reveal counting and rate limiting.
 *
 * The question here is what each limit adds to a read. A lifetime limit is a
 * comparison; a window pushes a timestamp and prunes the ones that have left
 * it, which is the only part with a data structure behind it.
 *
 * What this file cannot answer is what the counter itself costs, because every
 * exposing read charges one whether or not the value limits anything, so the
 * control in each group pays for it too. That figure was taken separately, by
 * timing reveals against a build with the charge removed, and is recorded in
 * the changeset: about 6ns, against roughly 20ns for the rest of the read.
 *
 * The budgets here are deliberately unreachable. A benchmark that exhausted
 * its value partway through a run would measure the refusal path for the rest
 * of it, and the refusal path is measured on purpose in its own group.
 */

import { bench, describe } from 'vitest';

import { SensitiveString } from '../sensitive-string.js';
import { benchFloor, consume, consumeFlag, TOKEN } from './fixtures.js';

const plain = new SensitiveString(TOKEN, 'sensitive', 'access_token');

const counted = new SensitiveString(TOKEN, 'sensitive', 'access_token', {
  maxReveals: Number.MAX_SAFE_INTEGER,
});

/**
 * A window short enough that pruning actually runs, under a limit no run can
 * reach: at a hundred nanoseconds a reveal, ten milliseconds holds on the order
 * of a hundred thousand charges, four orders of magnitude below the limit.
 */
const windowed = new SensitiveString(TOKEN, 'sensitive', 'access_token', {
  revealWindow: 10,
  maxRevealsPerWindow: 1_000_000,
});

const both = new SensitiveString(TOKEN, 'sensitive', 'access_token', {
  maxReveals: Number.MAX_SAFE_INTEGER,
  revealWindow: 10,
  maxRevealsPerWindow: 1_000_000,
});

/**
 * A value built from two budgeted sources, so the check and the charge each
 * have more than one state to walk.
 */
const derived = counted.concat(
  new SensitiveString('/suffix', 'sensitive', undefined, { maxReveals: Number.MAX_SAFE_INTEGER })
);

/** Spent, and therefore able to refuse the same read indefinitely. */
const exhausted = new SensitiveString(TOKEN, 'sensitive', 'access_token', { maxReveals: 0 });

const rateLimited = new SensitiveString(TOKEN, 'sensitive', 'access_token', {
  revealWindow: 3_600_000,
  maxRevealsPerWindow: 1,
});
rateLimited.reveal();

/** Swallow a refusal, so the throw is measured rather than aborting the run. */
function refused(read: () => unknown): void {
  try {
    consume(read());
  } catch (error) {
    consume(error);
  }
}

describe('what a budget costs on reveal', () => {
  bench('no budget (control)', () => {
    consume(plain.reveal());
  });

  bench('lifetime limit', () => {
    consume(counted.reveal());
  });

  bench('sliding window', () => {
    consume(windowed.reveal());
  });

  bench('both limits', () => {
    consume(both.reveal());
  });

  bench('two budgeted sources', () => {
    consume(derived.reveal());
  });
});

describe('what a budget costs on the paths that are not charged', () => {
  bench('redaction, no budget (control)', () => {
    consume(plain.toString());
  });

  bench('redaction, lifetime limit', () => {
    consume(counted.toString());
  });

  bench('equals, no budget (control)', () => {
    consumeFlag(plain.equals(TOKEN));
  });

  bench('equals, lifetime limit', () => {
    consumeFlag(counted.equals(TOKEN));
  });
});

describe('what a budget costs on derivation', () => {
  bench('no budget (control)', () => {
    consume(plain.substring(0, 12));
  });

  bench('lifetime limit', () => {
    consume(counted.substring(0, 12));
  });

  bench('sliding window', () => {
    consume(windowed.substring(0, 12));
  });
});

describe('what a budget costs at construction', () => {
  bench('no budget (control)', () => {
    consume(new SensitiveString(TOKEN, 'sensitive', 'access_token'));
  });

  bench('lifetime limit', () => {
    consume(new SensitiveString(TOKEN, 'sensitive', 'access_token', { maxReveals: 1 }));
  });

  bench('sliding window', () => {
    consume(
      new SensitiveString(TOKEN, 'sensitive', 'access_token', {
        revealWindow: 60_000,
        maxRevealsPerWindow: 10,
      })
    );
  });
});

describe('introspection', () => {
  bench('revealCount, no budget', () => {
    consume(plain.revealCount);
  });

  bench('revealCount, two sources', () => {
    consume(derived.revealCount);
  });

  bench('revealsRemaining', () => {
    consume(counted.revealsRemaining);
  });

  bench('isExhausted, no budget', () => {
    consumeFlag(plain.isExhausted());
  });

  bench('isExhausted, lifetime limit', () => {
    consumeFlag(counted.isExhausted());
  });
});

describe('the refusal path', () => {
  // Dominated by building the error, which captures a stack. A refusal is not
  // on anyone's hot path, and a caller hitting one in a loop has a bug that
  // this feature exists to make visible.
  bench('refused by the lifetime limit', () => {
    refused(() => exhausted.reveal());
  });

  bench('refused by the window', () => {
    refused(() => rateLimited.reveal());
  });

  bench('allowed (control)', () => {
    refused(() => counted.reveal());
  });
});

benchFloor();
