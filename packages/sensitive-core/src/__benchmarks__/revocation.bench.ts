/**
 * Revocation.
 *
 * The question here is what a check that almost never fires costs the reads
 * that are not being refused. Every exposing read and every comparison consults
 * the revocation state, so a process that revokes nothing still pays for the
 * feature, and that toll is what the first group measures against a build
 * without it: the control in every other group pays it too.
 *
 * The design that toll drives is the generation counter. A value that has
 * looked once and found nothing compares one integer instead of searching the
 * label map and walking the pattern list, so the size of those lists should not
 * show up in a read at all. The `after a revocation` group is there to prove
 * that: it revokes something unrelated between measurements, which invalidates
 * every cached answer and forces the search the counter normally skips.
 *
 * The lists are deliberately populated with entries that match nothing here. A
 * benchmark whose value was actually revoked would measure the refusal path for
 * the rest of the run, and the refusal path is measured on purpose in its own
 * group.
 */

import { bench, describe } from 'vitest';

import { SensitiveString } from '../sensitive-string.js';
import { RevocationList, revokeByLabel, revokeByPattern } from '../revocation.js';
import { benchFloor, consume, consumeFlag, TOKEN } from './fixtures.js';

const INSPECT = Symbol.for('nodejs.util.inspect.custom');

/**
 * The inspection path, which is a different check from the gate's.
 *
 * Called directly rather than through `util.inspect`, whose own formatting
 * would be most of the measurement and identical on both sides of the pair.
 */
function inspect(value: SensitiveString<'sensitive'>): string {
  return (value as unknown as Record<symbol, () => string>)[INSPECT]!();
}

/** A label nothing in the lists below matches. */
const LIVE = 'access_token';

const plain = new SensitiveString(TOKEN, 'sensitive', LIVE);
const unlabelled = new SensitiveString(TOKEN, 'sensitive');

const registry = new RevocationList();
registry.revoke('some_other_key', 'not this value');

const registered = new SensitiveString(TOKEN, 'sensitive', LIVE, {
  revocationRegistry: registry,
});

/** Revoked before the run, so it refuses the same read indefinitely. */
const revoked = new SensitiveString(TOKEN, 'sensitive', 'spent');
revoked.revoke('rotated');

/** A value built from two sources, so the walk has more than one state. */
const derived = plain.concat(new SensitiveString('/suffix', 'sensitive', 'suffix'));

/**
 * Populate the lists with entries that match nothing measured here. Sized so
 * that a search which is not being skipped is visible against one that is.
 */
for (let index = 0; index < 200; index++) {
  revokeByLabel(`rotated_key_${index}`, 'filler');
}

for (let index = 0; index < 20; index++) {
  revokeByPattern(new RegExp(`^retired_${index}_[a-z]+$`), 'filler');
}

/** Swallow a refusal, so the throw is measured rather than aborting the run. */
function refused(read: () => unknown): void {
  try {
    consume(read());
  } catch (error) {
    consume(error);
  }
}

describe('what the revocation check costs on reveal', () => {
  bench('unlabelled value', () => {
    consume(unlabelled.reveal());
  });

  bench('labelled value, nothing revoked for it', () => {
    consume(plain.reveal());
  });

  bench('two sources', () => {
    consume(derived.reveal());
  });

  bench('external registry', () => {
    consume(registered.reveal());
  });
});

describe('what it costs on the other paths through the gate', () => {
  bench('equals', () => {
    consumeFlag(plain.equals(TOKEN));
  });

  bench('redaction (does not check)', () => {
    consume(plain.toString());
  });

  bench('derivation', () => {
    consume(plain.substring(0, 12));
  });
});

describe('what a search costs when the cache cannot help', () => {
  // A value that has never looked searches on its first read, so constructing
  // one per iteration is how the search gets measured without the lists
  // growing under the measurement. The control is an unlabelled value, which
  // has nothing to look up and so skips both the map and the walk while paying
  // the same construction and the same read.
  bench('first read, labelled (searches)', () => {
    consume(new SensitiveString(TOKEN, 'sensitive', LIVE).reveal());
  });

  bench('first read, unlabelled (control)', () => {
    consume(new SensitiveString(TOKEN, 'sensitive').reveal());
  });
});

describe('introspection', () => {
  bench('isRevoked, live', () => {
    consumeFlag(plain.isRevoked);
  });

  bench('isRevoked, revoked', () => {
    consumeFlag(revoked.isRevoked);
  });

  // Inspection takes the other path, which consults no registry and latches
  // nothing. `toString()` is not the control for it: that is a safe read and
  // never reaches the revocation state at all, which is what the third member
  // is here to show.
  bench('inspect, live', () => {
    consume(inspect(plain));
  });

  bench('inspect, revoked', () => {
    consume(inspect(revoked));
  });

  bench('toString (does not check)', () => {
    consume(plain.toString());
  });
});

describe('the refusal path', () => {
  // Dominated by building the error, which captures a stack. Nobody's hot path
  // runs through here: a caller hitting it in a loop is using a secret that
  // somebody deliberately took away.
  bench('refused', () => {
    refused(() => revoked.reveal());
  });

  bench('allowed (control)', () => {
    refused(() => plain.reveal());
  });
});

benchFloor();
