/**
 * Sealing, priced against the unsealed path it replaces.
 *
 * Every group carries its unsealed twin as the control, because that is the
 * only comparison a reader can act on: the question is never "how fast is a
 * sealed reveal" but "what does sealing cost me here", and the answer differs
 * by two orders of magnitude between the reveal group and the redaction one.
 *
 * The four groups are the four shapes the documentation makes claims about.
 *
 * - **Reading** is where sealing is expensive, and the group prices the two
 *   ways of doing it: `reveal()` returns a string and `revealBytes()` does not.
 *   The difference between them here is small; the difference in what they
 *   leave behind is the whole feature, and that is measured in
 *   `__tests__/sealing-retention.timing.test.ts` rather than here.
 * - **Redaction** is where sealing is free, and has to be. A sealed value
 *   renders from a snapshot taken at construction, so this group should show no
 *   gap at all. A run where it does means a safe read started decrypting.
 * - **Comparison** is the shape a credential is actually used in, and it is the
 *   one where sealing is a trade rather than a cost, because the unsealed
 *   constant-time path already hashes both operands.
 * - **Construction** is paid once per value, which is why section 12 of the
 *   design says to seal a credential loaded at startup and not a value wrapped
 *   per request.
 *
 * Read these as ratios within a group, after subtracting the harness floor.
 * Absolute figures do not survive a different machine, and the sealed numbers
 * in particular move by a factor of two on a loaded one.
 */

import { bench, describe } from 'vitest';

import { SensitiveString } from '../sensitive-string.js';
import {
  benchFloor,
  consume,
  consumeFlag,
  distinctCopy,
  LENGTHS,
  valueOfLength,
} from './fixtures.js';

const VALUE = valueOfLength(64);

/** An equal value with a different identity, so a comparison compares two. */
const SAME = distinctCopy(VALUE);

const plain = new SensitiveString(VALUE, 'credential', 'access_token');
const sealed = new SensitiveString(VALUE, 'credential', 'access_token', { sealed: true });
const plainTwin = new SensitiveString(VALUE, 'credential', 'access_token');
const sealedTwin = new SensitiveString(VALUE, 'credential', 'access_token', { sealed: true });

describe('reading a value', () => {
  bench('unsealed reveal (control)', () => {
    consume(plain.reveal());
  });

  bench('sealed reveal', () => {
    consume(sealed.reveal());
  });

  bench('unsealed revealBytes', () => {
    consume(plain.revealBytes());
  });

  bench('sealed revealBytes', () => {
    consume(sealed.revealBytes());
  });
});

describe('reading by value length', () => {
  for (const length of LENGTHS) {
    const instance = new SensitiveString(valueOfLength(length), 'credential', undefined, {
      sealed: true,
    });

    // A decrypt is dominated by fixed per-call cost rather than by the data, so
    // this group should be much flatter than the length it spans.
    bench(`${String(length)} chars`, () => {
      consume(instance.reveal());
    });
  }
});

describe('redacting a value', () => {
  // The group that must show no gap. A sealed value renders from the snapshot
  // taken at construction, so neither member decrypts.
  bench('unsealed toString (control)', () => {
    consume(plain.toString());
  });

  bench('sealed toString', () => {
    consume(sealed.toString());
  });

  bench('unsealed length', () => {
    consume(plain.length);
  });

  bench('sealed length', () => {
    consume(sealed.length);
  });
});

describe('comparing a credential', () => {
  // The unsealed control is already the constant-time path, which hashes both
  // operands under an ephemeral key, so the gap here is the two decrypts and
  // not the comparison.
  bench('unsealed against a string (control)', () => {
    consumeFlag(plain.equals(SAME));
  });

  bench('sealed against a string', () => {
    consumeFlag(sealed.equals(SAME));
  });

  bench('unsealed against unsealed', () => {
    consumeFlag(plain.equals(plainTwin));
  });

  bench('sealed against sealed', () => {
    consumeFlag(sealed.equals(sealedTwin));
  });
});

describe('constructing a value', () => {
  bench('unsealed (control)', () => {
    consume(new SensitiveString(VALUE, 'credential', 'access_token'));
  });

  bench('sealed', () => {
    consume(new SensitiveString(VALUE, 'credential', 'access_token', { sealed: true }));
  });

  bench('sealed from a Buffer', () => {
    // `fromBuffer` zeroes what it is given, so the buffer is built per
    // iteration and the control above is the wrong comparison for this one.
    // Read it against `sealed` and remember both pay for the allocation.
    consume(SensitiveString.fromBuffer(Buffer.from(VALUE, 'utf8'), 'credential', 'access_token'));
  });
});

describe('deriving from a value', () => {
  // A derivative of a sealed value opens the box, slices the string, and seals
  // the result, so this group prices a decrypt plus a seal rather than either.
  bench('unsealed substring (control)', () => {
    consume(plain.substring(0, 16));
  });

  bench('sealed substring', () => {
    consume(sealed.substring(0, 16));
  });
});

benchFloor();

// No `resetSealing()` here, and the first draft's is the reason this comment
// exists. Vitest evaluates the module to collect the `bench` registrations and
// runs them afterwards, so a call at this scope executes before any benchmark
// does: it emptied the key ring while the fixtures above were already sealed
// under it, and every sealed read then reported an integrity failure and
// printed as `NaNx`. The same shape as `beforeAll` being ignored here.
//
// Nothing needs cleaning up anyway. The ring holds one 32-byte key, the
// construction group is nowhere near a generation rollover, and each bench
// file runs in its own worker.
