/**
 * Comparison.
 *
 * `credential` compares in constant time and `sensitive` does not, which is
 * the one behavioural difference between the two default classes. The first
 * group prices that difference against a bare `===`.
 *
 * The mismatch positions in the second group exist to be compared with each
 * other rather than with a target: constant-time comparison is exactly the
 * property that an early mismatch must not be measurably cheaper than a late
 * one. `length differs` belongs in that group for the same reason and not as
 * a separate case: since both operands are hashed to a fixed width before
 * they are compared, a wrong length is a mismatch like any other and should
 * price like one. These numbers are indicative only. The statistical version of that
 * question, with interleaving and a noise floor, is
 * `__tests__/timing-analysis.timing.test.ts`, run through `pnpm test:timing`.
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
const OTHER = `${valueOfLength(63)}Z`;

/**
 * An equal value with a different identity, so the control compares two
 * strings rather than one against itself. Built here rather than in the timed
 * function: a control that allocates its own operand every iteration measures
 * the allocator and reports the library as faster than a bare `===`.
 */
const SAME = distinctCopy(VALUE);

const credential = new SensitiveString(VALUE, 'credential');
const sensitive = new SensitiveString(VALUE, 'sensitive');
const credentialTwin = new SensitiveString(VALUE, 'credential');

describe('equals against a matching value', () => {
  bench('String === (control)', () => {
    consumeFlag(VALUE === SAME);
  });

  bench('sensitive, variable time', () => {
    consumeFlag(sensitive.equals(VALUE));
  });

  bench('credential, constant time', () => {
    consumeFlag(credential.equals(VALUE));
  });

  bench('credential against another instance', () => {
    consumeFlag(credential.equals(credentialTwin));
  });
});

describe('credential equals by mismatch position', () => {
  const early = `Z${VALUE.slice(1)}`;
  const late = OTHER;

  bench('match', () => {
    consumeFlag(credential.equals(VALUE));
  });

  bench('first character differs', () => {
    consumeFlag(credential.equals(early));
  });

  bench('last character differs', () => {
    consumeFlag(credential.equals(late));
  });

  bench('length differs', () => {
    consumeFlag(credential.equals(`${VALUE}extra`));
  });
});

describe('credential equals by value length', () => {
  for (const length of LENGTHS) {
    const instance = new SensitiveString(valueOfLength(length), 'credential');
    const operand = distinctCopy(valueOfLength(length));

    bench(`${length} chars`, () => {
      consumeFlag(instance.equals(operand));
    });
  }
});

// Each instance is compared against an equal string it does not already
// hold. Comparing against its own backing string made `===` a pointer
// comparison, which is why this sweep used to report 16KB as six times faster
// than 16 chars.
describe('sensitive equals by value length', () => {
  for (const length of LENGTHS) {
    const instance = new SensitiveString(valueOfLength(length), 'sensitive');
    const operand = distinctCopy(valueOfLength(length));

    bench(`${length} chars`, () => {
      consumeFlag(instance.equals(operand));
    });
  }
});

describe('isEmpty', () => {
  const empty = new SensitiveString('', 'sensitive');

  bench('populated', () => {
    consume(sensitive.isEmpty());
  });

  bench('empty', () => {
    consume(empty.isEmpty());
  });
});

benchFloor();
