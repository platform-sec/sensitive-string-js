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
 * one. These numbers are indicative only. The statistical version of that
 * question, with interleaving and a noise floor, is
 * `__tests__/timing-analysis.timing.test.ts`, run through `pnpm test:timing`.
 */

import { bench, describe } from 'vitest';

import { SensitiveString } from '../sensitive-string.js';
import { consume, consumeFlag, LENGTHS, valueOfLength } from './fixtures.js';

const VALUE = valueOfLength(64);
const OTHER = `${valueOfLength(63)}Z`;

/**
 * An equal value built separately, so the control compares two strings rather
 * than one against itself. Built here rather than in the timed function: a
 * control that allocates its own operand every iteration measures the
 * allocator and reports the library as faster than a bare `===`.
 */
const SAME = `${VALUE.slice(0, 32)}${VALUE.slice(32)}`;

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
    const value = valueOfLength(length);
    const instance = new SensitiveString(value, 'credential');

    bench(`${length} chars`, () => {
      consumeFlag(instance.equals(value));
    });
  }
});

describe('sensitive equals by value length', () => {
  for (const length of LENGTHS) {
    const value = valueOfLength(length);
    const instance = new SensitiveString(value, 'sensitive');

    bench(`${length} chars`, () => {
      consumeFlag(instance.equals(value));
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
