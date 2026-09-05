/**
 * The redaction path on a single value.
 *
 * This is the hot path: it runs on every log line, every `JSON.stringify` of a
 * payload that happens to hold a value, and every interpolation into a
 * message. A value is redacted far more often than it is revealed, so the
 * absolute numbers here matter more than most in this suite.
 *
 * Masking is a `sensitive` operation throughout, because the default
 * `credential` policy sets `allowMask: false` and a masked credential would
 * be a refusal rather than a measurement.
 */

import { inspect } from 'node:util';

import { bench, describe } from 'vitest';

import { SensitiveString } from '../sensitive-string.js';
import { benchFloor, consume, LENGTHS, TOKEN, valueOfLength } from './fixtures.js';

const credential = new SensitiveString(TOKEN, 'credential', 'access_token');
const sensitive = new SensitiveString('ada@example.com', 'sensitive', 'email');

describe('redaction of one value', () => {
  bench('toString', () => {
    consume(credential.toString());
  });

  bench('toJSON', () => {
    consume(credential.toJSON());
  });

  bench('String()', () => {
    consume(String(credential));
  });

  bench('template interpolation', () => {
    // eslint-disable-next-line @typescript-eslint/restrict-template-expressions -- the implicit coercion is the subject of this benchmark
    consume(`token=${credential}`);
  });

  bench('JSON.stringify', () => {
    consume(JSON.stringify(credential));
  });

  bench('util.inspect', () => {
    consume(inspect(credential));
  });
});

describe('redaction by value length', () => {
  for (const length of LENGTHS) {
    const instance = new SensitiveString(valueOfLength(length), 'credential');

    bench(`${length} chars`, () => {
      consume(instance.toString());
    });
  }
});

describe('positional masking', () => {
  const card = new SensitiveString('4111111111111111', 'sensitive', 'card');

  bench('showLast 4', () => {
    consume(card.mask({ showLast: 4 }));
  });

  bench('showFirst 2, showLast 4', () => {
    consume(card.mask({ showFirst: 2, showLast: 4 }));
  });

  bench('custom mask character', () => {
    consume(card.mask({ showLast: 4, maskChar: '#' }));
  });

  bench('full redaction, no options', () => {
    consume(card.mask());
  });
});

describe('mask strategies', () => {
  const email = new SensitiveString('ada.lovelace@example.com', 'sensitive', 'email');
  const phone = new SensitiveString('+1-555-0142', 'sensitive', 'phone');
  const card = new SensitiveString('4111111111111111', 'sensitive', 'card');
  const ssn = new SensitiveString('123-45-6789', 'sensitive', 'ssn');
  const uuid = new SensitiveString('3f2504e0-4f89-11d3-9a0c-0305e82c3301', 'sensitive', 'uuid');

  bench('email', () => {
    consume(email.mask({ strategy: 'email' }));
  });

  bench('phone', () => {
    consume(phone.mask({ strategy: 'phone' }));
  });

  bench('card', () => {
    consume(card.mask({ strategy: 'card' }));
  });

  bench('ssn', () => {
    consume(ssn.mask({ strategy: 'ssn' }));
  });

  bench('uuid', () => {
    consume(uuid.mask({ strategy: 'uuid' }));
  });
});

describe('redaction against the raw equivalents', () => {
  const raw = 'ada@example.com';

  bench('raw string toString (control)', () => {
    consume(raw.toString());
  });

  bench('sensitive toString', () => {
    consume(sensitive.toString());
  });

  bench('raw string JSON.stringify (control)', () => {
    consume(JSON.stringify(raw));
  });

  bench('sensitive JSON.stringify', () => {
    consume(JSON.stringify(sensitive));
  });
});

benchFloor();
