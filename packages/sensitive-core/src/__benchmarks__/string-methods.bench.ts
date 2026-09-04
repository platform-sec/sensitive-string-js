/**
 * The string surface.
 *
 * Two shapes with different costs. A derivation returns a new
 * `SensitiveString`, so it pays a construction on every call; a partial query
 * returns a plain boolean or number and pays none. Splitting them into
 * separate groups keeps the ranking within each group meaningful.
 *
 * Everything here uses `sensitive`, because the default `credential` policy
 * sets `allowPartialQueries: false` and every query would be a refusal rather
 * than a measurement.
 */

import { bench, describe } from 'vitest';

import { SensitiveString } from '../sensitive-string.js';
import { consume, consumeFlag, LENGTHS, valueOfLength } from './fixtures.js';

const VALUE = 'ada.lovelace@example.com/session/8f2c4a1b9d3e';
const value = new SensitiveString(VALUE, 'sensitive', 'session_url');
const other = new SensitiveString('/extra', 'sensitive');

describe('derivations', () => {
  bench('construction from the raw value (control)', () => {
    consume(new SensitiveString(VALUE, 'sensitive'));
  });

  bench('substring', () => {
    consume(value.substring(0, 12));
  });

  bench('slice', () => {
    consume(value.slice(4, 20));
  });

  bench('trim', () => {
    consume(value.trim());
  });

  bench('toLowerCase', () => {
    consume(value.toLowerCase());
  });

  bench('padStart', () => {
    consume(value.padStart(64, '0'));
  });

  bench('charAt', () => {
    consume(value.charAt(3));
  });

  bench('map', () => {
    consume(value.map((raw) => raw.toUpperCase()));
  });

  bench('concat', () => {
    consume(value.concat(other));
  });
});

describe('partial queries', () => {
  bench('raw includes (control)', () => {
    consumeFlag(VALUE.includes('session'));
  });

  bench('includes', () => {
    consumeFlag(value.includes('session'));
  });

  bench('startsWith', () => {
    consumeFlag(value.startsWith('ada'));
  });

  bench('endsWith', () => {
    consumeFlag(value.endsWith('9d3e'));
  });

  bench('indexOf', () => {
    consume(value.indexOf('session'));
  });

  bench('lastIndexOf', () => {
    consume(value.lastIndexOf('/'));
  });
});

describe('regex queries', () => {
  const anchored = /^[a-z.]+@example\.com/;

  bench('raw test (control)', () => {
    consumeFlag(anchored.test(VALUE));
  });

  bench('test', () => {
    consumeFlag(value.test(anchored));
  });

  bench('search', () => {
    consume(value.search(/session/));
  });
});

describe('regex derivations', () => {
  bench('match', () => {
    consume(value.match(/[a-z]+/));
  });

  bench('matchGroups', () => {
    consume(value.matchGroups(/(?<user>[a-z.]+)@(?<host>[a-z.]+)/));
  });

  bench('matchAll', () => {
    consume([...value.matchAll(/[a-z]+/g)]);
  });

  bench('split', () => {
    consume(value.split('/'));
  });

  bench('replace', () => {
    consume(value.replace('session', 'sess'));
  });

  bench('replaceAll', () => {
    consume(value.replaceAll('a', 'A'));
  });
});

describe('substring by value length', () => {
  for (const length of LENGTHS) {
    const instance = new SensitiveString(valueOfLength(length), 'sensitive');

    bench(`${length} chars`, () => {
      consume(instance.substring(0, 12));
    });
  }
});

describe('includes by value length', () => {
  for (const length of LENGTHS) {
    const instance = new SensitiveString(valueOfLength(length), 'sensitive');

    bench(`${length} chars`, () => {
      consumeFlag(instance.includes('CANARY'));
    });
  }
});
