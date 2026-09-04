/**
 * Expiration.
 *
 * A deadline is checked on every read, not only when someone asks, so the
 * question this file answers is what a value with a TTL costs on the paths
 * that a value without one already pays for: reveal, redaction, and
 * derivation. The `renew` group is separate because renewal is rare by
 * comparison and its cost is not on anyone's hot path.
 */

import { bench, describe } from 'vitest';

import { SensitiveString } from '../sensitive-string.js';
import { consume, consumeFlag, TOKEN } from './fixtures.js';

const plain = new SensitiveString(TOKEN, 'sensitive', 'access_token');
const expiring = new SensitiveString(TOKEN, 'sensitive', 'access_token', { ttl: 3_600_000 });
const renewable = new SensitiveString(TOKEN, 'sensitive', 'access_token', {
  ttl: 3_600_000,
  allowRenewal: true,
});

/**
 * A value built from two sources, so the deadline scan has more than one state
 * to walk. `concat` records both sources, and the earliest deadline wins.
 */
const derived = expiring.concat(new SensitiveString('/suffix', 'sensitive'));

describe('deadline checks', () => {
  bench('isExpired, no deadline', () => {
    consumeFlag(plain.isExpired());
  });

  bench('isExpired, one deadline', () => {
    consumeFlag(expiring.isExpired());
  });

  bench('isExpired, two sources', () => {
    consumeFlag(derived.isExpired());
  });

  bench('ttlRemaining', () => {
    consume(expiring.ttlRemaining());
  });

  bench('expiresAt', () => {
    consume(expiring.expiresAt);
  });

  bench('isRenewable', () => {
    consumeFlag(renewable.isRenewable());
  });
});

describe('what a deadline costs on reveal', () => {
  bench('no deadline', () => {
    consume(plain.reveal());
  });

  bench('one deadline', () => {
    consume(expiring.reveal());
  });

  bench('two sources', () => {
    consume(derived.reveal());
  });
});

describe('what a deadline costs on redaction', () => {
  bench('no deadline', () => {
    consume(plain.toString());
  });

  bench('one deadline', () => {
    consume(expiring.toString());
  });

  bench('two sources', () => {
    consume(derived.toString());
  });
});

describe('what a deadline costs on derivation', () => {
  bench('no deadline', () => {
    consume(plain.substring(0, 12));
  });

  bench('one deadline', () => {
    consume(expiring.substring(0, 12));
  });

  bench('two sources', () => {
    consume(derived.substring(0, 12));
  });
});

describe('renew', () => {
  // A fresh value per iteration, because renewal mutates the deadline and any
  // `maxRenewals` bound would be reached partway through a run.
  bench('construct then renew', () => {
    const value = new SensitiveString(TOKEN, 'sensitive', 'access_token', {
      ttl: 60_000,
      allowRenewal: true,
    });

    value.renew(60_000);
    consume(value.renewalCount);
  });

  bench('construct only (control)', () => {
    const value = new SensitiveString(TOKEN, 'sensitive', 'access_token', {
      ttl: 60_000,
      allowRenewal: true,
    });

    consume(value.renewalCount);
  });
});
