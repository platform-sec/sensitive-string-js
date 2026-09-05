/**
 * Construction, policy lookup, and the template tag.
 *
 * Construction is the operation a service performs most, because every value
 * that arrives from a secrets manager, a request body, or an environment
 * variable is wrapped once on the way in. The control in the first group is a
 * plain object holding the same string, so the group reports what wrapping
 * costs over the cheapest thing that could hold a value.
 */

import { bench, describe } from 'vitest';

import { SensitiveString } from '../sensitive-string.js';
import { getDefaultPolicy, getPolicy, hasPolicy, getRegisteredClasses } from '../policy.js';
import { st } from '../template.js';
import { benchFloor, consume, LENGTHS, TOKEN, valueOfLength } from './fixtures.js';

/**
 * Read once, so the sweep does not measure `Date` allocation, and far enough
 * out that it stays in the future for the whole run.
 */
const DEADLINE = new Date(Date.now() + 3_600_000);

describe('construction', () => {
  bench('plain object holding the string (control)', () => {
    consume({ value: TOKEN });
  });

  bench('sensitive', () => {
    consume(new SensitiveString(TOKEN, 'sensitive'));
  });

  bench('credential', () => {
    consume(new SensitiveString(TOKEN, 'credential'));
  });

  bench('credential with label', () => {
    consume(new SensitiveString(TOKEN, 'credential', 'access_token'));
  });

  bench('credential with ttl', () => {
    consume(new SensitiveString(TOKEN, 'credential', 'access_token', { ttl: 3_600_000 }));
  });

  bench('credential with expiresAt', () => {
    consume(new SensitiveString(TOKEN, 'credential', 'access_token', { expiresAt: DEADLINE }));
  });

  bench('credential with renewal bounds', () => {
    consume(
      new SensitiveString(TOKEN, 'credential', 'access_token', {
        ttl: 3_600_000,
        allowRenewal: true,
        maxRenewals: 3,
      })
    );
  });
});

describe('construction by value length', () => {
  for (const length of LENGTHS) {
    const value = valueOfLength(length);

    bench(`${length} chars`, () => {
      consume(new SensitiveString(value, 'credential'));
    });
  }
});

describe('policy lookup', () => {
  bench('getPolicy', () => {
    consume(getPolicy('credential'));
  });

  bench('getDefaultPolicy', () => {
    consume(getDefaultPolicy());
  });

  bench('hasPolicy', () => {
    consume(hasPolicy('credential'));
  });

  bench('getRegisteredClasses', () => {
    consume(getRegisteredClasses());
  });
});

describe('template tag', () => {
  const token = new SensitiveString(TOKEN, 'credential', 'access_token');
  const userId = 'usr_8812';
  const tag = st({ klass: 'credential', label: 'auth_header' });

  bench('plain interpolation then wrap (control)', () => {
    consume(new SensitiveString(`Bearer ${TOKEN} for ${userId}`, 'credential'));
  });

  bench('st, class inherited from interpolations', () => {
    consume(st`Bearer ${token} for ${userId}`);
  });

  bench('st, configured tag', () => {
    consume(tag`Bearer ${token} for ${userId}`);
  });

  bench('st, no sensitive interpolation', () => {
    consume(st`Bearer ${userId}`);
  });
});

benchFloor();
