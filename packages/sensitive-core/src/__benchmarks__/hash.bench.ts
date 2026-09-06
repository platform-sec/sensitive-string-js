/**
 * Digests, and what protecting one costs over computing it.
 *
 * Three questions. The first group prices `hash()` against the `node:crypto`
 * call it wraps, so the gate, the audit record and the derived instance can be
 * read as a constant on top of the digest. The second prices the algorithms
 * against each other over one length, and the third prices SHA-256 across
 * lengths, where per-byte work eventually dominates the per-call constant.
 *
 * Read every group as a ratio within itself, after subtracting the harness
 * floor. A digest of a 64-character token is cheap enough that the floor is a
 * visible share of it.
 */

import { bench, describe } from 'vitest';
import { createHash, createHmac, randomBytes } from 'node:crypto';

import { SensitiveString } from '../sensitive-string.js';
import type { RevealContext } from '../types.js';
import { benchFloor, consume, LENGTHS, TOKEN, valueOfLength } from './fixtures.js';

const value = new SensitiveString(TOKEN, 'sensitive', 'token');
const credential = new SensitiveString(TOKEN, 'credential', 'token');

/** 32 bytes, the recommended key size, and above the 16-byte floor. */
const KEY = randomBytes(32);
const SALT = randomBytes(16);

/** A protected key, which is read through its own gate on every call. */
const protectedKey = new SensitiveString(KEY.toString('base64'), 'credential', 'correlation_key');

/** Counted rather than logged, so the hook does real work without doing I/O. */
let audited = 0;
const AUDITING: RevealContext = {
  name: 'bench-audited',
  reason: 'benchmark',
  auditReveal: () => {
    audited += 1;
  },
};

const bySize = LENGTHS.map((length) => ({
  length,
  value: new SensitiveString(valueOfLength(length), 'sensitive', 'token'),
}));

describe('sha256 of a 64 character value', () => {
  bench('node:crypto directly (control)', () => {
    consume(createHash('sha256').update(TOKEN, 'utf8').digest('hex'));
  });

  bench('hash()', () => {
    consume(value.hash('sha256'));
  });

  bench('hash() on a credential', () => {
    consume(credential.hash('sha256'));
  });

  bench('hash() with a salt', () => {
    consume(value.hash('sha256', { salt: SALT }));
  });

  bench('hash() with an audit hook', () => {
    consume(value.hash('sha256', {}, AUDITING));
  });

  bench('hash() then reveal the digest', () => {
    consume(value.hash('sha256').reveal());
  });
});

describe('keyed digests of a 64 character value', () => {
  bench('node:crypto directly (control)', () => {
    consume(createHmac('sha256', KEY).update(TOKEN, 'utf8').digest('hex'));
  });

  bench('hmac() with a raw key', () => {
    consume(value.hmac('sha256', KEY));
  });

  bench('hmac() with a protected key', () => {
    consume(value.hmac('sha256', protectedKey));
  });
});

describe('algorithms over a 64 character value', () => {
  for (const algorithm of ['sha256', 'sha384', 'sha512', 'sha3-256', 'sha3-512'] as const) {
    bench(algorithm, () => {
      consume(value.hash(algorithm));
    });
  }
});

describe('sha256 by value length', () => {
  for (const { length, value: sized } of bySize) {
    bench(`${length} chars`, () => {
      consume(sized.hash('sha256'));
    });
  }
});

describe('digest encodings of a 64 character value', () => {
  for (const encoding of ['hex', 'base64', 'base64url'] as const) {
    bench(encoding, () => {
      consume(value.hash('sha256', { encoding }));
    });
  }
});

describe('hash audit count', () => {
  // The counter is read so the hook above cannot be optimized to nothing.
  bench('report', () => {
    consume(audited);
  });
});

benchFloor();
