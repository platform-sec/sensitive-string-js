/**
 * Deterministic Redaction Security Tests
 *
 * The feature deliberately weakens a guarantee: redacted output stops being
 * constant and starts carrying a keyed fingerprint of the value. What must
 * still hold is everything either side of that. The tag must not contain the
 * value, the key, or the scope; it must not be reproducible by anyone who does
 * not hold the key, which is what separates this from the plain-hash version
 * the design sketch proposed; and two values must not collide often enough to
 * merge two subjects into one in a log.
 *
 * The known-plaintext suite is the one ROADMAP 6.1 names by hand, and it is the
 * reason the unkeyed mode does not exist.
 */

import { createHash, createHmac, randomBytes } from 'node:crypto';
import { inspect } from 'node:util';
import { afterEach, describe, expect, it } from 'vitest';

import {
  createDeterministicRedactor,
  deterministicRedaction,
  getPolicy,
  MIN_DERIVED_TOKEN_LENGTH,
  redactCopy,
  redactInStructure,
  registerPolicy,
  resetPolicies,
  safeStringify,
  SensitiveString,
} from '../index.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';
const KEY_HEX = '5b0f2c8ad14e3f97a6b2c8d40e1f5a3b6c9d2e8f1a4b7c0d3e6f9a2b5c8d1e4f';
const KEY = Buffer.from(KEY_HEX, 'hex');
const SCOPE = 'LEAKED_SCOPE_session_7f3a';

/** Every rendering path a value can reach a log through. */
const RENDERINGS: readonly (readonly [string, (value: SensitiveString<'sensitive'>) => string])[] =
  [
    ['toString', (v) => v.toString()],
    [
      'template',
      // eslint-disable-next-line @typescript-eslint/restrict-template-expressions -- the implicit coercion is the path under test
      (v) => `${v}`,
    ],
    ['toJSON', (v) => v.toJSON()],
    ['JSON.stringify', (v) => JSON.stringify({ v })],
    ['inspect', (v) => inspect({ v }, { depth: 5 })],
    ['safeStringify', (v) => safeStringify({ v })],
    ['redactInStructure', (v) => JSON.stringify(redactInStructure({ nested: { v } }))],
    // The path the error tracking and APM integrations redact through, which is
    // how a tag reaches Sentry, Bugsnag, Rollbar and a Datadog span.
    ['redactCopy', (v) => JSON.stringify(redactCopy({ nested: { v } }))],
    ['serialize caught in a log', (v) => safeStringify({ wire: v.serialize() })],
    ['mask below its floor', (v) => v.mask({ showFirst: 1, minMasked: 999 })],
  ];

function install(options: Parameters<typeof deterministicRedaction>[1] = { key: KEY }): void {
  registerPolicy(deterministicRedaction('sensitive', options), { overwrite: true });
}

afterEach(() => {
  resetPolicies();
});

describe('the tag discloses nothing it was derived from', () => {
  // TEST-DR-S001
  it.each(RENDERINGS)('%s does not carry the value', (_label, render) => {
    install({ key: KEY, scope: SCOPE });

    const rendered = render(new SensitiveString(CANARY, 'sensitive', 'email'));

    expect(rendered).not.toContain(CANARY);

    // And no run of it either, which is what catches a partial leak that a
    // whole-string check would miss.
    for (let i = 0; i + 4 <= CANARY.length; i++) {
      expect(rendered).not.toContain(CANARY.slice(i, i + 4));
    }
  });

  // TEST-DR-S002
  it.each(RENDERINGS)('%s does not carry the key', (_label, render) => {
    install({ key: KEY, scope: SCOPE });

    const rendered = render(new SensitiveString(CANARY, 'sensitive'));

    expect(rendered).not.toContain(KEY_HEX);
    expect(rendered).not.toContain(KEY.toString('base64'));
    expect(rendered).not.toContain(KEY.toString('latin1'));

    for (let i = 0; i + 8 <= KEY_HEX.length; i++) {
      expect(rendered).not.toContain(KEY_HEX.slice(i, i + 8));
    }
  });

  // TEST-DR-S003
  it.each(RENDERINGS)('%s does not carry the scope', (_label, render) => {
    install({ key: KEY, scope: SCOPE });

    const rendered = render(new SensitiveString(CANARY, 'sensitive'));

    expect(rendered).not.toContain(SCOPE);
    expect(rendered).not.toContain('LEAKED_SCOPE');
  });

  // TEST-DR-S004
  it('renders a tag of hex characters and nothing else', () => {
    install();

    const rendering = getPolicy('sensitive').redact(CANARY);

    expect(rendering).toMatch(/^\[REDACTED:sensitive:[0-9a-f]+\]$/);
  });

  it('renders a tag of hex characters for a value made of control bytes', () => {
    install();

    const hostile = `\u0000\u001b[31m\n\r"'\\${'\u2028'}${'\ud83d\ude00'}`;

    expect(getPolicy('sensitive').redact(hostile)).toMatch(/^\[REDACTED:sensitive:[0-9a-f]+\]$/);
  });

  it('is refused by the redaction validation if a caller tries to render the value', () => {
    // The guard registerPolicy already applies, restated here because this
    // feature is the first one that makes redacted output value-dependent, and
    // "value-dependent" is one edit away from "the value".
    expect(() =>
      registerPolicy(
        { ...getPolicy('sensitive'), redact: (value) => `[REDACTED:${value}]` },
        { overwrite: true }
      )
    ).toThrow(/must not include the original value/);
  });
});

describe('the tag cannot be reproduced without the key', () => {
  // TEST-DR-S005, and the ROADMAP 6.1 requirement in its concrete form: an
  // attacker who holds the log, the plaintext and the algorithm, and who lacks
  // only the key, gets nothing. This is the whole argument for refusing the
  // unkeyed mode the design sketch defaulted to.
  it('does not match the plain digest the design sketch would have produced', () => {
    install();

    const tag = getPolicy('sensitive').redact(CANARY);

    for (const algorithm of ['sha256', 'sha384', 'sha512']) {
      const digest = createHash(algorithm).update(CANARY, 'utf8').digest('hex');

      expect(tag).not.toContain(digest.slice(0, MIN_DERIVED_TOKEN_LENGTH));
    }
  });

  it('does not match a digest the attacker salts with the scope, which is guessable', () => {
    install({ key: KEY, scope: SCOPE });

    const tag = getPolicy('sensitive').redact(CANARY);
    const salted = createHash('sha256').update(SCOPE).update(CANARY).digest('hex');

    expect(tag).not.toContain(salted.slice(0, MIN_DERIVED_TOKEN_LENGTH));
  });

  it('survives a known-plaintext attacker guessing the key', () => {
    install();

    const tag = getPolicy('sensitive').redact(CANARY);
    const guesses = new Set<string>();

    // The attacker knows the plaintext, the construction, and the tag. Only the
    // key is missing, and 2,000 guesses at it produce 2,000 wrong tags.
    for (let i = 0; i < 2000; i++) {
      const guess = createHmac('sha256', randomBytes(32))
        .update('sensitive', 'utf8')
        .update(new Uint8Array([0]))
        .update(CANARY, 'utf8')
        .digest('hex')
        .slice(0, MIN_DERIVED_TOKEN_LENGTH);

      guesses.add(`[REDACTED:sensitive:${guess}]`);
    }

    expect(guesses.has(tag)).toBe(false);
  });

  it('breaks correlation across a key rotation', () => {
    install({ key: KEY });
    const before = getPolicy('sensitive').redact(CANARY);

    install({ key: randomBytes(32) });

    expect(getPolicy('sensitive').redact(CANARY)).not.toBe(before);
  });

  it('breaks correlation across a scope, which is what bounds it to a session', () => {
    install({ key: KEY, scope: 'sess-1' });
    const first = getPolicy('sensitive').redact(CANARY);

    install({ key: KEY, scope: 'sess-2' });

    expect(getPolicy('sensitive').redact(CANARY)).not.toBe(first);
  });
});

describe('collisions', () => {
  /**
   * Deterministic inputs, not random ones. A collision test seeded from
   * `randomBytes` reports a different experiment every run and would flake at
   * whatever rate the bound predicts, which is the one thing a collision test
   * must not do.
   */
  function tags(count: number, length: number): Set<string> {
    const redact = createDeterministicRedactor({ key: KEY, length });
    const seen = new Set<string>();

    for (let i = 0; i < count; i++) {
      seen.add(redact(`subject-${i}@example.com`));
    }

    return seen;
  }

  // TEST-DR-C001, at the length this library actually ships. The sketch asked
  // for 1,000 values at eight characters; twelve is the floor here, so the same
  // check runs an order of magnitude wider.
  it('gives 10,000 values 10,000 distinct tags at the default length', () => {
    expect(tags(10_000, MIN_DERIVED_TOKEN_LENGTH).size).toBe(10_000);
  });

  // TEST-DR-C002 in the only form it can take: the sketch's four-character tag
  // is not buildable, because a collision merges two subjects into one and the
  // floor is where that stops being a tuning knob.
  it.each([2, 4, 8, MIN_DERIVED_TOKEN_LENGTH - 1])(
    'refuses a %i-character tag rather than documenting its collision rate',
    (length) => {
      expect(() => createDeterministicRedactor({ key: KEY, length })).toThrow(RangeError);
    }
  );

  // TEST-DR-C003
  it('gives 100,000 values 100,000 distinct tags at 16 characters', () => {
    expect(tags(100_000, 16).size).toBe(100_000);
  });
});

describe('what the feature does not change', () => {
  it('leaves the other class alone, so a credential keeps its constant redaction', () => {
    install();

    expect(getPolicy('credential').redact(CANARY)).toBe('[REDACTED:credential]');
  });

  it('keeps the raw value behind the reveal gate', () => {
    install();

    const value = new SensitiveString(CANARY, 'sensitive', 'email');

    // The tag is derived from the value inside the redaction path, which is the
    // one place the library reads it without authorizing. Nothing about that
    // path hands the value out.
    expect(value.toString()).not.toContain(CANARY);
    expect(value.reveal({ name: 'test', reason: 'assert the gate still works' })).toBe(CANARY);
  });

  it('never lets a redaction re-enter the gate, tag or no tag', () => {
    // A redactor that revealed would be a way around the audit trail, and a
    // redactor is caller code registered in a policy. `redact` receives the raw
    // string rather than the instance, so it has nothing to reveal from; this
    // pins that argument shape.
    const seen: unknown[] = [];

    registerPolicy(
      {
        ...getPolicy('sensitive'),
        redact: (...args: unknown[]) => {
          seen.push(...args);
          return '[REDACTED:sensitive]';
        },
      },
      { overwrite: true, skipRedactValidation: true }
    );

    new SensitiveString(CANARY, 'sensitive').toString();

    expect(seen).toEqual([CANARY]);
  });
});
