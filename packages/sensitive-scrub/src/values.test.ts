import { describe, expect, it } from 'vitest';

import { resolveScrubPolicy, ScrubPolicyError } from './policy.js';
import { scrubPayload } from './walk.js';
import { ALL_VALUE_PATTERNS, VALUE_PATTERNS, compileValuePatterns, matchValue } from './values.js';

/**
 * Q3's answer, tested.
 *
 * The shipped patterns are anchored, linear-time, and off unless a caller names
 * one. Each of those three is a separate failure mode and each has cases below.
 */

/** A subject each pattern should match, and one it should not. */
const SAMPLES: Record<string, { hit: string; miss: string }> = {
  jwt: {
    hit: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlLWhlcmU',
    miss: 'eyJhbGciOiJIUzI1NiJ9.no-third-segment',
  },
  bearer: {
    hit: 'Bearer abcdef0123456789abcdef',
    miss: 'Bearer short',
  },
  basicAuth: {
    hit: 'Basic dXNlcjpwYXNzd29yZA==',
    miss: 'Basic ',
  },
  pemPrivateKey: {
    hit: '-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----',
    miss: '-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END CERTIFICATE-----',
  },
  awsAccessKeyId: {
    hit: 'AKIAIOSFODNN7EXAMPLE',
    miss: 'AKIAIOSFODNN7EXAMPL',
  },
  githubToken: {
    hit: 'ghp_0123456789abcdefghijklmnopqrstuvwxyz',
    miss: 'ghx_0123456789abcdefghijklmnopqrstuvwxyz',
  },
  slackToken: {
    hit: 'xoxb-1234567890-abcdefghij',
    miss: 'xoxz-1234567890-abcdefghij',
  },
  openaiKey: {
    hit: 'sk-proj-0123456789abcdefghijkl',
    miss: 'sk-short',
  },
};

describe('the shipped patterns', () => {
  // TEST-SCRUB-VALUES-SAMPLES
  it.each(ALL_VALUE_PATTERNS)('%s matches its shape and not a near miss', (name) => {
    const sample = SAMPLES[name];

    expect(sample, `every shipped pattern needs a sample; ${name} has none`).toBeDefined();

    const compiled = compileValuePatterns([name]);

    expect(matchValue(sample?.hit ?? '', compiled)?.name).toBe(name);
    expect(matchValue(sample?.miss ?? '', compiled)).toBeNull();
  });

  // TEST-SCRUB-VALUES-ANCHORED
  it.each(ALL_VALUE_PATTERNS)('%s does not match its shape inside a larger string', (name) => {
    // Anchored at both ends. A pattern that matched a substring would censor a
    // whole log line to remove a token from the middle of it, and would turn a
    // linear scan into one per position.
    const compiled = compileValuePatterns([name]);
    const hit = SAMPLES[name]?.hit ?? '';

    expect(matchValue(`prefix ${hit}`, compiled)).toBeNull();
    expect(matchValue(`${hit} suffix`, compiled)).toBeNull();
  });

  // TEST-SCRUB-VALUES-TRAILING-NEWLINE
  it.each(ALL_VALUE_PATTERNS)('%s does not let a newline smuggle a second line past it', (name) => {
    // `$` also matches before a final line terminator in JavaScript, so a bare
    // end anchor would pass a value with anything at all on the next line.
    const compiled = compileValuePatterns([name]);
    const hit = SAMPLES[name]?.hit ?? '';

    expect(matchValue(`${hit}\nand something else`, compiled)).toBeNull();
  });

  // TEST-SCRUB-VALUES-FRESH
  it('hands back a fresh RegExp each time, carrying no lastIndex', () => {
    expect(VALUE_PATTERNS.jwt).not.toBe(VALUE_PATTERNS.jwt);

    for (const name of ALL_VALUE_PATTERNS) {
      expect(VALUE_PATTERNS[name].global, `${name} must not be global`).toBe(false);
      expect(VALUE_PATTERNS[name].sticky, `${name} must not be sticky`).toBe(false);
    }
  });

  // TEST-SCRUB-VALUES-LINEAR
  it.each(ALL_VALUE_PATTERNS)('%s stays linear on a pathological subject', (name) => {
    // Not a benchmark and not a gate on wall clock in general: this is a
    // catastrophic-backtracking check, where the failing case does not take
    // milliseconds longer but seconds to minutes.
    //
    // Every subject starts from the pattern's own matching sample and then
    // fails, which is the shape that makes an engine backtrack. A subject that
    // fails on the first character, which is what a bare run of one letter does
    // against an anchored pattern, is rejected immediately and proves nothing:
    // an earlier version of this case did exactly that and passed while
    // `openaiKey` took 266ms on the third subject below.
    const compiled = compileValuePatterns([name]);
    const hit = SAMPLES[name]?.hit ?? '';

    const subjects = [
      // A long run of characters the pattern's trailing class accepts.
      `${hit}${'a'.repeat(20000)}!`,
      // The same, hyphenated, which is what splits an optional infix group from
      // the class after it when the two share a character.
      `${hit}${'a-'.repeat(10000)}!`,
      // A prefix that commits the pattern to its slow path and then never ends.
      `${hit.slice(0, 8)}${'a'.repeat(20000)}!`,
    ];

    for (const subject of subjects) {
      const started = performance.now();

      matchValue(subject, compiled);

      expect(
        performance.now() - started,
        `${name} on a ${subject.length} character subject`
      ).toBeLessThan(50);
    }
  });
});

describe('resolution', () => {
  it('is off unless a caller names a pattern', () => {
    expect(resolveScrubPolicy().denyValues).toEqual([]);
    expect(resolveScrubPolicy({ denyValues: [] }).denyValues).toEqual([]);
  });

  it('names an unknown pattern at install time', () => {
    expect(() => resolveScrubPolicy({ denyValues: ['jwtt' as 'jwt'] })).toThrow(ScrubPolicyError);
    expect(() => resolveScrubPolicy({ denyValues: ['jwtt' as 'jwt'] })).toThrow(/jwt, bearer/);
  });

  it('takes a caller own RegExp and reports it by its source', () => {
    const compiled = compileValuePatterns([/^token-[0-9]+$/]);

    expect(matchValue('token-42', compiled)?.name).toBe('/^token-[0-9]+$/');
    expect(matchValue('token-x', compiled)).toBeNull();
  });

  it('strips the flags that would make a caller pattern miss every other subject', () => {
    // A global or sticky pattern carries `lastIndex` between calls, so the same
    // subject matches on one payload and not the next.
    const compiled = compileValuePatterns([/^token$/gi]);

    expect(compiled[0]?.pattern.global).toBe(false);
    expect(compiled[0]?.pattern.sticky).toBe(false);
    expect(compiled[0]?.pattern.ignoreCase).toBe(true);
    expect(matchValue('TOKEN', compiled)).not.toBeNull();
    expect(matchValue('TOKEN', compiled)).not.toBeNull();
  });
});

describe('in the walk', () => {
  // TEST-SCRUB-VALUES-WALK
  it('censors a matching value under any key, at any depth', () => {
    const policy = resolveScrubPolicy({ denyValues: ['bearer'] });
    const { payload, report } = scrubPayload(
      { deep: { nested: { anything: 'Bearer abcdef0123456789abcdef', note: 'keep' } } },
      policy,
      'event'
    );

    const walked = payload as { deep: { nested: { anything: string; note: string } } };

    expect(walked.deep.nested.anything).toBe('[SCRUBBED]');
    expect(walked.deep.nested.note).toBe('keep');
    expect(report.deniedValues).toEqual(['bearer']);
  });

  it('reports the shape and never the value', () => {
    const policy = resolveScrubPolicy({ denyValues: ['awsAccessKeyId'] });
    const { report } = scrubPayload({ id: 'AKIAIOSFODNN7EXAMPLE' }, policy, 'event');

    expect(report.deniedValues).toEqual(['awsAccessKeyId']);
    expect(JSON.stringify(report)).not.toContain('AKIAIOSFODNN7EXAMPLE');
    // Not where it matched, either. A path plus a shape name is a map of where
    // to look.
    expect(JSON.stringify(report)).not.toContain('id');
  });

  it('leaves a marker stage 1 already wrote alone', () => {
    // The rule 14.1 of the design settled for the key denylist, applied to the
    // value one: a marker names its class and the censor does not.
    const policy = resolveScrubPolicy({ denyValues: [/^\[REDACTED:credential\]$/] });
    const { payload } = scrubPayload({ a: '[REDACTED:credential]' }, policy, 'event');

    expect((payload as { a: string }).a).toBe('[SCRUBBED]');
  });

  it('runs after the URL branch, so a route survives', () => {
    const policy = resolveScrubPolicy({
      urlKeys: ['url'],
      denyValues: [/^https:.*$/],
    });

    const { payload } = scrubPayload({ url: 'https://api.test/pay?token=abc' }, policy, 'event');

    // The URL branch won, so the route and the parameter names survive. The
    // censor is written back in its literal form rather than the
    // percent-encoded one `URLSearchParams` produces, because the point of
    // rewriting a URL rather than dropping it is that somebody reads the result.
    expect((payload as { url: string }).url).toBe('https://api.test/pay?token=[SCRUBBED]');
  });

  it('costs nothing when no pattern is configured', () => {
    const policy = resolveScrubPolicy();
    const { payload, report } = scrubPayload(
      { a: 'Bearer abcdef0123456789abcdef' },
      policy,
      'event'
    );

    expect((payload as { a: string }).a).toBe('Bearer abcdef0123456789abcdef');
    expect(report.deniedValues).toEqual([]);
  });
});
