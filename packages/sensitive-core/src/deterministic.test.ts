import { createHmac } from 'node:crypto';
import { inspect } from 'node:util';
import { afterEach, describe, expect, it } from 'vitest';

import {
  createDeterministicRedactor,
  deterministicRedaction,
  DeterministicRedactionNotAllowedError,
} from './deterministic.js';
import {
  DEFAULT_DERIVED_TOKEN_LENGTH,
  MAX_DERIVED_TOKEN_LENGTH,
  MIN_DERIVATION_KEY_BYTES,
  MIN_DERIVED_TOKEN_LENGTH,
} from './derive.js';
import { getPolicy, registerPolicy, resetPolicies } from './policy.js';
import { SensitiveString } from './sensitive-string.js';
import { safeStringify } from './redact.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';
const OTHER = 'LEAKED_SECRET_zyx321cba';
const KEY = new Uint8Array(32).fill(7);
const OTHER_KEY = new Uint8Array(32).fill(9);

/** The rendering of `value` under the class policy currently registered. */
function redacted(value: string, klass: 'sensitive' | 'credential' = 'sensitive'): string {
  return getPolicy(klass).redact(value);
}

/** The tag inside `[prefix:tag]`, for a test that cares about the tag alone. */
function tagOf(rendering: string): string {
  const tag = /^\[[A-Za-z0-9_.:-]+:([0-9a-f]+)\]$/.exec(rendering)?.[1];

  expect(tag, `no tag in ${rendering}`).toBeDefined();

  return tag as string;
}

afterEach(() => {
  resetPolicies();
});

describe('createDeterministicRedactor', () => {
  describe('the derivation', () => {
    // TEST-DR-F005, in the form this library can hold it: the algorithm is
    // fixed rather than chosen, so what is worth asserting is which one, and in
    // what order the inputs go in. Written longhand rather than against a
    // golden string, so the test says what the construction is.
    it('is HMAC-SHA256 over the NUL-separated scope and the value, truncated', () => {
      const hmac = createHmac('sha256', KEY);
      hmac.update('tenant-7', 'utf8');
      hmac.update(new Uint8Array([0]));
      hmac.update(CANARY, 'utf8');

      expect(createDeterministicRedactor({ key: KEY, scope: 'tenant-7' })(CANARY)).toBe(
        `[REDACTED:${hmac.digest('hex').slice(0, DEFAULT_DERIVED_TOKEN_LENGTH)}]`
      );
    });

    // TEST-DR-F001
    it('renders the same value the same way, every time and in every instance', () => {
      const first = createDeterministicRedactor({ key: KEY });
      const second = createDeterministicRedactor({ key: KEY });

      expect(first(CANARY)).toBe(first(CANARY));
      expect(second(CANARY)).toBe(first(CANARY));
    });

    // TEST-DR-F002
    it('renders two values two ways', () => {
      const redact = createDeterministicRedactor({ key: KEY });

      expect(redact(CANARY)).not.toBe(redact(OTHER));
    });

    // TEST-DR-F007
    it('renders the same value differently under a different key', () => {
      expect(createDeterministicRedactor({ key: KEY })(CANARY)).not.toBe(
        createDeterministicRedactor({ key: OTHER_KEY })(CANARY)
      );
    });

    // TEST-DR-F006, which the design sketch spelled `salt`. A scope is a domain
    // component rather than a salt: it is mixed in ahead of the value under the
    // same key, and it exists to bound how far a tag correlates.
    it('renders the same value differently under a different scope', () => {
      const unscoped = createDeterministicRedactor({ key: KEY });
      const session = createDeterministicRedactor({ key: KEY, scope: 'sess-1' });
      const other = createDeterministicRedactor({ key: KEY, scope: 'sess-2' });

      expect(session(CANARY)).not.toBe(unscoped(CANARY));
      expect(session(CANARY)).not.toBe(other(CANARY));
    });

    /**
     * The redactor reads the components on every rendering, so an array kept by
     * reference would let a `push()` after construction move every tag that
     * followed it, and would let a component past the validation that ran once.
     * A non-string pushed in later does not produce a wrong tag, it makes
     * `redact()` throw on the path a log line takes.
     */
    it('copies the scope, so mutating it afterwards moves nothing', () => {
      const scope = ['sess-1'];
      const redact = createDeterministicRedactor({ key: KEY, scope });
      const before = redact(CANARY);

      scope.push('mutated');

      expect(redact(CANARY)).toBe(before);

      scope.push(null as unknown as string);

      expect(redact(CANARY)).toBe(before);
    });

    /**
     * The same rule as the scope, and it bites harder: a zeroed key is still a
     * valid key, so a caller who wiped the array they passed would move every
     * tag afterwards with no error anywhere to say so.
     */
    it("copies the key, so zeroizing the caller's array afterwards moves nothing", () => {
      const key = new Uint8Array(32).fill(7);
      const redact = createDeterministicRedactor({ key });
      const before = redact(CANARY);

      key.fill(0);

      expect(redact(CANARY)).toBe(before);
    });

    it('reads a string scope as one component, not as a character sequence', () => {
      expect(createDeterministicRedactor({ key: KEY, scope: 'sess-1' })(CANARY)).toBe(
        createDeterministicRedactor({ key: KEY, scope: ['sess-1'] })(CANARY)
      );
    });

    /**
     * The separator is what stops two scopes sharing a token space. With an
     * ordinary joining character these two would derive identically, and a
     * caller could pick a scope that impersonated the segment after it.
     */
    it('separates scope components so they cannot be reassociated', () => {
      expect(createDeterministicRedactor({ key: KEY, scope: ['a', 'bc'] })(CANARY)).not.toBe(
        createDeterministicRedactor({ key: KEY, scope: ['ab', 'c'] })(CANARY)
      );
    });

    // TEST-DR-F009. An empty value correlates with every other empty value,
    // which is correct: they are the same value. Worth an explicit test
    // because it is also the shape a future `clear()` has to avoid rendering,
    // or every cleared value in a log would share one tag.
    it('renders an empty value rather than refusing it', () => {
      const redact = createDeterministicRedactor({ key: KEY });

      expect(tagOf(redact(''))).toHaveLength(DEFAULT_DERIVED_TOKEN_LENGTH);
      expect(redact('')).not.toBe(redact(CANARY));
    });

    // TEST-DR-F010
    it('renders a value far longer than the digest', () => {
      const long = CANARY.repeat(100_000);
      const redact = createDeterministicRedactor({ key: KEY });

      expect(tagOf(redact(long))).toHaveLength(DEFAULT_DERIVED_TOKEN_LENGTH);
      expect(redact(long)).not.toBe(redact(`${long}x`));
    });
  });

  describe('the rendering', () => {
    // TEST-DR-F003
    it('uses the prefix the caller supplied', () => {
      expect(createDeterministicRedactor({ key: KEY, prefix: 'PII' })(CANARY)).toMatch(
        /^\[PII:[0-9a-f]{12}\]$/
      );
    });

    // TEST-DR-F004
    it.each([MIN_DERIVED_TOKEN_LENGTH, 16, 32, MAX_DERIVED_TOKEN_LENGTH])(
      'keeps %i hex characters when asked for them',
      (length) => {
        expect(tagOf(createDeterministicRedactor({ key: KEY, length })(CANARY))).toHaveLength(
          length
        );
      }
    );

    it('keeps the default length when asked for nothing', () => {
      expect(tagOf(createDeterministicRedactor({ key: KEY })(CANARY))).toHaveLength(
        DEFAULT_DERIVED_TOKEN_LENGTH
      );
    });

    it('truncates rather than rehashing, so a longer tag extends a shorter one', () => {
      const short = tagOf(createDeterministicRedactor({ key: KEY, length: 12 })(CANARY));
      const long = tagOf(createDeterministicRedactor({ key: KEY, length: 32 })(CANARY));

      expect(long.startsWith(short)).toBe(true);
    });

    // TEST-DR-F008
    it('applies a custom format', () => {
      const redact = createDeterministicRedactor({
        key: KEY,
        prefix: 'PII',
        format: (prefix, tag) => `<${prefix}#${tag}>`,
      });

      expect(redact(CANARY)).toMatch(/^<PII#[0-9a-f]{12}>$/);
    });

    it('hands a custom format the prefix and the tag and nothing else', () => {
      const seen: unknown[][] = [];

      createDeterministicRedactor({
        key: KEY,
        format: (...args) => {
          seen.push(args);
          return 'x';
        },
      })(CANARY);

      // Two arguments, neither of which is the value: the whole reason a
      // caller-supplied renderer is safe to accept here.
      for (const args of seen) {
        expect(args).toHaveLength(2);
        expect(args).not.toContain(CANARY);
      }
    });
  });

  describe('refusals', () => {
    // The ROADMAP 6.1 constraint, and the one that decides whether this
    // feature is safe at all: an unkeyed digest of a low-entropy value is a
    // wordlist lookup, so there is no unkeyed mode to fall back to.
    it('refuses to build without a key', () => {
      expect(() => createDeterministicRedactor({} as { key: Uint8Array })).toThrow(TypeError);
      expect(() =>
        createDeterministicRedactor({ key: undefined as unknown as Uint8Array })
      ).toThrow(/key must be/);
    });

    it('refuses a key below the entropy floor', () => {
      expect(() =>
        createDeterministicRedactor({ key: new Uint8Array(MIN_DERIVATION_KEY_BYTES - 1) })
      ).toThrow(RangeError);
    });

    // The design sketch defaulted to eight hex characters. `derive.ts` puts
    // the floor at twelve and says why: at 32 bits a one-in-a-thousand
    // collision arrives at about 3,000 distinct values, and a collision merges
    // two subjects into one in the log.
    it.each([4, 8, MIN_DERIVED_TOKEN_LENGTH - 1])(
      'refuses a %i-character tag, which is below the collision floor',
      (length) => {
        expect(() => createDeterministicRedactor({ key: KEY, length })).toThrow(RangeError);
      }
    );

    it('refuses a tag longer than the digest', () => {
      expect(() =>
        createDeterministicRedactor({ key: KEY, length: MAX_DERIVED_TOKEN_LENGTH + 1 })
      ).toThrow(RangeError);
    });

    it.each([
      ['empty', ''],
      ['spaced', 'REDACTED VALUE'],
      ['bracketed', '[REDACTED]'],
      ['over-long', 'p'.repeat(65)],
    ])('refuses a %s prefix, which would not stay one searchable token', (_label, prefix) => {
      expect(() => createDeterministicRedactor({ key: KEY, prefix })).toThrow(TypeError);
    });

    it('refuses a scope component carrying the separator', () => {
      expect(() =>
        createDeterministicRedactor({ key: KEY, scope: [`a${String.fromCharCode(0)}b`] })
      ).toThrow(TypeError);
    });

    it('refuses a scope that is neither a string nor an array', () => {
      expect(() =>
        createDeterministicRedactor({ key: KEY, scope: 7 as unknown as string })
      ).toThrow(TypeError);
    });

    // Every one of these is settled at construction rather than at the first
    // log line, which is the point: a redaction runs on the path a log line
    // takes, and a configuration error discovered there is discovered by
    // logging failing.
    it('refuses a format that throws, before it can take down a log line', () => {
      expect(() =>
        createDeterministicRedactor({
          key: KEY,
          format: () => {
            throw new Error('boom');
          },
        })
      ).toThrow('boom');
    });

    it('refuses a format that answers with something other than a string', () => {
      expect(() =>
        createDeterministicRedactor({
          key: KEY,
          format: (() => 42) as unknown as (prefix: string, tag: string) => string,
        })
      ).toThrow(/must return a string, received number/);
    });

    it('refuses a format that is not a function', () => {
      expect(() =>
        createDeterministicRedactor({
          key: KEY,
          format: 'nope' as unknown as (prefix: string, tag: string) => string,
        })
      ).toThrow(/format must be a function/);
    });

    it('refuses options that are not an object', () => {
      expect(() => createDeterministicRedactor(null as unknown as { key: Uint8Array })).toThrow(
        /must carry at least a key/
      );
    });
  });
});

describe('deterministicRedaction', () => {
  it('renders the ROADMAP shape, with the class in the prefix', () => {
    expect(deterministicRedaction('sensitive', { key: KEY }).redact(CANARY)).toMatch(
      /^\[REDACTED:sensitive:[0-9a-f]{12}\]$/
    );
  });

  it('mixes the class into the derivation, so one string classified twice tags twice', () => {
    // Not comparable across classes today, since `credential` is refused, so
    // the observable form is that the policy's tag differs from the bare
    // redactor's over the same key and scope.
    const policy = deterministicRedaction('sensitive', { key: KEY, scope: 's' });
    const bare = createDeterministicRedactor({ key: KEY, scope: 's' });

    expect(tagOf(policy.redact(CANARY))).not.toBe(tagOf(bare(CANARY)));

    // And it is the class that made the difference, in the documented position.
    expect(tagOf(policy.redact(CANARY))).toBe(
      tagOf(createDeterministicRedactor({ key: KEY, scope: ['s', 'sensitive'] })(CANARY))
    );
  });

  it('keeps every other field of the class policy it replaces', () => {
    registerPolicy(
      {
        ...getPolicy('sensitive'),
        allowMask: false,
        advisory: { criticality: 'high' },
        checkRevealAllowed: () => undefined,
      },
      { overwrite: true }
    );

    const base = getPolicy('sensitive');
    const tagged = deterministicRedaction('sensitive', { key: KEY });

    expect(tagged.name).toBe('sensitive');
    expect(tagged.allowMask).toBe(false);
    expect(tagged.advisory).toEqual({ criticality: 'high' });
    /* eslint-disable @typescript-eslint/unbound-method --
       identity is exactly what is being asserted: the hook must survive the
       replacement as the same function, and the redaction must not. Neither is
       called here. */
    expect(tagged.checkRevealAllowed).toBe(base.checkRevealAllowed);
    expect(tagged.redact).not.toBe(base.redact);
    /* eslint-enable @typescript-eslint/unbound-method */
  });

  it('lets a caller override the prefix the class would have supplied', () => {
    expect(deterministicRedaction('sensitive', { key: KEY, prefix: 'PII' }).redact(CANARY)).toMatch(
      /^\[PII:[0-9a-f]{12}\]$/
    );
  });

  it('refuses a credential, which is guessable and so must not be tagged', () => {
    expect(() => deterministicRedaction('credential', { key: KEY })).toThrow(
      DeterministicRedactionNotAllowedError
    );
    expect(() => deterministicRedaction('credential', { key: KEY })).toThrow(/credential/);
  });

  it('reports a missing key rather than a missing policy, and the other way round', () => {
    expect(() => deterministicRedaction('sensitive', {} as { key: Uint8Array })).toThrow(
      /key must be/
    );
    expect(() => deterministicRedaction('nope' as 'sensitive', { key: KEY })).toThrow(
      /No policy registered/
    );
  });

  it('refuses options that are not an object', () => {
    expect(() =>
      deterministicRedaction('sensitive', null as unknown as { key: Uint8Array })
    ).toThrow(/must carry at least a key/);
  });

  // A caller who passed a bad prefix to `deterministicRedaction` should not be
  // told about a function that appears nowhere in their code.
  it.each([
    ['a prefix', { key: KEY, prefix: 'bad prefix' }],
    ['a scope', { key: KEY, scope: 7 as unknown as string }],
    ['a format', { key: KEY, format: 'nope' as unknown as () => string }],
    ['options', null as unknown as { key: Uint8Array }],
  ])('names itself, not the primitive, when %s is wrong', (_label, options) => {
    expect(() => deterministicRedaction('sensitive', options)).toThrow(/^deterministicRedaction: /);
  });
});

/**
 * The guards that refuse to send a redaction onward, `assertNoMarker` in the
 * HTTP clients chief among them, learn a policy's marker by redacting two
 * probes of different lengths and keeping the answer when both agree. A
 * value-dependent policy defeats that test by construction, so it declares its
 * shape instead. Without this a custom `prefix` silently blinds the guard.
 */
describe('the marker pattern', () => {
  it.each([
    ['the default shape', { key: KEY }],
    ['a custom prefix', { key: KEY, prefix: 'PII' }],
    ['the longest tag', { key: KEY, length: MAX_DERIVED_TOKEN_LENGTH }],
    ['a custom format', { key: KEY, format: (p: string, t: string) => `<${p}#${t}>` }],
    // A prefix that is a run of the probe character the derivation uses, which
    // is where a naive first-match search finds the wrong occurrence.
    ['a prefix made of the probe character', { key: KEY, prefix: 'a'.repeat(12) }],
  ])('matches what the policy renders for %s', (_label, options) => {
    const policy = deterministicRedaction('sensitive', options);

    expect(policy.markerPattern?.test(policy.redact(CANARY))).toBe(true);
    expect(policy.markerPattern?.test(policy.redact(OTHER))).toBe(true);
  });

  it('does not match an unrelated string', () => {
    const policy = deterministicRedaction('sensitive', { key: KEY });

    expect(policy.markerPattern?.test('nothing redacted here')).toBe(false);
    expect(policy.markerPattern?.test('[REDACTED:sensitive]')).toBe(false);
  });

  // A wrong pattern reads as coverage, so no pattern is the honest answer for a
  // format the derivation cannot decompose.
  it.each([
    ['transforms the tag', (_p: string, t: string) => t.toUpperCase()],
    ['embeds the tag twice', (_p: string, t: string) => `${t}-${t}`],
  ])('declares none for a format that %s', (_label, format) => {
    expect(deterministicRedaction('sensitive', { key: KEY, format }).markerPattern).toBeUndefined();
  });

  it('carries no g flag, which would make a shared pattern answer alternately', () => {
    expect(deterministicRedaction('sensitive', { key: KEY }).markerPattern?.global).toBe(false);
  });
});

describe('the registered policy', () => {
  // TEST-DR-I001, TEST-DR-I002
  it('registers, and survives the redact validation registerPolicy applies', () => {
    expect(() =>
      registerPolicy(deterministicRedaction('sensitive', { key: KEY }), { overwrite: true })
    ).not.toThrow();

    expect(redacted(CANARY)).toMatch(/^\[REDACTED:sensitive:[0-9a-f]{12}\]$/);
  });

  it('is replaceable again, so a key rotation is one more registration', () => {
    registerPolicy(deterministicRedaction('sensitive', { key: KEY }), { overwrite: true });
    const before = redacted(CANARY);

    registerPolicy(deterministicRedaction('sensitive', { key: OTHER_KEY }), { overwrite: true });

    expect(redacted(CANARY)).not.toBe(before);
  });

  it('goes back to the constant rendering when policies are reset', () => {
    registerPolicy(deterministicRedaction('sensitive', { key: KEY }), { overwrite: true });
    resetPolicies();

    expect(redacted(CANARY)).toBe('[REDACTED:sensitive]');
  });

  describe('reaches every rendering path', () => {
    // TEST-DR-I003, TEST-DR-I004, TEST-DR-I005
    it.each([
      ['toString()', (v: SensitiveString<'sensitive'>) => v.toString()],
      ['String()', (v: SensitiveString<'sensitive'>) => String(v)],
      [
        'a template',
        // eslint-disable-next-line @typescript-eslint/restrict-template-expressions -- the implicit coercion is the path under test
        (v: SensitiveString<'sensitive'>) => `${v}`,
      ],
      ['toJSON()', (v: SensitiveString<'sensitive'>) => v.toJSON()],
      ['JSON.stringify', (v: SensitiveString<'sensitive'>) => JSON.stringify(v)],
      ['inspect()', (v: SensitiveString<'sensitive'>) => inspect(v)],
      ['safeStringify', (v: SensitiveString<'sensitive'>) => safeStringify({ v })],
    ])('%s', (_label, render) => {
      registerPolicy(deterministicRedaction('sensitive', { key: KEY }), { overwrite: true });

      const one = new SensitiveString(CANARY, 'sensitive');
      const same = new SensitiveString(CANARY, 'sensitive', 'a-different-label');
      const other = new SensitiveString(OTHER, 'sensitive');

      const tag = tagOf(redacted(CANARY));

      expect(render(one)).toContain(tag);
      expect(render(same)).toContain(tag);
      expect(render(other)).not.toContain(tag);
      expect(render(one)).not.toContain(CANARY);
    });
  });

  /**
   * The property that makes the tag usable in an incident: a `serialize()`
   * payload that reaches a log line is redacted through the same class policy,
   * so it carries the same tag as the instance it came from rather than a
   * second identity for one subject.
   */
  it('gives a serialize() payload caught in a log the same tag as its instance', () => {
    registerPolicy(deterministicRedaction('sensitive', { key: KEY }), { overwrite: true });

    const value = new SensitiveString(CANARY, 'sensitive');
    const logged = safeStringify({ wire: value.serialize() });

    expect(logged).toContain(tagOf(redacted(CANARY)));
    expect(logged).not.toContain(CANARY);
  });

  it('tags a mask that could not meet its floor, which falls back to redaction', () => {
    registerPolicy(deterministicRedaction('sensitive', { key: KEY }), { overwrite: true });

    // Two characters cannot hide the four a `sensitive` mask must hide, so
    // `mask()` degrades to the class redaction rather than to a worse mask.
    expect(new SensitiveString('ab', 'sensitive').mask({ showFirst: 1 })).toBe(redacted('ab'));
  });

  /**
   * Redaction runs under the gate's `safe` access, ahead of the deadline and
   * the revocation check, because a log line has to keep redacting after a
   * value dies. That is unchanged here and worth pinning: the consequence is
   * that a dead value still emits its tag, which is the same disclosure the
   * live one made and no new one.
   */
  it('still tags a value whose deadline has passed', () => {
    registerPolicy(deterministicRedaction('sensitive', { key: KEY }), { overwrite: true });

    const expired = new SensitiveString(CANARY, 'sensitive', undefined, { ttl: 0 });

    expect(expired.toString()).toBe(redacted(CANARY));
    expect(() => expired.reveal()).toThrow();
  });

  it('still tags a value that has been revoked', () => {
    registerPolicy(deterministicRedaction('sensitive', { key: KEY }), { overwrite: true });

    const revoked = new SensitiveString(CANARY, 'sensitive');
    revoked.revoke('rotated');

    expect(revoked.toString()).toBe(redacted(CANARY));
    expect(() => revoked.reveal()).toThrow();
  });

  /**
   * Redaction is not a reveal, so it runs no audit hook and charges no budget.
   * A value with a spent budget must still be loggable, and a log line must not
   * appear in an audit trail as an access.
   */
  it('neither charges the reveal budget nor audits, because redaction is not a reveal', () => {
    registerPolicy(deterministicRedaction('sensitive', { key: KEY }), { overwrite: true });

    const value = new SensitiveString(CANARY, 'sensitive', undefined, { maxReveals: 1 });

    for (let i = 0; i < 10; i++) {
      expect(value.toString()).toBe(redacted(CANARY));
    }

    // Untouched by ten renderings, which is what proves nothing was charged.
    expect(value.reveal({ name: 't' })).toBe(CANARY);
    expect(() => value.reveal({ name: 't' })).toThrow();
  });
});
