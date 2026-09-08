/**
 * Functional coverage for sealing: a sealed value behaves like an unsealed one
 * everywhere a caller can see, and differs only where the design says it does.
 *
 * The security properties, the enumerating guards and the canary assertions are
 * in `__tests__/sealing-security.test.ts`; the process-memory measurements are
 * in `__tests__/sealing-retention.timing.test.ts`, because a GC schedule should
 * not gate a release.
 */
import { randomBytes } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import {
  createDeterministicRedactor,
  destroySealingKey,
  fromWorkerPayload,
  getSealing,
  registerPolicy,
  resetPolicies,
  resetSealing,
  SealedValueIntegrityError,
  SealingKeyDestroyedError,
  RevealLimitExceededError,
  SealingUnavailableError,
  SensitiveString,
  setSealing,
  st,
  toWorkerPayload,
} from './index.js';
import { sealingRingState, setSealingLimits } from './sealing.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';
const DERIVATION_KEY = 'derivation-key-at-least-32-bytes-long';

afterEach(() => {
  resetSealing();
  resetPolicies();
});

/** The same value, one sealed and one not, for a difference-of-behaviour test. */
function pair(value: string, klass: 'sensitive' | 'credential' = 'sensitive') {
  return {
    sealed: new SensitiveString(value, klass, 'canary', { sealed: true }),
    plain: new SensitiveString(value, klass, 'canary'),
  };
}

describe('sealing a value', () => {
  it('round-trips through reveal unchanged', () => {
    for (const value of [
      CANARY,
      'ascii',
      'ünïcödé with accents',
      '日本語のテキスト',
      '🔐🗝️ emoji and a ZWJ family 👨‍👩‍👧‍👦',
      'mixed 🔐 ascii 日本語 end',
    ]) {
      const sealed = new SensitiveString(value, 'credential', 'canary', { sealed: true });

      expect(sealed.isSealed).toBe(true);
      expect(sealed.reveal()).toBe(value);
      // Twice, because each read decrypts and neither may be the odd one out.
      expect(sealed.reveal()).toBe(value);
    }
  });

  it('seals an empty string and round-trips it', () => {
    const sealed = new SensitiveString('', 'sensitive', 'empty', { sealed: true });

    expect(sealed.isSealed).toBe(true);
    expect(sealed.reveal()).toBe('');
    expect(sealed.length).toBe(0);
    expect(sealed.isEmpty()).toBe(true);
  });

  it('reports the same length and emptiness as an unsealed value', () => {
    for (const value of [
      '',
      'a',
      CANARY,
      '日本語',
      '🔐',
      '🔐🔐 mixed 日本語 x',
      'x'.repeat(4096),
    ]) {
      const { sealed, plain } = pair(value);

      expect(sealed.length, JSON.stringify(value)).toBe(plain.length);
      expect(sealed.isEmpty()).toBe(plain.isEmpty());
      // The property the code-unit walk exists for: `length` is UTF-16 code
      // units, so a value outside the basic plane counts two per character.
      expect(sealed.length).toBe(value.length);
    }
  });

  it('renders, serializes to JSON and inspects exactly as an unsealed value', () => {
    const { sealed, plain } = pair(CANARY, 'credential');

    expect(sealed.toString()).toBe(plain.toString());
    expect(sealed.toJSON()).toBe(plain.toJSON());
    expect(JSON.stringify({ token: sealed })).toBe(JSON.stringify({ token: plain }));
    expect(String(sealed)).toBe(String(plain));
    expect(`${String(sealed)}`).toBe(`${String(plain)}`);
  });

  it('produces the same wire payload as an unsealed value', () => {
    const { sealed, plain } = pair(CANARY, 'credential');

    expect(sealed.serialize()).toEqual(plain.serialize());
  });

  it('behaves identically under mask, the string methods and the regex operations', () => {
    const value = 'CANARY_value_1234';
    const { sealed, plain } = pair(value);

    expect(sealed.mask({ showLast: 4 })).toBe(plain.mask({ showLast: 4 }));
    expect(sealed.substring(0, 6).reveal()).toBe(plain.substring(0, 6).reveal());
    expect(sealed.toUpperCase().reveal()).toBe(plain.toUpperCase().reveal());
    expect(sealed.slice(-4).reveal()).toBe(plain.slice(-4).reveal());
    expect(sealed.startsWith('CANARY')).toBe(true);
    expect(sealed.includes('value')).toBe(true);
    expect(sealed.indexOf('value')).toBe(plain.indexOf('value'));
    expect(sealed.test(/^CANARY/)).toBe(true);
    expect(sealed.split('_').map((part) => part.reveal())).toEqual(
      plain.split('_').map((part) => part.reveal())
    );
    expect(sealed.replace('CANARY', 'X').reveal()).toBe(plain.replace('CANARY', 'X').reveal());
    expect(sealed.hash('sha256').reveal()).toBe(plain.hash('sha256').reveal());
    expect(sealed.at(0)?.reveal()).toBe(plain.at(0)?.reveal());
  });
});

describe('revealBytes', () => {
  it('returns the UTF-8 bytes of a sealed value', () => {
    const sealed = new SensitiveString(CANARY, 'credential', 'canary', { sealed: true });
    const bytes = sealed.revealBytes();

    try {
      expect(bytes).toBeInstanceOf(Buffer);
      expect(bytes.toString('utf8')).toBe(CANARY);
    } finally {
      bytes.fill(0);
    }
  });

  it('returns a buffer the caller owns, so zeroing it does not damage the value', () => {
    const sealed = new SensitiveString(CANARY, 'credential', 'canary', { sealed: true });

    for (let round = 0; round < 3; round++) {
      const bytes = sealed.revealBytes();
      expect(bytes.toString('utf8')).toBe(CANARY);
      bytes.fill(0);
    }

    expect(sealed.reveal()).toBe(CANARY);
  });

  it('works on an unsealed value, which encodes rather than decrypts', () => {
    const plain = new SensitiveString(CANARY, 'sensitive', 'canary');
    const bytes = plain.revealBytes();

    expect(bytes.toString('utf8')).toBe(CANARY);
    bytes.fill(0);
    expect(plain.reveal()).toBe(CANARY);
  });

  it('counts as a reveal and is audited as one', () => {
    const seen: string[] = [];
    const sealed = new SensitiveString(CANARY, 'credential', 'canary', {
      sealed: true,
      maxReveals: 2,
    });

    sealed.revealBytes({ name: 'first', auditReveal: (_v, d) => seen.push(d.operation) }).fill(0);
    expect(sealed.revealCount).toBe(1);
    expect(sealed.revealsRemaining).toBe(1);

    sealed.reveal({ name: 'second', auditReveal: (_v, d) => seen.push(d.operation) });
    expect(seen).toEqual(['reveal', 'reveal']);
    expect(() => sealed.revealBytes()).toThrow(RevealLimitExceededError);
  });
});

describe('fromBuffer', () => {
  it('produces the same value as the string constructor and zeroes its input', () => {
    const bytes = Buffer.from(CANARY, 'utf8');
    const value = SensitiveString.fromBuffer(bytes, 'credential', 'db_password');

    expect(bytes.every((byte) => byte === 0)).toBe(true);
    expect(value.isSealed).toBe(true);
    expect(value.klass).toBe('credential');
    expect(value.label).toBe('db_password');
    expect(value.reveal()).toBe(CANARY);
    expect(value.length).toBe(CANARY.length);
    expect(value.toString()).toBe(
      new SensitiveString(CANARY, 'credential', 'db_password').toString()
    );
  });

  it('agrees with the string constructor about length, across the whole encoding', () => {
    for (const value of ['', 'a', 'ü', '€', '日本語', '🔐', '🔐a日€', 'x'.repeat(1000)]) {
      const built = SensitiveString.fromBuffer(Buffer.from(value, 'utf8'), 'sensitive');

      expect(built.length, JSON.stringify(value)).toBe(value.length);
      expect(built.reveal()).toBe(value);
    }
  });

  it('carries the ordinary options', () => {
    const value = SensitiveString.fromBuffer(Buffer.from(CANARY, 'utf8'), 'credential', 'boot', {
      maxReveals: 1,
    });

    expect(value.reveal()).toBe(CANARY);
    expect(() => value.reveal()).toThrow(RevealLimitExceededError);
  });

  it('rejects invalid UTF-8 with a TypeError', () => {
    const cases: readonly (readonly [string, number[]])[] = [
      ['a bare continuation byte', [0x80]],
      ['a truncated two-byte sequence', [0xc3]],
      ['a truncated three-byte sequence', [0xe6, 0x97]],
      ['a truncated four-byte sequence', [0xf0, 0x9f, 0x94]],
      ['an overlong two-byte NUL', [0xc0, 0x80]],
      ['an overlong three-byte sequence', [0xe0, 0x80, 0xaf]],
      ['an overlong four-byte sequence', [0xf0, 0x80, 0x80, 0xaf]],
      ['a UTF-8-encoded surrogate', [0xed, 0xa0, 0x80]],
      ['a code point above U+10FFFF', [0xf4, 0x90, 0x80, 0x80]],
      ['a 0xf5 lead byte', [0xf5, 0x80, 0x80, 0x80]],
      ['a 0xff byte', [0xff]],
      ['valid text followed by a bad byte', [0x61, 0x62, 0xc3, 0x28]],
    ];

    for (const [name, bytes] of cases) {
      expect(() => SensitiveString.fromBuffer(Buffer.from(bytes), 'sensitive'), name).toThrow(
        TypeError
      );
    }
  });

  it('accepts every well-formed sequence length', () => {
    for (const bytes of [[0x61], [0xc3, 0xbc], [0xe6, 0x97, 0xa5], [0xf0, 0x9f, 0x94, 0x90]]) {
      const buffer = Buffer.from(bytes);
      const expected = buffer.toString('utf8');

      expect(SensitiveString.fromBuffer(buffer, 'sensitive').reveal()).toBe(expected);
    }
  });

  it('renders through the class marker for a policy that ignores its argument', () => {
    const seen: string[] = [];

    // A constant redactor that records everything it is shown. The probes
    // `fromBuffer` uses to learn the rendering is constant land here too, which
    // is what the filter below is for; what must not land here is the value.
    registerPolicy(
      {
        name: 'sensitive',
        redact: (value: string) => {
          seen.push(value);
          return '[CONSTANT]';
        },
      },
      { overwrite: true }
    );
    seen.length = 0;

    const built = SensitiveString.fromBuffer(Buffer.from(CANARY, 'utf8'), 'sensitive', 'x');

    expect(built.toString()).toBe('[CONSTANT]');
    expect(seen).not.toContain(CANARY);
  });

  it('renders a value-reading policy against this value, not against the empty string', () => {
    // Deterministic redaction derives a correlation tag from the value. Handing
    // it the empty string would give every value built this way the same tag,
    // which is worse than no tag: two unrelated credentials would correlate.
    registerPolicy(
      {
        name: 'sensitive',
        redact: createDeterministicRedactor({ key: DERIVATION_KEY }),
      },
      { overwrite: true }
    );

    const first = SensitiveString.fromBuffer(Buffer.from('value-one', 'utf8'), 'sensitive', 'a');
    const second = SensitiveString.fromBuffer(Buffer.from('value-two', 'utf8'), 'sensitive', 'b');
    const again = SensitiveString.fromBuffer(Buffer.from('value-one', 'utf8'), 'sensitive', 'c');
    const viaConstructor = new SensitiveString('value-one', 'sensitive', 'd');

    expect(first.toString()).not.toBe(second.toString());
    expect(first.toString()).toBe(again.toString());
    // And it agrees with what the ordinary constructor would have produced.
    expect(first.toString()).toBe(viaConstructor.toString());
    expect(first.toString()).not.toContain('value-one');
  });

  it('refuses { sealed: false }, which contradicts its only purpose', () => {
    const bytes = Buffer.from(CANARY, 'utf8');

    expect(() => SensitiveString.fromBuffer(bytes, 'credential', 'x', { sealed: false })).toThrow(
      TypeError
    );
    // Refused before anything was consumed, so the caller still has its bytes.
    expect(bytes.toString('utf8')).toBe(CANARY);
  });

  it('refuses a non-Buffer', () => {
    for (const bad of [CANARY, null, undefined, 42, new Uint8Array([1, 2])]) {
      expect(() => SensitiveString.fromBuffer(bad as unknown as Buffer, 'sensitive')).toThrow(
        TypeError
      );
    }
  });

  it('leaves no instance behind when the bytes are rejected', () => {
    const bytes = Buffer.from([0xff, 0xfe]);

    expect(() => SensitiveString.fromBuffer(bytes, 'sensitive')).toThrow(TypeError);
    // The buffer is untouched too: validation runs before anything consumes it.
    expect([...bytes]).toEqual([0xff, 0xfe]);
  });
});

describe('the process setting', () => {
  it('defaults to off, and reports its defaults resolved', () => {
    expect(getSealing()).toEqual({ sealByDefault: false, strict: true });
    expect(new SensitiveString(CANARY, 'credential').isSealed).toBe(false);
  });

  it('seals values constructed with no options once it is on', () => {
    setSealing({ sealByDefault: true });

    expect(new SensitiveString(CANARY, 'credential').isSealed).toBe(true);
    expect(new SensitiveString(CANARY, 'credential', 'x', {}).isSealed).toBe(true);
    expect(new SensitiveString(CANARY, 'credential', 'x', { ttl: 1000 }).isSealed).toBe(true);
  });

  it('lets one value opt out by name', () => {
    setSealing({ sealByDefault: true });

    const opted = new SensitiveString(CANARY, 'credential', 'x', { sealed: false });

    expect(opted.isSealed).toBe(false);
    expect(opted.reveal()).toBe(CANARY);
  });

  it('merges, so setting one switch does not reset the other', () => {
    setSealing({ sealByDefault: true });
    setSealing({ strict: false });

    expect(getSealing()).toEqual({ sealByDefault: true, strict: false });
  });

  it('hands back a frozen copy rather than the live object', () => {
    const config = getSealing();

    expect(Object.isFrozen(config)).toBe(true);
    expect(() => {
      (config as { sealByDefault: boolean }).sealByDefault = true;
    }).toThrow(TypeError);
    expect(getSealing().sealByDefault).toBe(false);
  });

  it('refuses a configuration of the wrong shape', () => {
    expect(() => setSealing(null as unknown as { strict: boolean })).toThrow(TypeError);
    expect(() => setSealing({ sealByDefault: 'yes' as unknown as boolean })).toThrow(TypeError);
    expect(() => setSealing({ strict: 1 as unknown as boolean })).toThrow(TypeError);
  });
});

describe('derived values', () => {
  it('seals every derivative of a sealed value', () => {
    const sealed = new SensitiveString('CANARY_value_1234', 'sensitive', 'canary', {
      sealed: true,
    });

    expect(sealed.substring(0, 4).isSealed).toBe(true);
    expect(sealed.toUpperCase().isSealed).toBe(true);
    expect(sealed.map((raw) => raw).isSealed).toBe(true);
    expect(sealed.reclassify('credential').isSealed).toBe(true);
    expect(sealed.hash('sha256').isSealed).toBe(true);
    expect(sealed.split('_').every((part) => part.isSealed)).toBe(true);
  });

  it('seals a concat result when either operand is sealed, in both orders', () => {
    const sealed = new SensitiveString('left', 'sensitive', 'l', { sealed: true });
    const plain = new SensitiveString('right', 'sensitive', 'r');

    expect(sealed.concat(plain).isSealed).toBe(true);
    expect(plain.concat(sealed).isSealed).toBe(true);
    expect(sealed.concat('literal').isSealed).toBe(true);
    expect(plain.concat('literal').isSealed).toBe(false);
    expect(sealed.concat(plain).reveal()).toBe('leftright');
    expect(plain.concat(sealed).reveal()).toBe('rightleft');
  });

  it('seals a template result when any interpolation is sealed', () => {
    const sealed = new SensitiveString('secret', 'credential', 'c', { sealed: true });
    const plain = new SensitiveString('open', 'sensitive', 's');

    expect(st`prefix ${sealed}`.isSealed).toBe(true);
    expect(st`${plain} and ${sealed}`.isSealed).toBe(true);
    expect(st`${plain} alone`.isSealed).toBe(false);
    expect(st`prefix ${sealed}`.reveal()).toBe('prefix secret');
  });

  it('gives each sibling of a one-to-many derivation its own box', () => {
    const sealed = new SensitiveString('a_b_c', 'sensitive', 'canary', { sealed: true });
    const parts = sealed.split('_');

    expect(parts.map((part) => part.reveal())).toEqual(['a', 'b', 'c']);

    // Independent storage: clearing one leaves the others readable, which a
    // shared box could not do.
    parts[0]!.clear();
    expect(parts[1]!.reveal()).toBe('b');
    expect(parts[2]!.reveal()).toBe('c');
  });

  it('refuses to derive rather than hand back a plaintext copy, even when strict is off', () => {
    // `strict` is a preference about a caller's own request. It has no say over
    // this rule: a derivative that fell back to a string would be a well-formed
    // instance holding a sealed value's contents in the clear, which is the R2
    // bypass the propagation exists to close.
    setSealing({ strict: false });
    setSealingLimits({ budget: 1, generations: 1 });

    const parent = new SensitiveString('CANARY_value', 'sensitive', 'p', { sealed: true });
    expect(parent.isSealed).toBe(true);

    // The ring is spent, so the derivative cannot be sealed and must not be
    // built unsealed either.
    expect(() => parent.substring(0, 4)).toThrow(SealingUnavailableError);
    expect(() => parent.map((raw) => raw)).toThrow(SealingUnavailableError);
    expect(() => parent.concat('x')).toThrow(SealingUnavailableError);
    expect(() => st`prefix ${parent}`).toThrow(SealingUnavailableError);
  });

  it('does not seal a derivative of an unsealed value in a sealByDefault process', () => {
    setSealing({ sealByDefault: true });

    const opted = new SensitiveString('CANARY_value', 'sensitive', 'x', { sealed: false });

    // Tighten-only: a derivative takes its storage from its sources, not from
    // the process default, so an explicit opt-out is not undone by deriving.
    expect(opted.substring(0, 4).isSealed).toBe(false);
  });
});

describe('equals', () => {
  it('is correct across every sealed and unsealed combination', () => {
    const combinations: readonly (readonly [boolean, boolean])[] = [
      [true, true],
      [true, false],
      [false, true],
      [false, false],
    ];

    for (const [leftSealed, rightSealed] of combinations) {
      const name = `${String(leftSealed)}/${String(rightSealed)}`;
      const left = new SensitiveString(CANARY, 'credential', 'l', { sealed: leftSealed });
      const same = new SensitiveString(CANARY, 'credential', 'r', { sealed: rightSealed });
      const other = new SensitiveString('different', 'credential', 'r', { sealed: rightSealed });

      expect(left.equals(same), name).toBe(true);
      expect(left.equals(other), name).toBe(false);
    }
  });

  it('compares a sealed value against a plain string', () => {
    const sealed = new SensitiveString(CANARY, 'credential', 'canary', { sealed: true });

    expect(sealed.equals(CANARY)).toBe(true);
    expect(sealed.equals('wrong')).toBe(false);
    expect(sealed.equals('')).toBe(false);
    expect(sealed.equals(`${CANARY} `)).toBe(false);
  });

  it('never reports a sealed credential equal to the empty string', () => {
    // The exact failure the design's subclass probe found, asserted directly
    // because it is the one that admits anybody to a password check.
    for (const klass of ['credential', 'sensitive'] as const) {
      const sealed = new SensitiveString(CANARY, klass, 'canary', { sealed: true });

      expect(sealed.equals('')).toBe(false);
      expect(sealed.equals(new SensitiveString('', klass, 'x', { sealed: true }))).toBe(false);
    }

    const empty = new SensitiveString('', 'credential', 'x', { sealed: true });
    expect(empty.equals('')).toBe(true);
  });

  it('is symmetric across the sealed and unsealed sides', () => {
    const sealed = new SensitiveString(CANARY, 'sensitive', 'l', { sealed: true });
    const plain = new SensitiveString(CANARY, 'sensitive', 'r');

    expect(sealed.equals(plain)).toBe(plain.equals(sealed));
    expect(sealed.equals(plain)).toBe(true);
  });

  it('handles values outside the basic plane', () => {
    const value = '🔐 日本語 secret';
    const sealed = new SensitiveString(value, 'credential', 'x', { sealed: true });

    expect(sealed.equals(value)).toBe(true);
    expect(sealed.equals('🔐 日本語 secre')).toBe(false);
  });

  it('raises on a comparand of the wrong type, as the constant-time path does', () => {
    // Not reachable through the declared signature, and reachable from
    // JavaScript. Pinned across all three shapes because they do not agree, and
    // the disagreement is the comparison's rather than the storage's: the
    // constant-time path hands the comparand to `createHmac`, which refuses it,
    // and a sealed value is always on that path. An unsealed `credential`
    // already behaved this way; an unsealed `sensitive` answers false from
    // `===`, and sealing one changes that.
    const sealedSensitive = new SensitiveString(CANARY, 'sensitive', 'canary', { sealed: true });
    const plainSensitive = new SensitiveString(CANARY, 'sensitive', 'canary');
    const plainCredential = new SensitiveString(CANARY, 'credential', 'canary');

    const wrong: readonly [string, unknown][] = [
      ['a number', 42],
      ['null', null],
      ['undefined', undefined],
      ['an object', {}],
      ['an array', []],
      ['a boolean', true],
      ['a Buffer', Buffer.from(CANARY, 'utf8')],
    ];

    for (const [name, bad] of wrong) {
      expect(plainSensitive.equals(bad as string), name).toBe(false);
      expect(() => sealedSensitive.equals(bad as string), name).toThrow(TypeError);
    }

    // The unsealed constant-time path agrees for the scalars, which is where
    // the sealed path took its convention from. It disagrees for an array and a
    // Buffer, which the next case is about.
    for (const [name, bad] of wrong.slice(0, 4)) {
      expect(() => plainCredential.equals(bad as string), name).toThrow(TypeError);
    }
  });

  it('refuses a Buffer comparand rather than comparing against its bytes', () => {
    // The case that made the explicit check necessary. `Buffer.from` accepts a
    // Buffer and an array, so leaving the encoding to it would let a comparand
    // nobody meant to pass compare successfully against a sealed value while
    // the same comparand raised against an unsealed credential.
    const sealed = new SensitiveString(CANARY, 'credential', 'canary', { sealed: true });

    let thrown: unknown;
    try {
      sealed.equals(Buffer.from(CANARY, 'utf8') as unknown as string);
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(TypeError);
    expect((thrown as Error).message).toMatch(/string or a SensitiveString/);
    expect((thrown as Error).message).not.toContain(CANARY);
  });

  it('does not count as a reveal', () => {
    const sealed = new SensitiveString(CANARY, 'credential', 'canary', { sealed: true });

    sealed.equals(CANARY);
    sealed.equals('nope');

    expect(sealed.revealCount).toBe(0);
  });
});

describe('clear', () => {
  it('keeps rendering and refuses every read', () => {
    const sealed = new SensitiveString(CANARY, 'credential', 'canary', { sealed: true });
    const rendering = sealed.toString();

    sealed.clear();

    expect(sealed.isCleared).toBe(true);
    expect(sealed.toString()).toBe(rendering);
    expect(sealed.toString()).not.toContain(CANARY);
    expect(() => sealed.reveal()).toThrow(/cleared/i);
    expect(() => sealed.revealBytes()).toThrow(/cleared/i);
    expect(() => sealed.equals(CANARY)).toThrow(/cleared/i);
    expect(() => sealed.length).toThrow(/cleared/i);
    expect(() => sealed.isEmpty()).toThrow(/cleared/i);
  });

  it('reports the value as no longer sealed, because it no longer holds one', () => {
    const sealed = new SensitiveString(CANARY, 'credential', 'canary', { sealed: true });

    expect(sealed.isSealed).toBe(true);
    sealed.clear();
    expect(sealed.isSealed).toBe(false);
  });

  it('is idempotent', () => {
    const sealed = new SensitiveString(CANARY, 'credential', 'canary', { sealed: true });

    sealed.clear();
    const at = sealed.clearedAt;
    expect(() => sealed.clear()).not.toThrow();
    expect(sealed.clearedAt).toEqual(at);
  });
});

describe('the key lifecycle', () => {
  it('makes every existing sealed value unreadable when the key is destroyed', () => {
    const first = new SensitiveString(CANARY, 'credential', 'first', { sealed: true });
    const second = new SensitiveString('another', 'sensitive', 'second', { sealed: true });
    const plain = new SensitiveString(CANARY, 'credential', 'plain');

    destroySealingKey();

    expect(() => first.reveal()).toThrow(SealingKeyDestroyedError);
    expect(() => second.reveal()).toThrow(SealingKeyDestroyedError);
    expect(() => first.revealBytes()).toThrow(SealingKeyDestroyedError);
    expect(() => first.equals(CANARY)).toThrow(SealingKeyDestroyedError);

    // Unsealed values are untouched: the two erasures are complementary rather
    // than overlapping.
    expect(plain.reveal()).toBe(CANARY);
  });

  it('leaves redaction, length and the lifecycle metadata answering', () => {
    const sealed = new SensitiveString(CANARY, 'credential', 'canary', { sealed: true });
    const rendering = sealed.toString();

    destroySealingKey();

    expect(sealed.toString()).toBe(rendering);
    expect(sealed.length).toBe(CANARY.length);
    expect(sealed.isSealed).toBe(true);
    expect(sealed.isCleared).toBe(false);
  });

  it('names the destruction rather than reporting an integrity failure', () => {
    const sealed = new SensitiveString(CANARY, 'credential', 'canary', { sealed: true });

    destroySealingKey();

    try {
      sealed.reveal();
      expect.unreachable('a destroyed key must refuse');
    } catch (thrown) {
      expect(thrown).toBeInstanceOf(SealingKeyDestroyedError);
      expect(thrown).not.toBeInstanceOf(SealedValueIntegrityError);
      expect((thrown as SealingKeyDestroyedError).destroyedAt).toBeInstanceOf(Date);
      expect((thrown as SealingKeyDestroyedError).destroyedFor).toBeGreaterThanOrEqual(0);
      expect((thrown as SealingKeyDestroyedError).label).toBe('canary');
    }
  });

  it('lets values sealed after a destroy work normally', () => {
    const before = new SensitiveString(CANARY, 'credential', 'before', { sealed: true });

    destroySealingKey();

    const after = new SensitiveString(CANARY, 'credential', 'after', { sealed: true });

    expect(after.isSealed).toBe(true);
    expect(after.reveal()).toBe(CANARY);
    expect(() => before.reveal()).toThrow(SealingKeyDestroyedError);
  });

  it('is idempotent', () => {
    const sealed = new SensitiveString(CANARY, 'credential', 'canary', { sealed: true });

    destroySealingKey();
    const first = (() => {
      try {
        sealed.reveal();
        return undefined;
      } catch (thrown) {
        return (thrown as SealingKeyDestroyedError).destroyedAt;
      }
    })();

    expect(() => destroySealingKey()).not.toThrow();

    try {
      sealed.reveal();
      expect.unreachable('a destroyed key must refuse');
    } catch (thrown) {
      // A second destroy does not restamp a generation it already tombstoned.
      expect((thrown as SealingKeyDestroyedError).destroyedAt).toEqual(first);
    }
  });
});

describe('generations', () => {
  it('starts a new generation at the seal budget, and old values still open', () => {
    setSealingLimits({ budget: 3 });

    const first = new SensitiveString('one', 'sensitive', 'a', { sealed: true });
    const second = new SensitiveString('two', 'sensitive', 'b', { sealed: true });
    const third = new SensitiveString('three', 'sensitive', 'c', { sealed: true });

    expect(sealingRingState()).toEqual({ generations: 1, seals: 3, destroyed: 0 });

    const fourth = new SensitiveString('four', 'sensitive', 'd', { sealed: true });

    expect(sealingRingState()).toEqual({ generations: 2, seals: 1, destroyed: 0 });

    // Nothing was re-encrypted and no instance was walked, so every value from
    // the spent generation still opens under the key it was sealed with.
    expect(first.reveal()).toBe('one');
    expect(second.reveal()).toBe('two');
    expect(third.reveal()).toBe('three');
    expect(fourth.reveal()).toBe('four');
  });

  it('destroys every generation, not only the current one', () => {
    setSealingLimits({ budget: 1 });

    const first = new SensitiveString('one', 'sensitive', 'a', { sealed: true });
    const second = new SensitiveString('two', 'sensitive', 'b', { sealed: true });

    expect(sealingRingState().generations).toBe(2);

    destroySealingKey();

    expect(sealingRingState().destroyed).toBe(2);
    expect(() => first.reveal()).toThrow(SealingKeyDestroyedError);
    expect(() => second.reveal()).toThrow(SealingKeyDestroyedError);
  });

  it('raises SealingUnavailableError when the ring is exhausted', () => {
    setSealingLimits({ budget: 1, generations: 2 });

    expect(new SensitiveString('one', 'sensitive', 'a', { sealed: true }).isSealed).toBe(true);
    expect(new SensitiveString('two', 'sensitive', 'b', { sealed: true }).isSealed).toBe(true);

    expect(() => new SensitiveString('three', 'sensitive', 'c', { sealed: true })).toThrow(
      SealingUnavailableError
    );
  });

  it('never falls back to a plaintext string while strict is on', () => {
    setSealingLimits({ budget: 1, generations: 1 });
    new SensitiveString('one', 'sensitive', 'a', { sealed: true });

    let thrown: unknown;
    try {
      new SensitiveString(CANARY, 'credential', 'b', { sealed: true });
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(SealingUnavailableError);
    expect((thrown as SealingUnavailableError).reason).toBe('generations-exhausted');
    expect(String((thrown as Error).message)).not.toContain(CANARY);
  });

  it('falls back to a string when strict is off, and says so through isSealed', () => {
    setSealing({ strict: false });
    setSealingLimits({ budget: 1, generations: 1 });
    new SensitiveString('one', 'sensitive', 'a', { sealed: true });

    const fallback = new SensitiveString(CANARY, 'credential', 'b', { sealed: true });

    expect(fallback.isSealed).toBe(false);
    expect(fallback.reveal()).toBe(CANARY);
  });

  it('leaves a fallback value indistinguishable from one that never asked to seal', () => {
    setSealing({ strict: false });
    setSealingLimits({ budget: 1, generations: 1 });
    new SensitiveString('one', 'sensitive', 'a', { sealed: true });

    const fallback = new SensitiveString(CANARY, 'sensitive', 'b', { sealed: true });
    const never = new SensitiveString(CANARY, 'sensitive', 'b');

    expect(fallback.isSealed).toBe(false);

    // The refused seal must leave nothing behind, and the rendering is the part
    // that could: a value that captured one before the seal failed would answer
    // from the snapshot for the rest of its life, where an ordinary unsealed
    // value re-renders through whatever policy is registered when it is logged.
    registerPolicy({ name: 'sensitive', redact: () => '[LATE]' }, { overwrite: true });

    expect(fallback.toString()).toBe('[LATE]');
    expect(fallback.toString()).toBe(never.toString());
  });

  it('falls back for a sealByDefault value even while strict is on', () => {
    // `strict` is about a caller who asked by name. A process default that
    // cannot be honoured must not stop the process from wrapping values.
    setSealing({ sealByDefault: true });
    setSealingLimits({ budget: 1, generations: 1 });
    new SensitiveString('one', 'sensitive', 'a', { sealed: true });

    const fallback = new SensitiveString(CANARY, 'credential', 'b');

    expect(fallback.isSealed).toBe(false);
    expect(fallback.reveal()).toBe(CANARY);
  });

  it('refuses a limit that is not a positive integer', () => {
    expect(() => setSealingLimits({ budget: 0 })).toThrow(RangeError);
    expect(() => setSealingLimits({ budget: 1.5 })).toThrow(RangeError);
    expect(() => setSealingLimits({ generations: -1 })).toThrow(RangeError);
  });
});

describe('the wire format', () => {
  it('carries no sealing field, so a payload cannot tell a receiver how to store', () => {
    const sealed = new SensitiveString(CANARY, 'credential', 'canary', { sealed: true });
    const wire = sealed.serialize();

    expect(Object.keys(wire).sort()).toEqual(['__sensitive', 'klass', 'label', 'value']);
    expect(JSON.stringify(wire)).not.toContain('sealed');
  });

  it('lets the receiving process decide, from its own configuration', () => {
    const wire = new SensitiveString(CANARY, 'credential', 'canary', { sealed: true }).serialize();

    expect(SensitiveString.deserialize(wire).isSealed).toBe(false);

    setSealing({ sealByDefault: true });
    const received = SensitiveString.deserialize<'credential'>(wire);

    expect(received.isSealed).toBe(true);
    expect(received.reveal()).toBe(CANARY);
  });
});

describe('the worker handoff', () => {
  it('carries the plaintext and lets the receiving side decide how to store it', () => {
    const sealedToken = new SensitiveString(CANARY, 'credential', 'api_key', { sealed: true });
    const payload = toWorkerPayload({ token: sealedToken });

    // A box cannot travel: the key is per isolate, because `getGlobalSingleton`
    // keys on `globalThis` and a worker is a separate one. The handoff is an
    // `expose` through the gate, so it decrypts on this side and the far side
    // seals its own copy under its own key if its own configuration says to.
    expect(payload.values.token).toEqual({
      __sensitive: true,
      klass: 'credential',
      value: CANARY,
      label: 'api_key',
    });
    expect(JSON.stringify(payload)).not.toContain('sealed');

    const received = fromWorkerPayload<{ token: SensitiveString<'credential'> }>(
      structuredClone(payload)
    );

    expect(received.values.token.isSealed).toBe(false);
    expect(received.values.token.reveal()).toBe(CANARY);
  });

  it('seals on the receiving side when that side configured it', () => {
    const payload = structuredClone(
      toWorkerPayload({
        token: new SensitiveString(CANARY, 'credential', 'api_key', { sealed: true }),
      })
    );

    setSealing({ sealByDefault: true });
    const received = fromWorkerPayload<{ token: SensitiveString<'credential'> }>(payload);

    expect(received.values.token.isSealed).toBe(true);
    expect(received.values.token.reveal()).toBe(CANARY);
  });

  it('counts the handoff as the exposure it is', () => {
    const sealedToken = new SensitiveString(CANARY, 'credential', 'api_key', { sealed: true });

    toWorkerPayload({ token: sealedToken });

    expect(sealedToken.revealCount).toBe(1);
  });
});

describe('interaction with the rest of the gate', () => {
  it('checks expiry before decrypting', () => {
    const sealed = new SensitiveString(CANARY, 'credential', 'canary', {
      sealed: true,
      ttl: 0,
    });

    expect(() => sealed.reveal()).toThrow(/expired/i);
    expect(() => sealed.revealBytes()).toThrow(/expired/i);
    // Redaction and length still answer, from what was captured.
    expect(sealed.toString()).not.toContain(CANARY);
    expect(sealed.length).toBe(CANARY.length);
  });

  it('checks revocation before decrypting', () => {
    const sealed = new SensitiveString(CANARY, 'credential', 'canary', { sealed: true });
    sealed.revoke('rotated');

    expect(() => sealed.reveal()).toThrow(/revoked/i);
    expect(() => sealed.revealBytes()).toThrow(/revoked/i);
  });

  it('charges a reveal budget once per byte-returning read', () => {
    const sealed = new SensitiveString(CANARY, 'credential', 'canary', {
      sealed: true,
      maxReveals: 3,
    });

    sealed.revealBytes().fill(0);
    sealed.revealBytes().fill(0);
    expect(sealed.revealsRemaining).toBe(1);
  });

  it('renders through a policy that reads the value, without decrypting per log line', () => {
    const seen: string[] = [];

    registerPolicy(
      {
        name: 'sensitive',
        redact: (value) => {
          seen.push(value);
          return `[R:${String(value.length)}]`;
        },
      },
      { overwrite: true }
    );

    // `registerPolicy` proves the redactor redacts by running it over its own
    // canaries, so the interesting count starts here.
    seen.length = 0;

    const sealed = new SensitiveString(CANARY, 'sensitive', 'canary', { sealed: true });

    // Once, at construction, from the live value.
    expect(seen).toEqual([CANARY]);

    expect(sealed.toString()).toBe(`[R:${String(CANARY.length)}]`);
    expect(sealed.toJSON()).toBe(`[R:${String(CANARY.length)}]`);
    JSON.stringify({ sealed });

    // And never again, so a deterministic redactor does not force a decrypt on
    // every logged object.
    expect(seen).toEqual([CANARY]);
  });

  it('keeps the rendering a policy registered later would have changed', () => {
    const sealed = new SensitiveString(CANARY, 'sensitive', 'canary', { sealed: true });
    const plain = new SensitiveString(CANARY, 'sensitive', 'canary');

    registerPolicy({ name: 'sensitive', redact: () => '[LATE]' }, { overwrite: true });

    // The documented difference: a sealed value's rendering is captured at
    // construction, so a policy registered afterwards does not reach it.
    expect(sealed.toString()).toBe('[REDACTED:sensitive]');
    expect(plain.toString()).toBe('[LATE]');
  });

  it('falls back to the class marker when the policy redact throws', () => {
    registerPolicy(
      {
        name: 'sensitive',
        redact: () => {
          throw new Error('broken redactor');
        },
      },
      // `registerPolicy` would refuse this policy by running it, which is the
      // right default and the reason the escape hatch exists.
      { overwrite: true, skipRedactValidation: true }
    );

    const sealed = new SensitiveString(CANARY, 'sensitive', 'canary', { sealed: true });

    expect(sealed.isSealed).toBe(true);
    expect(sealed.toString()).toBe('[REDACTED:sensitive]');
    expect(sealed.reveal()).toBe(CANARY);
  });
});

describe('the process-global ring', () => {
  it('is reachable under the Symbol.for key a second copy of core would use', () => {
    setSealing({ sealByDefault: true });
    const token = new SensitiveString(CANARY, 'credential', 'token');

    const key = Symbol.for('@platform-sec/sensitive-string-core/memory-sealing');
    const shared = (
      globalThis as unknown as Record<
        symbol,
        { config: { sealByDefault: boolean }; generations: { destroyed: Date | undefined }[] }
      >
    )[key];

    // A second physical installation calls getGlobalSingleton with this same
    // key and receives this same object, so one `destroySealingKey()` reaches
    // the values both copies sealed, and neither copy has to be configured.
    expect(shared?.config.sealByDefault).toBe(true);
    expect(shared?.generations.length).toBe(1);
    expect(token.isSealed).toBe(true);

    // And the destroy the other copy would call is the same operation.
    destroySealingKey();
    expect(shared?.generations[0]?.destroyed).toBeInstanceOf(Date);
    expect(() => token.reveal()).toThrow(SealingKeyDestroyedError);
  });

  it('holds no generation until something is actually sealed', () => {
    setSealing({ sealByDefault: true });
    new SensitiveString(CANARY, 'credential', 'unsealed', { sealed: false });

    // The key is generated lazily on the first seal, so a process that
    // configures sealing and then seals nothing never draws one.
    expect(sealingRingState().generations).toBe(0);
  });
});

describe('resetSealing', () => {
  it('restores the defaults', () => {
    setSealing({ sealByDefault: true, strict: false });
    resetSealing();

    expect(getSealing()).toEqual({ sealByDefault: false, strict: true });
  });

  it('empties the ring, so a value from before it reports tampering rather than destruction', () => {
    const sealed = new SensitiveString(CANARY, 'credential', 'canary', { sealed: true });

    resetSealing();

    // Documented on `resetSealing`: emptying the ring is the one thing in the
    // module that reuses a generation index, so the old box meets a different
    // key rather than a tombstone. Both refuse; only the other one names why.
    new SensitiveString('fresh', 'sensitive', 'x', { sealed: true });
    expect(() => sealed.reveal()).toThrow(SealedValueIntegrityError);
  });
});

describe('a sealed value under load', () => {
  it('seals and opens many values without collision', () => {
    const values = Array.from({ length: 200 }, () => randomBytes(24).toString('hex'));
    const sealedValues = values.map(
      (value, index) =>
        new SensitiveString(value, 'credential', `v${String(index)}`, { sealed: true })
    );

    for (const [index, sealed] of sealedValues.entries()) {
      expect(sealed.reveal()).toBe(values[index]);
      expect(sealed.equals(values[index]!)).toBe(true);
    }
  });

  it('opens the same value a hundred times with the same answer', () => {
    const sealed = new SensitiveString(CANARY, 'credential', 'canary', { sealed: true });

    for (let round = 0; round < 100; round++) {
      expect(sealed.reveal()).toBe(CANARY);
    }
  });
});
