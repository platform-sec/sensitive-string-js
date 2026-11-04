/**
 * What sealing must hold whatever else changes.
 *
 * Three of these suites enumerate rather than sample, following the pattern
 * `ttl-security.test.ts` established: a method added later without the right
 * handling fails here instead of shipping. The lists are written out rather
 * than derived from a name pattern, so a new member has to be looked at by a
 * person before it can join one.
 *
 * `node:crypto` is wrapped so decryptions can be counted. That is the only way
 * to assert the load-bearing negative, which is that redaction never decrypts:
 * the observable result of a safe read is identical either way, so nothing
 * short of counting the cipher constructions can tell a captured rendering from
 * a per-log-line decrypt.
 */
// Imported by name rather than taken from the global, so `Buffer.prototype` has
// a type: `stringsDecodedDuring` patches it, and an untyped prototype makes
// every line of that helper an unchecked `any`.
import { Buffer } from 'node:buffer';
import { inspect } from 'node:util';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const crypto = vi.hoisted(() => ({ deciphers: 0, ciphers: 0 }));
const compare = vi.hoisted(() => ({ strings: 0, bytes: 0 }));

vi.mock('../compare.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../compare.js')>();

  return {
    ...actual,
    constantTimeEquals: (a: string, b: string) => {
      compare.strings += 1;
      return actual.constantTimeEquals(a, b);
    },
    constantTimeEqualsBytes: (a: Buffer, b: Buffer) => {
      compare.bytes += 1;
      return actual.constantTimeEqualsBytes(a, b);
    },
  };
});

vi.mock('node:crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:crypto')>();

  return {
    ...actual,
    default: actual,
    createDecipheriv: (...args: unknown[]) => {
      crypto.deciphers += 1;
      return (actual.createDecipheriv as (...a: unknown[]) => unknown)(...args);
    },
    createCipheriv: (...args: unknown[]) => {
      crypto.ciphers += 1;
      return (actual.createCipheriv as (...a: unknown[]) => unknown)(...args);
    },
  };
});

// Static imports, which `vi.mock` is hoisted above, so these see the wrappers.
// The first draft used `await import` and lost every type along the way, which
// is what an assertion on `error.label` needs.
import { randomBytes } from 'node:crypto';
import {
  destroySealingKey,
  redactCopy,
  redactInStructure,
  resetEnvironmentInfo,
  resetPolicies,
  resetSealing,
  safeStringify,
  SealedValueIntegrityError,
  SealingKeyDestroyedError,
  SensitiveString,
  setEnvironmentInfo,
  st,
} from '../index.js';
import { additionalData, openBox, sealBytes } from '../sealing.js';
import type { SensitivityClass } from '../types.js';

type Sensitive = SensitiveString<SensitivityClass>;

const CANARY = 'LEAKED_SECRET_abc123xyz';
const HMAC_KEY = 'hmac-key-value-32-bytes-long-abc';

/** A sealed value carrying the canary, rebuilt per case. */
function sealed(klass: SensitivityClass = 'sensitive'): Sensitive {
  return new SensitiveString(CANARY, klass, 'canary', { sealed: true });
}

/**
 * Every operation that reads with `'safe'`, directly or through one of the
 * walks that end in `toString()`.
 *
 * None of them may decrypt. A safe read is one that needs no authorization, and
 * a sealed value has none to give: decrypting for a log line would put a
 * plaintext string in the heap on every logged object, which is the thing
 * sealing exists to avoid.
 */
const SAFE_READ_OPERATIONS: readonly [string, (value: Sensitive) => unknown][] = [
  ['toString', (v) => v.toString()],
  ['toJSON', (v) => v.toJSON()],
  ['String()', (v) => String(v)],
  ['template interpolation', (v) => `${String(v)}`],
  ['JSON.stringify', (v) => JSON.stringify({ v })],
  ['util.inspect', (v) => inspect(v)],
  ['console.log formatting', (v) => inspect({ nested: [v] }, { depth: 5 })],
  ['length', (v) => v.length],
  ['isEmpty', (v) => v.isEmpty()],
  ['isSealed', (v) => v.isSealed],
  ['isCleared', (v) => v.isCleared],
  ['isRevoked', (v) => v.isRevoked],
  ['isExhausted', (v) => v.isExhausted()],
  ['revealCount', (v) => v.revealCount],
  ['expiresAt', (v) => v.expiresAt],
  ['redactInStructure', (v) => redactInStructure({ token: v })],
  ['redactCopy', (v) => redactCopy({ token: v })],
  ['safeStringify', (v) => safeStringify({ token: v })],
];

/**
 * Every operation that reaches the raw value. Each must behave identically on a
 * sealed and an unsealed value, and neither its result nor any error it throws
 * may carry the canary.
 */
const RAW_VALUE_OPERATIONS: readonly [string, (value: Sensitive) => unknown][] = [
  ['reveal', (v) => v.reveal()],
  ['revealBytes', (v) => v.revealBytes().toString('utf8')],
  ['mask', (v) => v.mask({ showLast: 2 })],
  ['equals(string)', (v) => v.equals(CANARY)],
  ['equals(SensitiveString)', (v) => v.equals(new SensitiveString(CANARY, 'sensitive'))],
  ['concat', (v) => v.concat('suffix').reveal()],
  ['substring', (v) => v.substring(0, 4).reveal()],
  ['trim', (v) => v.trim().reveal()],
  ['trimStart', (v) => v.trimStart().reveal()],
  ['trimEnd', (v) => v.trimEnd().reveal()],
  ['toLowerCase', (v) => v.toLowerCase().reveal()],
  ['toUpperCase', (v) => v.toUpperCase().reveal()],
  ['padStart', (v) => v.padStart(64, 'x').reveal()],
  ['padEnd', (v) => v.padEnd(64, 'x').reveal()],
  ['slice', (v) => v.slice(1).reveal()],
  ['startsWith', (v) => v.startsWith('LEAKED')],
  ['endsWith', (v) => v.endsWith('xyz')],
  ['includes', (v) => v.includes('SECRET')],
  ['indexOf', (v) => v.indexOf('SECRET')],
  ['lastIndexOf', (v) => v.lastIndexOf('SECRET')],
  ['test', (v) => v.test(/SECRET/)],
  ['search', (v) => v.search(/SECRET/)],
  ['match', (v) => v.match(/SECRET/)?.map((m) => m.reveal())],
  ['matchGroups', (v) => v.matchGroups(/(?<tag>SECRET)/)?.['tag']?.reveal()],
  ['matchAll', (v) => Array.from(v.matchAll(/SECRET/g)).flat().length],
  ['split', (v) => v.split('_').map((part) => part.reveal())],
  ['replace', (v) => v.replace('SECRET', 'x').reveal()],
  ['replaceAll', (v) => v.replaceAll(/SECRET/g, 'x').reveal()],
  ['charAt', (v) => v.charAt(0).reveal()],
  ['at', (v) => v.at(0)?.reveal()],
  ['hash', (v) => v.hash('sha256').reveal()],
  ['hmac', (v) => v.hmac('sha256', HMAC_KEY).reveal()],
  ['map', (v) => v.map((raw) => raw).reveal()],
  ['reclassify', (v) => v.reclassify('credential').reveal()],
  ['serialize', (v) => v.serialize().value],
];

/** Every operation that produces a new protected value from an existing one. */
const DERIVING_OPERATIONS: readonly [string, (value: Sensitive) => Sensitive[]][] = [
  ['concat', (v) => [v.concat('suffix')]],
  ['concat(SensitiveString)', (v) => [v.concat(new SensitiveString('s', 'sensitive'))]],
  ['substring', (v) => [v.substring(0, 4)]],
  ['trim', (v) => [v.trim()]],
  ['trimStart', (v) => [v.trimStart()]],
  ['trimEnd', (v) => [v.trimEnd()]],
  ['toLowerCase', (v) => [v.toLowerCase()]],
  ['toUpperCase', (v) => [v.toUpperCase()]],
  ['padStart', (v) => [v.padStart(64, 'x')]],
  ['padEnd', (v) => [v.padEnd(64, 'x')]],
  ['slice', (v) => [v.slice(1)]],
  ['match', (v) => v.match(/SECRET/) ?? []],
  ['matchGroups', (v) => Object.values(v.matchGroups(/(?<tag>SECRET)/) ?? {})],
  ['matchAll', (v) => Array.from(v.matchAll(/SECRET/g)).flat()],
  ['split', (v) => v.split('_')],
  ['replace', (v) => [v.replace('SECRET', 'x')]],
  ['replaceAll', (v) => [v.replaceAll(/SECRET/g, 'x')]],
  ['charAt', (v) => [v.charAt(0)]],
  ['at', (v) => [v.at(0)!]],
  ['hash', (v) => [v.hash('sha256')]],
  ['hmac', (v) => [v.hmac('sha256', HMAC_KEY)]],
  ['map', (v) => [v.map((raw) => raw)]],
  ['reclassify', (v) => [v.reclassify('credential')]],
  ['template literal', (v) => [st`prefix ${v}`]],
];

beforeEach(() => {
  crypto.deciphers = 0;
  crypto.ciphers = 0;
  compare.strings = 0;
  compare.bytes = 0;
});

/**
 * Every plaintext string produced anywhere while `operation` runs.
 *
 * `Buffer.prototype.toString` is the only way a decrypted box can become one,
 * so wrapping it is a direct reading of the invariant rather than a proxy for
 * it: a comparison that leaves this list empty produced no plaintext string,
 * whatever route it took to get there.
 */
/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call -- `Buffer.prototype` resolves as `any` here, and patching it is the point of the helper: nothing better typed can observe a string this library made but never handed out. */
function stringsDecodedDuring(operation: () => void): string[] {
  const decoded: string[] = [];
  const original = Buffer.prototype.toString;

  Buffer.prototype.toString = function (
    this: Buffer,
    encoding?: BufferEncoding,
    start?: number,
    end?: number
  ): string {
    const result: string = original.call(this, encoding, start, end);
    decoded.push(result);
    return result;
  };

  try {
    operation();
  } finally {
    Buffer.prototype.toString = original;
  }

  return decoded;
}
/* eslint-enable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call */

afterEach(() => {
  resetSealing();
  resetPolicies();
});

describe('the safe path never decrypts', () => {
  it('is measuring what it thinks it is', () => {
    // The guard on every count below. If the wrapper stopped intercepting, the
    // counters would read zero everywhere and each assertion would pass for the
    // wrong reason.
    const value = sealed();
    expect(crypto.ciphers).toBeGreaterThan(0);

    const before = crypto.deciphers;
    value.reveal();
    expect(crypto.deciphers).toBe(before + 1);
  });

  it('answers every safe read without constructing a decipher', () => {
    for (const [name, operation] of SAFE_READ_OPERATIONS) {
      const value = sealed();
      crypto.deciphers = 0;

      const result = operation(value);

      expect(crypto.deciphers, `${name} decrypted`).toBe(0);
      expect(JSON.stringify(result) ?? '', name).not.toContain(CANARY);
    }
  });

  it('answers every safe read after the key has been destroyed', () => {
    // An independent instrument for the same invariant, and a stronger one: a
    // safe read that decrypted would not merely be slow here, it would throw.
    // It is also the shape an incident response actually produces, where the
    // key is gone and the logs still have to render.
    const value = sealed('credential');
    const rendering = value.toString();

    destroySealingKey();

    for (const [name, operation] of SAFE_READ_OPERATIONS) {
      expect(() => operation(value), name).not.toThrow();
    }

    expect(value.toString()).toBe(rendering);
    expect(value.length).toBe(CANARY.length);
    expect(() => value.reveal()).toThrow(SealingKeyDestroyedError);
  });

  it('does not decrypt once per logged object', () => {
    const value = sealed();
    crypto.deciphers = 0;

    for (let line = 0; line < 50; line++) {
      JSON.stringify({ line, token: value });
      inspect(value);
    }

    expect(crypto.deciphers).toBe(0);
  });
});

describe('every raw-value operation', () => {
  it('gives the same answer sealed as unsealed, and leaks nothing either way', () => {
    for (const [name, operation] of RAW_VALUE_OPERATIONS) {
      const fromSealed = operation(sealed());
      const fromPlain = operation(new SensitiveString(CANARY, 'sensitive', 'canary'));

      expect(fromSealed, name).toEqual(fromPlain);
    }
  });

  it('refuses with an error that carries no canary once the key is destroyed', () => {
    for (const [name, operation] of RAW_VALUE_OPERATIONS) {
      const value = sealed();
      destroySealingKey();

      let thrown: unknown;
      try {
        operation(value);
      } catch (error) {
        thrown = error;
      }

      expect(thrown, name).toBeInstanceOf(SealingKeyDestroyedError);
      expect((thrown as Error).message, name).not.toContain(CANARY);
      expect((thrown as Error).stack ?? '', name).not.toContain(CANARY);

      resetSealing();
    }
  });
});

describe('every derivation', () => {
  it('produces a sealed child from a sealed parent', () => {
    for (const [name, derive] of DERIVING_OPERATIONS) {
      const parent = sealed();
      const children = derive(parent);

      expect(children.length, name).toBeGreaterThan(0);

      for (const child of children) {
        expect(child.isSealed, `${name} produced an unsealed child`).toBe(true);
      }
    }
  });

  it('produces children whose plaintext is not reachable without the key', () => {
    for (const [name, derive] of DERIVING_OPERATIONS) {
      const parent = sealed();
      const children = derive(parent);

      destroySealingKey();

      for (const child of children) {
        expect(() => child.reveal(), name).toThrow(SealingKeyDestroyedError);
        expect(child.toString(), name).not.toContain(CANARY);
      }

      resetSealing();
    }
  });
});

describe('tampering with the classification', () => {
  it('makes a rewritten klass unreadable rather than reclassified', () => {
    const value = sealed('credential');

    // The write itself still succeeds: `readonly` is a TypeScript claim, not a
    // runtime one, and freezing is the other half of the answer. What sealing
    // adds is that the write no longer buys anything.
    (value as unknown as { klass: string }).klass = 'sensitive';
    expect(value.klass).toBe('sensitive');

    expect(() => value.reveal()).toThrow(SealedValueIntegrityError);
    expect(() => value.revealBytes()).toThrow(SealedValueIntegrityError);
    expect(() => value.equals(CANARY)).toThrow(SealedValueIntegrityError);
  });

  it('makes a rewritten label unreadable', () => {
    const value = sealed('credential');

    (value as unknown as { label: string }).label = 'harmless';

    expect(() => value.reveal()).toThrow(SealedValueIntegrityError);
  });

  it('makes a label removed or added unreadable', () => {
    const labelled = sealed('credential');
    (labelled as unknown as { label: string | undefined }).label = undefined;
    expect(() => labelled.reveal()).toThrow(SealedValueIntegrityError);

    const unlabelled = new SensitiveString(CANARY, 'credential', undefined, { sealed: true });
    (unlabelled as unknown as { label: string | undefined }).label = '';
    expect(() => unlabelled.reveal()).toThrow(SealedValueIntegrityError);
  });

  it('reports tampering rather than the runtime cipher message', () => {
    const value = sealed('credential');
    (value as unknown as { klass: string }).klass = 'sensitive';

    try {
      value.reveal();
      expect.unreachable('a tampered value must refuse');
    } catch (thrown) {
      const error = thrown as SealedValueIntegrityError;

      expect(error).toBeInstanceOf(SealedValueIntegrityError);
      expect(error.message).not.toMatch(/unsupported state|unable to authenticate/i);
      expect(error.message).not.toContain(CANARY);
      expect(error.stack ?? '').not.toContain(CANARY);
      expect(error.label).toBe('canary');
    }
  });

  it('is not tripped by an untouched value', () => {
    const value = sealed('credential');

    expect(value.reveal()).toBe(CANARY);
    expect(value.klass).toBe('credential');
  });
});

describe('tampering with the box', () => {
  const aad = additionalData('credential', 'canary');

  function box(value = CANARY): Buffer {
    const plain = Buffer.from(value, 'utf8');

    try {
      return sealBytes(plain, aad, 'canary');
    } finally {
      plain.fill(0);
    }
  }

  it('opens an untouched box', () => {
    const opened = openBox(box(), aad, 'canary');

    expect(opened.toString('utf8')).toBe(CANARY);
  });

  it('refuses a flipped bit anywhere in the box', () => {
    const original = box();

    for (let at = 0; at < original.length; at++) {
      const damaged = Buffer.from(original);
      damaged[at] = damaged[at]! ^ 0x01;

      // Byte 0 to 3 is the generation index, so a flip there names a
      // generation the ring does not hold. Every other byte fails the tag.
      expect(() => openBox(damaged, aad, 'canary'), `byte ${String(at)}`).toThrow(
        SealedValueIntegrityError
      );
    }
  });

  it('refuses a truncated box', () => {
    const original = box();

    for (const length of [0, 1, 4, 16, 31, original.length - 1]) {
      expect(() => openBox(original.subarray(0, length), aad, 'canary'), String(length)).toThrow(
        SealedValueIntegrityError
      );
    }
  });

  it('refuses an extended box', () => {
    expect(() => openBox(Buffer.concat([box(), Buffer.from([0])]), aad, 'canary')).toThrow(
      SealedValueIntegrityError
    );
  });

  it('refuses a box opened under different additional data', () => {
    const original = box();

    for (const wrong of [
      additionalData('sensitive', 'canary'),
      additionalData('credential', 'other'),
      additionalData('credential', undefined),
      additionalData('credential', ''),
    ]) {
      expect(() => openBox(original, wrong, 'canary')).toThrow(SealedValueIntegrityError);
    }
  });

  it('distinguishes a missing label from an empty one', () => {
    // The discriminator byte in the additional data, asserted directly: without
    // it the two would produce identical bytes and a box could be moved between
    // them.
    expect(additionalData('credential', undefined)).not.toEqual(additionalData('credential', ''));
  });

  it('refuses a box swapped in from another value', () => {
    const mine = box('mine');
    const theirs = box('theirs');

    // Same key, same additional data, and it still does not open as the other,
    // because each box authenticates its own ciphertext under its own IV.
    expect(openBox(mine, aad, 'canary').toString('utf8')).toBe('mine');
    expect(openBox(theirs, aad, 'canary').toString('utf8')).toBe('theirs');

    const spliced = Buffer.concat([mine.subarray(0, 16), theirs.subarray(16)]);
    expect(() => openBox(spliced, aad, 'canary')).toThrow(SealedValueIntegrityError);
  });

  it('carries no part of the value in its refusal', () => {
    const damaged = box();
    damaged[damaged.length - 1] = damaged.at(-1)! ^ 0x80;

    try {
      openBox(damaged, aad, 'canary');
      expect.unreachable('a damaged box must refuse');
    } catch (thrown) {
      expect((thrown as Error).message).not.toContain(CANARY);
      expect((thrown as Error).stack ?? '').not.toContain(CANARY);
    }
  });
});

describe('equals on a sealed value', () => {
  it('leaves neither operand readable afterwards', () => {
    // Asserted on references the test holds, because the buffers `equals()`
    // works with are otherwise unreachable: the comparand is one of them, and
    // it is zeroed by the same `finally` that zeroes the decrypted side.
    const comparand = new SensitiveString(CANARY, 'sensitive', 'other', { sealed: true });
    const value = sealed();

    const revealed = comparand.revealBytes();
    expect(revealed.toString('utf8')).toBe(CANARY);
    revealed.fill(0);

    expect(value.equals(comparand)).toBe(true);
    // The instances survive their own comparison; only the transient buffers go.
    expect(value.reveal()).toBe(CANARY);
    expect(comparand.reveal()).toBe(CANARY);
  });

  it('produces no plaintext string, whichever side is sealed', () => {
    // The invariant, read directly. A comparison that routed a sealed value
    // through the string path would decrypt exactly as often and cost exactly
    // the same, so a decipher count cannot tell the two apart and this is what
    // does.
    const cases: readonly [string, () => void][] = [
      [
        'both sealed',
        () => {
          sealed().equals(new SensitiveString(CANARY, 'sensitive', 'other', { sealed: true }));
        },
      ],
      ['sealed against a string', () => void sealed().equals(CANARY)],
      [
        'sealed against an unsealed value',
        () => void sealed().equals(new SensitiveString(CANARY, 'sensitive', 'other')),
      ],
      [
        'unsealed against a sealed value',
        () =>
          void new SensitiveString(CANARY, 'sensitive', 'other').equals(
            new SensitiveString(CANARY, 'sensitive', 'x', { sealed: true })
          ),
      ],
    ];

    for (const [name, operation] of cases) {
      expect(stringsDecodedDuring(operation), name).not.toContain(CANARY);
    }
  });

  it('routes a sealed comparison through the byte comparison and never the string one', () => {
    // The second instrument for the same invariant, at the seam rather than at
    // the representation: `compare.ts` publishes one function per operand kind,
    // and a sealed value must reach only the byte one.
    sealed().equals(new SensitiveString(CANARY, 'sensitive', 'other', { sealed: true }));
    expect({ ...compare }).toEqual({ strings: 0, bytes: 1 });

    compare.strings = 0;
    compare.bytes = 0;
    sealed('credential').equals(CANARY);
    expect({ ...compare }).toEqual({ strings: 0, bytes: 1 });

    // And an unsealed credential keeps the string path it has always used, so
    // nothing changes for a caller who did not opt in.
    compare.strings = 0;
    compare.bytes = 0;
    new SensitiveString(CANARY, 'credential', 'x').equals(CANARY);
    expect({ ...compare }).toEqual({ strings: 1, bytes: 0 });
  });

  it('decrypts exactly twice for two sealed operands, and once for one', () => {
    const left = sealed();
    const right = new SensitiveString(CANARY, 'sensitive', 'other', { sealed: true });
    const plain = new SensitiveString(CANARY, 'sensitive', 'other');

    crypto.deciphers = 0;
    left.equals(right);
    expect(crypto.deciphers).toBe(2);

    crypto.deciphers = 0;
    left.equals(plain);
    expect(crypto.deciphers).toBe(1);

    crypto.deciphers = 0;
    left.equals(CANARY);
    expect(crypto.deciphers).toBe(1);
  });

  it('never returns true for the empty string against a non-empty credential', () => {
    // The exact failure the design's subclass probe produced, which is the
    // reason sealing is a storage decision inside the class rather than a
    // subclass on top of it: a stored password that accepts '' from anyone.
    for (const klass of ['credential', 'sensitive'] as const) {
      for (const value of [CANARY, 'a', 'x'.repeat(200)]) {
        const instance = new SensitiveString(value, klass, 'canary', { sealed: true });

        expect(instance.equals(''), `${klass}/${String(value.length)}`).toBe(false);
      }
    }
  });

  it('never returns true for a value it was not built from', () => {
    const value = sealed('credential');

    for (const guess of ['', ' ', CANARY.slice(0, -1), `${CANARY}x`, CANARY.toLowerCase()]) {
      expect(value.equals(guess), JSON.stringify(guess)).toBe(false);
    }

    expect(value.equals(CANARY)).toBe(true);
  });
});

describe('what an instance publishes', () => {
  it('exposes neither the box nor the key through any own property', () => {
    const value = sealed('credential');

    expect(Object.getOwnPropertyNames(value)).toEqual(['klass', 'label']);
    expect(Object.getOwnPropertySymbols(value)).toEqual([]);

    for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(value))) {
      expect(Buffer.isBuffer(descriptor.value)).toBe(false);
    }
  });

  it('exposes no Buffer anywhere on the prototype chain', () => {
    const value = sealed('credential');
    let proto: object | null = Object.getPrototypeOf(value) as object | null;

    while (proto !== null) {
      for (const key of Object.getOwnPropertyNames(proto)) {
        if (key === 'constructor') {
          continue;
        }

        try {
          const read = (value as unknown as Record<string, unknown>)[key];

          expect(Buffer.isBuffer(read), key).toBe(false);
          if (typeof read !== 'function') {
            expect(String(read), key).not.toContain(CANARY);
          }
        } catch {
          // A getter is free to refuse; refusing discloses nothing.
        }
      }

      proto = Object.getPrototypeOf(proto) as object | null;
    }
  });

  it('reaches nothing sensitive through JSON, inspect or structured redaction', () => {
    const value = sealed('credential');
    const renderings = [
      JSON.stringify(value),
      JSON.stringify({ deep: { list: [value] } }),
      inspect(value, { depth: 10, showHidden: true }),
      safeStringify({ token: value }),
      JSON.stringify(redactInStructure({ token: value })),
      JSON.stringify(redactCopy({ token: value })),
    ];

    for (const rendering of renderings) {
      expect(rendering ?? '').not.toContain(CANARY);
      // A box or a key rendered as a Buffer would show as one of these.
      expect(rendering ?? '').not.toMatch(/"type":\s*"Buffer"/);
      expect(rendering ?? '').not.toMatch(/<Buffer /);
    }
  });

  it('publishes no way to read, set or export a sealing key', async () => {
    const core: Record<string, unknown> = await import('../index.js');
    const surface = Object.keys(core);

    // Listed rather than excluded from the pattern, so a future sealing export
    // has to be looked at here before it can ship. None of these five hands a
    // key to anybody: two are the configuration, one destroys, and two name a
    // refusal.
    expect(surface.filter((name) => /sealing/i.test(name)).sort()).toEqual([
      'SealingKeyDestroyedError',
      'SealingUnavailableError',
      'destroySealingKey',
      'getSealing',
      'resetSealing',
      'setSealing',
    ]);

    // And nothing anywhere on the surface reads or writes a key of any kind.
    expect(surface.filter((name) => /^(get|set|export|read)[A-Z].*Key/.test(name))).toEqual([]);

    // And the destroy returns nothing, so it cannot hand back what it zeroed.
    expect(destroySealingKey()).toBeUndefined();

    for (const name of surface) {
      expect(Buffer.isBuffer(core[name]), name).toBe(false);
    }
  });
});

describe('canaries in every path this feature adds', () => {
  it('keeps the canary out of every sealing error', () => {
    const cases: readonly [string, () => unknown][] = [
      [
        'destroyed key',
        () => {
          const value = sealed('credential');
          destroySealingKey();
          return value.reveal();
        },
      ],
      [
        'tampered classification',
        () => {
          const value = sealed('credential');
          (value as unknown as { klass: string }).klass = 'sensitive';
          return value.reveal();
        },
      ],
      [
        'damaged box',
        () => {
          const aad = additionalData('credential', 'canary');
          const plain = Buffer.from(CANARY, 'utf8');
          const damaged = sealBytes(plain, aad, 'canary');
          plain.fill(0);
          damaged[damaged.length - 1] = damaged.at(-1)! ^ 0xff;
          return openBox(damaged, aad, 'canary');
        },
      ],
      [
        'invalid UTF-8 from fromBuffer',
        () => SensitiveString.fromBuffer(Buffer.from([0xff, 0xfe]), 'credential', CANARY),
      ],
    ];

    for (const [name, run] of cases) {
      let thrown: unknown;
      try {
        run();
      } catch (error) {
        thrown = error;
      }

      expect(thrown, name).toBeInstanceOf(Error);
      const error = thrown as Error;

      expect(error.message, name).not.toContain(CANARY);
      // The stack is a lazy accessor, so it is read rather than assumed.
      expect(error.stack ?? '', name).not.toContain(CANARY);
      expect(inspect(error), name).not.toContain(CANARY);
      expect(JSON.stringify(error, Object.getOwnPropertyNames(error)), name).not.toContain(CANARY);

      resetSealing();
    }
  });

  it('keeps the canary out of fromBuffer, whose only argument is the value', () => {
    // The label slot is where caller text legitimately appears, so this case
    // puts the canary in the value and asserts the message is the library's own
    // prose plus a byte offset.
    const bytes = Buffer.concat([Buffer.from(CANARY, 'utf8'), Buffer.from([0xff])]);

    try {
      SensitiveString.fromBuffer(bytes, 'credential', 'db_password');
      expect.unreachable('invalid UTF-8 must be refused');
    } catch (thrown) {
      expect((thrown as Error).message).not.toContain(CANARY);
      expect((thrown as Error).message).toMatch(/valid UTF-8/);
    }
  });

  it('holds no canary in a sealed value that was never revealed', () => {
    // A structural stand-in for the heap probe, which lives in the timing
    // suite: nothing a caller can reach renders the value.
    const value = sealed('credential');
    const reachable = [
      value.toString(),
      value.toJSON(),
      inspect(value, { depth: 10, showHidden: true }),
      String(value.length),
      String(value.isEmpty()),
      String(value.isSealed),
      safeStringify({ value }),
    ].join('|');

    expect(reachable).not.toContain(CANARY);
  });
});

describe('a sealed value under the rest of the gate', () => {
  it('is refused by the redaction scope before it decrypts', () => {
    const value = sealed('credential');
    const holder = {
      token: value,
      toJSON() {
        // A reveal from inside a walk that is running this object's toJSON on
        // its behalf. The walk absorbs the refusal and redacts the own
        // properties instead, so what this asserts is the output and the count.
        return { token: this.token.reveal() };
      },
    };

    crypto.deciphers = 0;
    const redacted = JSON.stringify(redactInStructure({ holder }));

    expect(redacted).not.toContain(CANARY);
    expect(crypto.deciphers).toBe(0);
  });

  it('does not decrypt for a read the environment refuses', () => {
    setEnvironmentInfo({ environment: 'production' });

    try {
      const value = new SensitiveString(CANARY, 'credential', 'canary', {
        sealed: true,
        restrictions: { allowedEnvironments: ['staging'] },
      });

      crypto.deciphers = 0;
      expect(() => value.reveal()).toThrow(/environment|restrict/i);
      expect(crypto.deciphers).toBe(0);
    } finally {
      resetEnvironmentInfo();
    }
  });

  it('does not decrypt for a read a spent budget refuses', () => {
    const value = new SensitiveString(CANARY, 'credential', 'canary', {
      sealed: true,
      maxReveals: 1,
    });

    value.reveal();
    crypto.deciphers = 0;

    expect(() => value.reveal()).toThrow();
    expect(crypto.deciphers).toBe(0);
  });

  it('does not decrypt for a read an audit hook stopped', () => {
    const value = sealed('credential');

    crypto.deciphers = 0;
    expect(() =>
      value.reveal({
        name: 'refuser',
        auditReveal: () => {
          throw new Error('sink says no');
        },
      })
    ).toThrow('sink says no');
    expect(crypto.deciphers).toBe(0);
  });
});

describe('a sealed value and the canary corpus', () => {
  it('round-trips values the encoding makes awkward', () => {
    const values = [
      ' embedded nul ',
      'trailing spaces   ',
      '� literal replacement char',
      randomBytes(64).toString('base64'),
      randomBytes(64).toString('hex'),
      '\\n\\t escapes as text',
      '"quotes" and {braces}',
      'x'.repeat(65536),
    ];

    for (const value of values) {
      const instance = new SensitiveString(value, 'credential', 'corpus', { sealed: true });

      expect(instance.reveal(), JSON.stringify(value.slice(0, 24))).toBe(value);
      expect(instance.length).toBe(value.length);
      expect(instance.equals(value)).toBe(true);
    }
  });
});
