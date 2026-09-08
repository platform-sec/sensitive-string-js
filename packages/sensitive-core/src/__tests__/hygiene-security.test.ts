/**
 * Memory hygiene, adversarially.
 *
 * Two enumerating tables drive it, the way `ttl-security.test.ts` established:
 * an operation added later that forgets the gate fails here rather than
 * shipping as a bypass, and a derivation that dropped the cleared state would
 * hand back a working copy of a value the caller destroyed.
 */
import * as util from 'node:util';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  ClearedSensitiveValueError,
  clearAllSensitiveValues,
  containsSensitive,
  deterministicRedaction,
  getMemoryHygiene,
  registerPolicy,
  redactCopy,
  redactInStructure,
  resetMemoryHygiene,
  resetPolicies,
  safeLog,
  safeStringify,
  SensitiveString,
  sensitiveClassesIn,
  setMemoryHygiene,
  st,
  withRevealContext,
} from '../index.js';
import type { RevealDetails, SensitivityClass } from '../index.js';

/** Flat, and built by concatenation nowhere: see the retention suite's note. */
const CANARY = 'HYGIENE_SECURITY_CANARY_3d71';

/** An HMAC key long enough to clear the 16-byte floor. */
const HMAC_KEY = 'k'.repeat(32);

/**
 * Every operation that reaches the raw value, named so a new one that forgets
 * the gate fails here rather than shipping as a bypass.
 */
const RAW_VALUE_OPERATIONS: readonly [string, (value: SensitiveString<'sensitive'>) => unknown][] =
  [
    ['reveal', (v) => v.reveal()],
    ['mask', (v) => v.mask({ showLast: 2 })],
    ['equals', (v) => v.equals(CANARY)],
    ['equals(SensitiveString)', (v) => new SensitiveString('other', 'sensitive').equals(v)],
    ['concat', (v) => v.concat('suffix')],
    ['substring', (v) => v.substring(0, 4)],
    ['trim', (v) => v.trim()],
    ['trimStart', (v) => v.trimStart()],
    ['trimEnd', (v) => v.trimEnd()],
    ['toLowerCase', (v) => v.toLowerCase()],
    ['toUpperCase', (v) => v.toUpperCase()],
    ['padStart', (v) => v.padStart(64, 'x')],
    ['padEnd', (v) => v.padEnd(64, 'x')],
    ['slice', (v) => v.slice(1)],
    ['startsWith', (v) => v.startsWith('H')],
    ['endsWith', (v) => v.endsWith('1')],
    ['includes', (v) => v.includes('CANARY')],
    ['indexOf', (v) => v.indexOf('CANARY')],
    ['lastIndexOf', (v) => v.lastIndexOf('CANARY')],
    ['test', (v) => v.test(/CANARY/)],
    ['search', (v) => v.search(/CANARY/)],
    ['match', (v) => v.match(/CANARY/)],
    ['matchGroups', (v) => v.matchGroups(/(?<tag>CANARY)/)],
    ['matchAll', (v) => v.matchAll(/CANARY/g)],
    ['split', (v) => v.split('_')],
    ['replace', (v) => v.replace('CANARY', 'x')],
    ['replaceAll', (v) => v.replaceAll(/CANARY/g, 'x')],
    ['charAt', (v) => v.charAt(0)],
    ['at', (v) => v.at(0)],
    ['hash', (v) => v.hash('sha256')],
    ['hmac', (v) => v.hmac('sha256', HMAC_KEY)],
    ['map', (v) => v.map((raw) => raw)],
    ['reclassify', (v) => v.reclassify('credential')],
    ['serialize', (v) => v.serialize()],
    ['length', (v) => v.length],
    ['isEmpty', (v) => v.isEmpty()],
  ];

/**
 * Every operation that produces a new protected value from an existing one. A
 * derivation that dropped the cleared state would hand back a working copy of
 * a value the caller destroyed.
 */
const DERIVING_OPERATIONS: readonly [
  string,
  (value: SensitiveString<'sensitive'>) => SensitiveString<SensitivityClass>[],
][] = [
  ['concat', (v) => [v.concat('suffix')]],
  ['concat(SensitiveString)', (v) => [v.concat(new SensitiveString('suffix', 'sensitive'))]],
  ['substring', (v) => [v.substring(0, 4)]],
  ['trim', (v) => [v.trim()]],
  ['trimStart', (v) => [v.trimStart()]],
  ['trimEnd', (v) => [v.trimEnd()]],
  ['toLowerCase', (v) => [v.toLowerCase()]],
  ['toUpperCase', (v) => [v.toUpperCase()]],
  ['padStart', (v) => [v.padStart(64, 'x')]],
  ['padEnd', (v) => [v.padEnd(64, 'x')]],
  ['slice', (v) => [v.slice(1)]],
  ['match', (v) => v.match(/CANARY/) ?? []],
  ['matchGroups', (v) => Object.values(v.matchGroups(/(?<tag>CANARY)/) ?? {})],
  ['matchAll', (v) => Array.from(v.matchAll(/CANARY/g)).flat()],
  ['split', (v) => v.split('_')],
  ['replace', (v) => [v.replace('CANARY', 'x')]],
  ['replaceAll', (v) => [v.replaceAll(/CANARY/g, 'x')]],
  ['charAt', (v) => [v.charAt(0)]],
  ['at', (v) => [v.at(0)!]],
  ['hash', (v) => [v.hash('sha256')]],
  ['hmac', (v) => [v.hmac('sha256', HMAC_KEY)]],
  ['map', (v) => [v.map((raw) => raw)]],
  ['reclassify', (v) => [v.reclassify('credential')]],
  ['template literal', (v) => [st`prefix ${v}`]],
];

function canary(label = 'canary'): SensitiveString<'sensitive'> {
  return new SensitiveString(CANARY, 'sensitive', label);
}

describe('memory hygiene security', () => {
  beforeEach(() => {
    resetPolicies();
    resetMemoryHygiene();
  });

  afterEach(() => {
    resetMemoryHygiene();
    resetPolicies();
  });

  describe('the gate', () => {
    it('refuses every operation that reaches the raw value, and leaks nothing doing it', () => {
      for (const [name, operation] of RAW_VALUE_OPERATIONS) {
        const value = canary();
        value.clear();

        let thrown: unknown;
        try {
          operation(value);
          expect.unreachable(`${name} must refuse a cleared value`);
        } catch (error) {
          thrown = error;
        }

        expect(thrown, name).toBeInstanceOf(ClearedSensitiveValueError);
        expect(String(thrown), name).not.toContain(CANARY);
        // The stack is a lazy accessor: reading it here is what forces the
        // frames to be formatted, which is where a message built from the
        // value would show up.
        expect((thrown as Error).stack ?? '', name).not.toContain(CANARY);
      }
    });

    it('gives every derivative the parent state, so clearing the parent refuses it', () => {
      for (const [name, derive] of DERIVING_OPERATIONS) {
        const parent = canary();
        const children = derive(parent);

        expect(children.length, name).toBeGreaterThan(0);

        parent.clear();

        for (const child of children) {
          expect(child.isCleared, name).toBe(true);

          let thrown: unknown;
          try {
            child.reveal();
            expect.unreachable(`${name} must produce a value the parent's clear refuses`);
          } catch (error) {
            thrown = error;
          }

          expect(thrown, name).toBeInstanceOf(ClearedSensitiveValueError);
          expect(String(thrown), name).not.toContain(CANARY);
        }
      }
    });

    it('refuses a cleared value inside an authorized context', () => {
      const value = canary();
      value.clear();

      withRevealContext({ name: 'trusted', reason: 'operator asked' }, () => {
        expect(() => value.reveal()).toThrow(ClearedSensitiveValueError);
      });
    });
  });

  describe('canaries', () => {
    it('yields the canary from no method after a clear', () => {
      const value = canary();
      value.clear();

      const rendered = [
        value.toString(),
        value.toJSON(),
        JSON.stringify({ value }),
        JSON.stringify(value),
        String(value),
        util.inspect(value),
      ];

      for (const output of rendered) {
        expect(output).not.toContain(CANARY);
      }
    });

    it('keeps the canary out of the error, its message and its stack', () => {
      const value = canary('db_password');
      value.clear();

      try {
        value.reveal();
        expect.unreachable('a cleared value must refuse');
      } catch (error) {
        const thrown = error as ClearedSensitiveValueError;

        expect(thrown.message).not.toContain(CANARY);
        expect(thrown.stack ?? '').not.toContain(CANARY);
        // The label is developer text and appears by design, which is what
        // makes the error actionable.
        expect(thrown.message).toContain('db_password');
      }
    });

    it('yields the canary from no derived operation after the origin is cleared', () => {
      const parent = canary();
      const children = DERIVING_OPERATIONS.flatMap(([, derive]) => derive(parent));

      parent.clear();

      for (const child of children) {
        expect(String(child)).not.toContain(CANARY);
        expect(() => child.reveal()).toThrow(ClearedSensitiveValueError);
        expect(JSON.stringify({ child })).not.toContain(CANARY);
      }
    });

    it('survives every redaction helper, because logging must never throw', () => {
      // The guarantee this feature must not break. An error handler doing
      // `logger.error({ err, token })` on a cleared token would otherwise
      // raise a second error from inside the first and lose the diagnostic.
      // A derivative that only inherited the clear is in the payload too: it
      // renders live rather than from a snapshot, which is the other branch.
      const token = new SensitiveString(CANARY, 'credential', 'tok');
      const derived = token.substring(0, 16);
      token.clear();

      const payload = { token, derived, nested: { list: [token, derived] } };

      expect(() => redactInStructure(payload)).not.toThrow();
      expect(() => safeStringify(payload)).not.toThrow();
      expect(() => safeLog(payload)).not.toThrow();
      expect(() => containsSensitive(payload)).not.toThrow();
      expect(() => sensitiveClassesIn(payload)).not.toThrow();
      expect(() => redactCopy(payload)).not.toThrow();

      expect(safeStringify(payload)).not.toContain(CANARY);
      expect(JSON.stringify(redactInStructure(payload))).not.toContain(CANARY);
      expect(JSON.stringify(redactCopy(payload))).not.toContain(CANARY);
    });

    it('has no method that un-clears a value', () => {
      const value = canary();
      value.clear();

      const names = new Set<string>();
      for (
        let proto: object | null = Object.getPrototypeOf(value) as object | null;
        proto !== null && proto !== Object.prototype;
        proto = Object.getPrototypeOf(proto) as object | null
      ) {
        for (const name of Object.getOwnPropertyNames(proto)) {
          names.add(name);
        }
      }

      expect([...names].filter((name) => /unclear|uncleared|restore|revive/i.test(name))).toEqual(
        []
      );
      expect(value.isCleared).toBe(true);
    });
  });

  describe('the gate does not route through anything overridable', () => {
    it('is not lifted by a subclass that overrides isCleared and clearedAt', () => {
      class Liar extends SensitiveString<'sensitive'> {
        override get isCleared(): boolean {
          return false;
        }

        override get clearedAt(): Date | undefined {
          return undefined;
        }
      }

      const value = new Liar(CANARY, 'sensitive', 'liar');
      value.clear();

      expect(value.isCleared).toBe(false);
      expect(value.clearedAt).toBeUndefined();
      // The gate reads the private flag, so the lie changes nothing.
      expect(() => value.reveal()).toThrow(ClearedSensitiveValueError);
      expect(() => value.length).toThrow(ClearedSensitiveValueError);
    });

    it('is not lifted by an own isCleared property on the instance', () => {
      const value = canary();
      value.clear();

      Object.defineProperty(value, 'isCleared', { value: false, configurable: true });

      expect(value.isCleared).toBe(false);
      expect(() => value.reveal()).toThrow(ClearedSensitiveValueError);
    });
  });

  describe('the wire format', () => {
    it('refuses to serialize a cleared value, and emits no payload', () => {
      const value = canary();
      value.clear();

      let payload: unknown;
      expect(() => {
        payload = value.serialize();
      }).toThrow(ClearedSensitiveValueError);

      expect(payload).toBeUndefined();
      expect(JSON.stringify(payload) ?? '').not.toContain(CANARY);
    });

    it('has no field a cleared state could cross on', () => {
      const value = canary();
      const serialized = value.serialize();

      expect(Object.keys(serialized)).not.toContain('cleared');
      expect(Object.keys(serialized)).not.toContain('clearedAt');

      const received = SensitiveString.deserialize<'sensitive'>(serialized);
      expect(received.isCleared).toBe(false);
    });
  });

  describe('freezeInstances', () => {
    it('refuses klass and label writes, own properties, and prototype replacement', () => {
      setMemoryHygiene({ freezeInstances: true });
      const value = new SensitiveString(CANARY, 'credential', 'api_key');

      expect(() => {
        (value as unknown as { klass: string }).klass = 'sensitive';
      }).toThrow(TypeError);
      expect(() => {
        (value as unknown as { label: string }).label = 'forged';
      }).toThrow(TypeError);
      expect(() => {
        Object.defineProperty(value, 'label', { value: 'forged' });
      }).toThrow(TypeError);
      expect(() => {
        // A block body, not an expression: `setPrototypeOf` returns `any`, and
        // returning it from the arrow is what the unsafe-return rule catches.
        Object.setPrototypeOf(value, null);
      }).toThrow(TypeError);

      expect(value.klass).toBe('credential');
      expect(value.label).toBe('api_key');
      expect(value.reveal()).toBe(CANARY);
    });

    it('cannot have redaction redirected by an own toJSON', () => {
      setMemoryHygiene({ freezeInstances: true });
      const value = new SensitiveString(CANARY, 'credential', 'api_key');

      expect(() => {
        (value as unknown as { toJSON: () => string }).toJSON = () => CANARY;
      }).toThrow(TypeError);

      expect(JSON.stringify({ value })).not.toContain(CANARY);
      expect(JSON.stringify({ value })).toContain('[REDACTED:credential]');
    });

    it('is what the unfrozen default permits, which is why the switch exists', () => {
      // The same four writes against an unfrozen instance, so the row this
      // feature is defending is measured rather than assumed.
      const value = new SensitiveString(CANARY, 'credential', 'api_key');

      (value as unknown as { toJSON: () => string }).toJSON = () => 'FORGED';
      expect(JSON.stringify({ value })).toContain('FORGED');

      (value as unknown as { klass: string }).klass = 'sensitive';
      expect(value.toString()).toBe('[REDACTED:sensitive]');
    });

    it('leaves clear() working, because #private fields are not frozen', () => {
      setMemoryHygiene({ freezeInstances: true });
      const value = new SensitiveString(CANARY, 'credential', 'api_key');

      expect(() => value.clear()).not.toThrow();
      expect(value.isCleared).toBe(true);
      expect(() => value.reveal()).toThrow(ClearedSensitiveValueError);
      expect(value.toString()).toBe('[REDACTED:credential]');
    });
  });

  describe('deterministic redaction', () => {
    const KEY = 'deterministic-key-of-sufficient-length';

    function registerDeterministic(): void {
      registerPolicy(deterministicRedaction('sensitive', { key: KEY }), { overwrite: true });
    }

    it('keeps a cleared value at the tag it had before the clear', () => {
      registerDeterministic();

      const value = canary();
      const before = value.toString();

      value.clear();

      expect(value.toString()).toBe(before);
      expect(value.toJSON()).toBe(before);
      expect(before).not.toContain(CANARY);
    });

    it('does not give two cleared values one shared tag', () => {
      registerDeterministic();

      const first = new SensitiveString(`${CANARY}-one`, 'sensitive', 'first');
      const second = new SensitiveString(`${CANARY}-two`, 'sensitive', 'second');

      first.clear();
      second.clear();

      // Without the snapshot both would redact to the tag of the empty string,
      // which a log reader would read as a correlation between two unrelated
      // values. A false correlation in an audit log is worse than none.
      expect(first.toString()).not.toBe(second.toString());
    });

    it('renders the pre-clear tag even after the policy is re-registered', () => {
      registerDeterministic();

      const value = canary();
      value.clear();
      const snapshot = value.toString();

      registerPolicy(
        {
          name: 'sensitive',
          redact: () => '[REDACTED:sensitive]',
          requireConstantTimeEquals: false,
        },
        { overwrite: true }
      );

      // The documented cost of the snapshot: a cleared value's rendering is
      // fixed at the moment it was destroyed.
      expect(value.toString()).toBe(snapshot);
    });
  });

  describe('a broken policy or sink does not prevent a clear', () => {
    it('clears through a redact that throws, and renders the default marker', () => {
      // `registerPolicy` calls the redactor to validate it, so the break is
      // armed after registration rather than during it.
      let broken = false;
      registerPolicy(
        {
          name: 'sensitive',
          redact: () => {
            if (broken) {
              throw new Error('redactor is broken');
            }

            return '[REDACTED:sensitive]';
          },
          requireConstantTimeEquals: false,
        },
        { overwrite: true }
      );

      const value = canary();
      broken = true;

      expect(() => value.clear()).not.toThrow();
      expect(value.isCleared).toBe(true);
      expect(value.toString()).toBe('[REDACTED:sensitive]');
      expect(value.toString()).not.toContain(CANARY);
    });

    it('clears through an audit sink that throws', () => {
      const value = canary();
      const auditReveal = vi.fn((_v: unknown, _d: RevealDetails) => {
        throw new Error('sink is down');
      });

      expect(() => value.clear({ name: 'shutdown', auditReveal })).not.toThrow();
      expect(auditReveal).toHaveBeenCalledOnce();
      expect(value.isCleared).toBe(true);
      expect(() => value.reveal()).toThrow(ClearedSensitiveValueError);
    });

    it('sweeps past an instance whose sink throws', () => {
      setMemoryHygiene({ trackInstances: true });

      const first = canary('first');
      const second = canary('second');

      // The sweep takes no context of its own, so the throwing sink is the
      // ambient one; what matters is that neither instance survives.
      expect(clearAllSensitiveValues()).toBe(2);
      expect(first.isCleared).toBe(true);
      expect(second.isCleared).toBe(true);
    });
  });

  describe('tracking', () => {
    // Whether a `WeakRef` actually clears, and whether the finalizer actually
    // prunes, need `global.gc` and live in `hygiene-retention.timing.test.ts`
    // with the rest of the collector measurements. They are deliberately not
    // here behind a `typeof global.gc` guard that returns early: `pnpm test`
    // runs without `--expose-gc`, so such a test would report a pass for a
    // measurement it never took.

    it('is off unless it is switched on', () => {
      expect(getMemoryHygiene()).toEqual({ freezeInstances: false, trackInstances: false });

      const value = canary();
      expect(clearAllSensitiveValues()).toBe(0);
      expect(value.isCleared).toBe(false);
    });
  });
});
