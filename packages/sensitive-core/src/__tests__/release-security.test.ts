/**
 * A reveal that waits on a verification, driven through the exposing-operation
 * table the destination suite drives: every operation that hands plaintext
 * out refuses while the verification is pending, refuses for good once it
 * has said anything but yes, and works once it has said yes.
 *
 * The corpus case is a password whose destination is trusted only after an
 * SSH host key has been checked against a known-hosts store. A path that
 * hands the value out before that check settles is the leak the option
 * exists to close.
 */
import * as util from 'node:util';
import { describe, expect, it, vi } from 'vitest';
import {
  SensitiveString,
  st,
  toWorkerPayload,
  UnreleasedSensitiveValueError,
  withRevealContext,
} from '../index.js';
import type { RevealContext } from '../index.js';

const CANARY = 'RELEASE_SECURITY_CANARY_5c1d';
const HMAC_KEY = 'k'.repeat(32);

/** A verification the test settles by hand. */
function gate(): { promise: Promise<boolean>; yes: () => void; no: () => void; fail: () => void } {
  let resolve!: (answer: boolean) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<boolean>((res, rej) => {
    resolve = res;
    reject = rej;
  });

  return {
    promise,
    yes: () => resolve(true),
    no: () => resolve(false),
    fail: () => reject(new Error('host key mismatch')),
  };
}

/** Let the promise's handlers run. */
const settle = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));

function held(promise: Promise<boolean>, label = 'ssh_password'): SensitiveString<'credential'> {
  return new SensitiveString(CANARY, 'credential', label, { releasedBy: promise });
}

const EXPOSING_OPERATIONS: readonly [string, (value: SensitiveString<'credential'>) => unknown][] =
  [
    ['reveal', (v) => v.reveal()],
    ['revealBytes', (v) => v.revealBytes()],
    ['concat', (v) => v.concat('suffix')],
    ['substring', (v) => v.substring(0, 4)],
    ['trim', (v) => v.trim()],
    ['toLowerCase', (v) => v.toLowerCase()],
    ['padStart', (v) => v.padStart(64, 'x')],
    ['slice', (v) => v.slice(1)],
    ['split', (v) => v.split('_')],
    ['replace', (v) => v.replace('CANARY', 'x')],
    ['charAt', (v) => v.charAt(0)],
    ['at', (v) => v.at(0)],
    ['hash', (v) => v.hash('sha256')],
    ['hmac', (v) => v.hmac('sha256', HMAC_KEY)],
    ['map', (v) => v.map((raw) => raw)],
    ['reclassify', (v) => v.reclassify('sensitive')],
    ['serialize', (v) => v.serialize()],
    ['template literal', (v) => st`prefix ${v}`],
    ['toWorkerPayload', (v) => toWorkerPayload({ v })],
  ];

describe('a reveal that waits on a verification', () => {
  describe('construction', () => {
    it('refuses anything that is not a thenable, naming the type and not the value', () => {
      for (const releasedBy of [true, false, 'yes', 1, null, {}]) {
        expect(
          () =>
            new SensitiveString(CANARY, 'credential', 'p', {
              releasedBy: releasedBy as unknown as Promise<boolean>,
            }),
          typeof releasedBy
        ).toThrow(TypeError);
      }
    });

    it('accepts a foreign thenable', async () => {
      const thenable = { then: (ok: (v: boolean) => void) => ok(true) };
      const value = new SensitiveString(CANARY, 'credential', 'p', {
        releasedBy: thenable as unknown as PromiseLike<boolean>,
      });

      await settle();
      expect(value.reveal()).toBe(CANARY);
    });
  });

  describe('the gate', () => {
    it('refuses every exposing operation while the verification is pending', () => {
      for (const [name, operation] of EXPOSING_OPERATIONS) {
        const value = held(gate().promise);

        let thrown: unknown;
        try {
          operation(value);
          expect.unreachable(`${name} must refuse a value whose verification is pending`);
        } catch (error) {
          thrown = error;
        }

        expect(thrown, name).toBeInstanceOf(UnreleasedSensitiveValueError);
        expect((thrown as UnreleasedSensitiveValueError).status, name).toBe('pending');
        expect(String(thrown), name).not.toContain(CANARY);
        expect(util.inspect(thrown), name).not.toContain(CANARY);
      }
    });

    it('allows every exposing operation once the verification says yes', async () => {
      for (const [name, operation] of EXPOSING_OPERATIONS) {
        const g = gate();
        const value = held(g.promise);
        g.yes();
        await settle();

        expect(() => operation(value), name).not.toThrow();
      }
    });

    it('refuses for good once the verification says no, throws, or answers off type', async () => {
      const cases: [string, () => Promise<boolean>, string][] = [
        ['false', () => Promise.resolve(false), 'its verification refused'],
        ['throw', () => Promise.reject(new Error('host key mismatch')), 'threw instead'],
        [
          'off type',
          () => Promise.resolve('yes' as unknown as boolean),
          'answered with string instead of a boolean',
        ],
      ];

      for (const [name, make, detail] of cases) {
        const value = held(make());
        await settle();

        for (const [operation, run] of EXPOSING_OPERATIONS) {
          let thrown: unknown;
          try {
            run(value);
            expect.unreachable(`${operation} must refuse after ${name}`);
          } catch (error) {
            thrown = error;
          }

          expect(thrown, `${name}/${operation}`).toBeInstanceOf(UnreleasedSensitiveValueError);
          expect((thrown as UnreleasedSensitiveValueError).status).toBe('refused');
          expect(String(thrown), `${name}/${operation}`).toContain(detail);
          expect(String(thrown), `${name}/${operation}`).not.toContain(CANARY);
        }
      }
    });

    it('carries the cause of a throwing verification without the value', async () => {
      const g = gate();
      const value = held(g.promise);
      g.fail();
      await settle();

      let thrown: unknown;
      try {
        value.reveal();
      } catch (error) {
        thrown = error;
      }

      expect((thrown as Error).cause).toBeInstanceOf(Error);
      expect(String((thrown as Error).cause)).toContain('host key mismatch');
      expect(util.inspect(thrown)).not.toContain(CANARY);
    });

    it('does not check a comparison, which sends the value nowhere', () => {
      const value = held(gate().promise);

      expect(value.equals(CANARY)).toBe(true);
      expect(new SensitiveString(CANARY, 'credential').equals(value)).toBe(true);
    });

    it('keeps redaction and metadata working while held', () => {
      const value = held(gate().promise, 'held');

      expect(String(value)).not.toContain(CANARY);
      expect(JSON.stringify({ value })).not.toContain(CANARY);
      expect(util.inspect(value)).not.toContain(CANARY);
      expect(value.length).toBe(CANARY.length);
      expect(value.label).toBe('held');
    });

    it('denies before the policy hook, the audit hook and the budget', () => {
      const audit = vi.fn();
      const value = new SensitiveString(CANARY, 'credential', 'p', {
        releasedBy: gate().promise,
        maxReveals: 1,
      });

      expect(() => value.reveal({ name: 'x', auditReveal: audit })).toThrow(
        UnreleasedSensitiveValueError
      );
      expect(audit).not.toHaveBeenCalled();
      expect(value.revealsRemaining).toBe(1);
    });

    it('cannot be released from outside, and a refusal does not soften on a retry', async () => {
      const g = gate();
      const value = held(g.promise);
      g.no();
      await settle();

      for (let attempt = 0; attempt < 3; attempt += 1) {
        expect(() => value.reveal()).toThrow(UnreleasedSensitiveValueError);
      }

      // The promise has settled; nothing on the value's public surface holds
      // the cell, so nothing can change what it said.
      expect(Object.keys(value)).toEqual(['klass', 'label']);
      expect(JSON.stringify(value)).not.toContain('release');
    });

    it('reads the ambient or explicit context only after the check, so a held value is refused under either', () => {
      const value = held(gate().promise);
      const ctx: RevealContext = { name: 'explicit', tags: { sink: 'http', host: 'h.example' } };

      expect(() => value.reveal(ctx)).toThrow(UnreleasedSensitiveValueError);
      withRevealContext(ctx, () => {
        expect(() => value.reveal()).toThrow(UnreleasedSensitiveValueError);
      });
    });
  });

  describe('derived values and the wire', () => {
    it('cannot derive from a held value, and a derivation after release is released', async () => {
      const g = gate();
      const value = held(g.promise);

      expect(() => value.substring(0, 4)).toThrow(UnreleasedSensitiveValueError);

      g.yes();
      await settle();
      const child = value.substring(0, 4);
      expect(child.reveal()).toBe(CANARY.slice(0, 4));
    });

    it('refuses to serialize while held and carries nothing once released', async () => {
      const g = gate();
      const value = held(g.promise);

      expect(() => value.serialize()).toThrow(UnreleasedSensitiveValueError);

      g.yes();
      await settle();
      const wire = value.serialize();
      expect(JSON.stringify(wire)).not.toContain('release');
      expect(SensitiveString.deserialize<'credential'>(wire).reveal()).toBe(CANARY);
    });

    it('leaves no unhandled rejection when the verification throws and nothing reads the value', async () => {
      const unhandled: unknown[] = [];
      const listener = (reason: unknown): void => {
        unhandled.push(reason);
      };
      process.on('unhandledRejection', listener);

      try {
        held(Promise.reject(new Error('host key mismatch')));
        await settle();
        await settle();
      } finally {
        process.off('unhandledRejection', listener);
      }

      expect(unhandled).toEqual([]);
    });
  });
});
