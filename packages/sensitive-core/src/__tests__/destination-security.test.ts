/**
 * Destination binding, driven through the same two tables the TTL,
 * reveal-budget, revocation and environment suites use: every operation that
 * hands plaintext out of the library, and every operation that derives a new
 * protected value from one.
 *
 * A binding that lives only in `reveal()` is walked past by
 * `secret.map(v => v).reveal()`, and one a derivation drops hands back a copy
 * that may go anywhere. The corpus finding this feature answers is a value
 * wrapped correctly, revealed exactly where the design says, and sent to the
 * wrong host; a bypass here would reproduce it with one more step.
 */
import * as util from 'node:util';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  DestinationRestrictedError,
  EnvironmentRestrictedError,
  ExpiredSensitiveValueError,
  fromWorkerPayload,
  resetEnvironmentInfo,
  resetPolicies,
  revokeByLabel,
  RevealLimitExceededError,
  RevokedSensitiveValueError,
  safeStringify,
  SensitiveString,
  setEnvironmentInfo,
  st,
  toWorkerPayload,
  withRevealContext,
} from '../index.js';
import type { RevealContext, RevealDetails, SensitivityClass } from '../index.js';

const CANARY = 'DESTINATION_SECURITY_CANARY_3e8a';

/** An HMAC key long enough to clear the 16-byte floor. */
const HMAC_KEY = 'k'.repeat(32);

/** The one host every value below may go to. */
const HOST = 'api.example.com';
const ONLY_HOST = { hosts: [HOST] } as const;

/** What the HTTP clients build for a request to `host`. */
function toward(host: string): RevealContext {
  return { name: `POST https://${host}/`, tags: { sink: 'http', host } };
}

function boundValue(label = 'canary'): SensitiveString<'sensitive'> {
  return new SensitiveString(CANARY, 'sensitive', label, { destinations: ONLY_HOST });
}

/**
 * Every operation that hands plaintext out of the library, named so a new one
 * that forgets the gate fails here rather than shipping as a bypass. `equals`
 * is deliberately absent and has its own case below: a comparison sends the
 * value nowhere.
 */
const EXPOSING_OPERATIONS: readonly [string, (value: SensitiveString<'sensitive'>) => unknown][] = [
  ['reveal', (v) => v.reveal()],
  ['revealBytes', (v) => v.revealBytes()],
  ['mask', (v) => v.mask({ showLast: 2 })],
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
  ['startsWith', (v) => v.startsWith('D')],
  ['endsWith', (v) => v.endsWith('a')],
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
  ['template literal', (v) => st`prefix ${v}`],
  ['toWorkerPayload', (v) => toWorkerPayload({ v })],
];

/**
 * Every operation that produces a new protected value from an existing one. A
 * derivation that dropped the binding would hand back a copy that may be sent
 * anywhere the value it came from may not.
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

describe('destination binding security', () => {
  beforeEach(() => {
    resetPolicies();
    resetEnvironmentInfo();
    vi.spyOn(console, 'warn').mockImplementation(() => undefined);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    resetEnvironmentInfo();
  });

  describe('the gate', () => {
    it('refuses every exposing operation under a context that names another host', () => {
      for (const [name, operation] of EXPOSING_OPERATIONS) {
        const value = boundValue();

        let thrown: unknown;
        try {
          withRevealContext(toward('elsewhere.example.com'), () => operation(value));
          expect.unreachable(`${name} must refuse a value bound to another host`);
        } catch (error) {
          thrown = error;
        }

        expect(thrown, name).toBeInstanceOf(DestinationRestrictedError);
        expect(String(thrown), name).not.toContain(CANARY);
        expect((thrown as Error).stack ?? '', name).not.toContain(CANARY);
        expect(util.inspect(thrown), name).not.toContain(CANARY);
      }
    });

    it('refuses every exposing operation under a context that names no destination', () => {
      for (const [name, operation] of EXPOSING_OPERATIONS) {
        const value = boundValue();

        let thrown: unknown;
        try {
          withRevealContext({ name: 'named but silent', reason: 'still refused' }, () =>
            operation(value)
          );
          expect.unreachable(`${name} must refuse under a context that states no host`);
        } catch (error) {
          thrown = error;
        }

        expect(thrown, name).toBeInstanceOf(DestinationRestrictedError);
        expect(String(thrown), name).not.toContain(CANARY);
      }
    });

    it('allows every exposing operation toward the bound host', () => {
      for (const [name, operation] of EXPOSING_OPERATIONS) {
        const value = boundValue();

        expect(() => withRevealContext(toward(HOST), () => operation(value)), name).not.toThrow();
      }
    });

    it('does not check a comparison, which sends the value nowhere', () => {
      const value = new SensitiveString(CANARY, 'credential', 'token', {
        destinations: ONLY_HOST,
      });
      const open = new SensitiveString(CANARY, 'credential', 'other');

      // Both operand positions, with no context at all. A bound credential
      // must still be able to answer whether a candidate matches it, because
      // comparison is the operation the library wants used in place of reveal
      // and nothing leaves the process by asking.
      expect(value.equals(CANARY)).toBe(true);
      expect(open.equals(value)).toBe(true);
      expect(value.equals('wrong')).toBe(false);
    });

    it('keeps redaction and metadata working on a value it refuses', () => {
      const value = boundValue('registry_password');

      expect(String(value)).not.toContain(CANARY);
      expect(JSON.stringify({ value })).not.toContain(CANARY);
      expect(util.inspect(value)).not.toContain(CANARY);
      expect(safeStringify({ value })).not.toContain(CANARY);
      expect(value.length).toBe(CANARY.length);
      expect(value.klass).toBe('sensitive');
      expect(value.label).toBe('registry_password');
    });

    it('denies before the policy hook and the audit hook run, and charges nothing', () => {
      const records: RevealDetails[] = [];
      const value = new SensitiveString(CANARY, 'sensitive', 'canary', {
        destinations: ONLY_HOST,
        maxReveals: 1,
      });

      expect(() =>
        value.reveal({
          name: 'audited',
          tags: { sink: 'http', host: 'elsewhere.example.com' },
          auditReveal: (_v, details) => records.push(details),
        })
      ).toThrow(DestinationRestrictedError);

      expect(records).toEqual([]);
      expect(value.revealCount).toBe(0);
      expect(value.revealsRemaining).toBe(1);
    });

    it('cannot be lifted by catching the refusal and asking again', () => {
      const value = boundValue();

      for (let attempt = 0; attempt < 5; attempt += 1) {
        try {
          value.reveal(toward('elsewhere.example.com'));
          expect.unreachable('the refusal must not soften on a retry');
        } catch (error) {
          expect(error).toBeInstanceOf(DestinationRestrictedError);
        }
      }

      expect(value.revealCount).toBe(0);
    });

    it('cannot be lifted by a subclass or by shadowing on the instance', () => {
      class Forged extends SensitiveString<'sensitive'> {
        override reveal(): string {
          return super.reveal();
        }
      }

      const forged = new Forged(CANARY, 'sensitive', 'canary', { destinations: ONLY_HOST });
      expect(() => forged.reveal()).toThrow(DestinationRestrictedError);

      const value = boundValue();
      Object.defineProperty(value, 'label', { value: 'relabelled' });
      expect(() => value.reveal()).toThrow(DestinationRestrictedError);
    });

    it('cannot be lifted by a lookalike host in either direction', () => {
      const value = new SensitiveString(CANARY, 'credential', 'registry', {
        destinations: { hosts: ['registry-1.docker.io'] },
      });

      // The two spellings the corpus measured passing a substring comparison:
      // the real host as a prefix of an attacker's, and as a suffix of one.
      for (const host of [
        'registry-1.docker.io.attacker.net',
        'attacker-registry-1.docker.io',
        'registry-1.docker.io:8443',
        'xregistry-1.docker.io',
      ]) {
        expect(() => value.reveal(toward(host)), host).toThrow(DestinationRestrictedError);
      }
    });
  });

  describe('derived values', () => {
    it('gives every derivation the binding of the value it came from', () => {
      for (const [name, derive] of DERIVING_OPERATIONS) {
        const value = boundValue();
        const children = withRevealContext(toward(HOST), () => derive(value));

        expect(children.length, name).toBeGreaterThan(0);

        for (const child of children) {
          let thrown: unknown;
          try {
            child.reveal(toward('elsewhere.example.com'));
            expect.unreachable(`${name} must hand back a bound value`);
          } catch (error) {
            thrown = error;
          }

          expect(thrown, name).toBeInstanceOf(DestinationRestrictedError);
          expect(String(thrown), name).not.toContain(CANARY);
        }
      }
    });

    it('combines the bindings of both parents of a concatenation', () => {
      const hostBound = new SensitiveString(CANARY, 'sensitive', 'host', {
        destinations: { hosts: [HOST] },
      });
      const sinkBound = new SensitiveString('other', 'sensitive', 'sink', {
        destinations: { sinks: ['http'] },
      });

      const combined = withRevealContext(toward(HOST), () => hostBound.concat(sinkBound));
      expect(combined.reveal(toward(HOST))).toBe(`${CANARY}other`);

      // Each parent's binding still refuses on its own, so the result is at
      // least as bound as either of them.
      expect(() => combined.reveal(toward('elsewhere.example.com'))).toThrow(
        DestinationRestrictedError
      );
      expect(() => combined.reveal({ name: 'x', tags: { sink: 'prisma', host: HOST } })).toThrow(
        DestinationRestrictedError
      );
    });

    it('carries a binding into a template literal built from two values', () => {
      const boundPart = boundValue('bound');
      const open = new SensitiveString('other', 'sensitive', 'open');
      const combined = withRevealContext(toward(HOST), () => st`${open} and ${boundPart}`);

      expect(() => combined.reveal()).toThrow(DestinationRestrictedError);
      expect(combined.reveal(toward(HOST))).toBe(`other and ${CANARY}`);
    });
  });

  describe('alongside the other gates', () => {
    it('reports the revocation first, since a revoked value must never look retryable', () => {
      const value = boundValue('revoked_bound');
      revokeByLabel('revoked_bound', 'rotated');

      expect(() => value.reveal()).toThrow(RevokedSensitiveValueError);
    });

    it('reports the deadline before the binding', () => {
      const value = new SensitiveString(CANARY, 'sensitive', 'canary', {
        destinations: ONLY_HOST,
        ttl: 0,
      });

      expect(() => value.reveal()).toThrow(ExpiredSensitiveValueError);
    });

    it('reports the environment restriction before the binding', () => {
      setEnvironmentInfo({ environment: 'production', region: 'us-east-1' });
      const value = new SensitiveString(CANARY, 'sensitive', 'canary', {
        destinations: ONLY_HOST,
        restrictions: { allowedRegions: ['eu-*'] },
      });

      expect(() => value.reveal()).toThrow(EnvironmentRestrictedError);
    });

    it('refuses before a reveal budget is spent, so a wrong host costs nothing', () => {
      const value = new SensitiveString(CANARY, 'sensitive', 'canary', {
        destinations: ONLY_HOST,
        maxReveals: 1,
      });

      expect(() => value.reveal(toward('elsewhere.example.com'))).toThrow(
        DestinationRestrictedError
      );
      expect(value.revealsRemaining).toBe(1);

      expect(value.reveal(toward(HOST))).toBe(CANARY);
      expect(value.revealsRemaining).toBe(0);
      expect(() => value.reveal(toward(HOST))).toThrow(RevealLimitExceededError);
    });
  });

  describe('the wire format', () => {
    it('carries the binding to the other side, and serializing is itself a bound reveal', () => {
      const value = new SensitiveString(CANARY, 'credential', 'registry', {
        destinations: { sinks: ['http'], hosts: ['*.example.com'] },
      });

      expect(() => value.serialize()).toThrow(DestinationRestrictedError);

      const wire = value.serialize(toward('api.example.com'));
      expect(wire.destinations).toEqual([{ sinks: ['http'], hosts: ['*.example.com'] }]);
      expect(JSON.stringify(wire)).toContain(CANARY);

      const rebuilt = SensitiveString.deserialize<'credential'>(wire);
      expect(() => rebuilt.reveal()).toThrow(DestinationRestrictedError);
      expect(() => rebuilt.reveal(toward('api.other.net'))).toThrow(DestinationRestrictedError);
      expect(rebuilt.reveal(toward('api.example.com'))).toBe(CANARY);
    });

    it('carries every binding of a value derived from two bound values', () => {
      const combined = withRevealContext(toward(HOST), () =>
        new SensitiveString(CANARY, 'sensitive', 'host', {
          destinations: { hosts: [HOST] },
        }).concat(
          new SensitiveString('other', 'sensitive', 'sink', { destinations: { sinks: ['http'] } })
        )
      );

      const wire = combined.serialize(toward(HOST));
      expect(wire.destinations).toHaveLength(2);

      const rebuilt = SensitiveString.deserialize<'sensitive'>(wire);
      expect(() => rebuilt.reveal({ name: 'x', tags: { sink: 'prisma', host: HOST } })).toThrow(
        DestinationRestrictedError
      );
      expect(rebuilt.reveal(toward(HOST))).toBe(`${CANARY}other`);
    });

    it('rejects a payload binding with a key this receiver does not know', () => {
      const wire = {
        __sensitive: true as const,
        klass: 'sensitive' as const,
        value: CANARY,
        destinations: [{ hosts: [HOST], regions: ['eu-*'] }],
      };

      expect(() => SensitiveString.deserialize(wire)).toThrow(/unknown key 'regions'/);
    });

    it('rejects a payload binding the constructor would have refused', () => {
      for (const destinations of [[], [{}], [{ hosts: [] }], [{ hosts: ['https://x'] }], 'x']) {
        const wire = {
          __sensitive: true as const,
          klass: 'sensitive' as const,
          value: CANARY,
          destinations,
        };

        expect(() => SensitiveString.deserialize(wire), JSON.stringify(destinations)).toThrow();
      }
    });

    it('lets a payload only tighten: a rebuilt value with no field may go anywhere it could before', () => {
      const wire = { __sensitive: true as const, klass: 'sensitive' as const, value: CANARY };
      const rebuilt = SensitiveString.deserialize<'sensitive'>(wire);

      expect(rebuilt.reveal()).toBe(CANARY);
      expect(rebuilt.serialize().destinations).toBeUndefined();
    });
  });

  describe('the worker handoff', () => {
    it('crosses with the value, and the handoff is itself a bound reveal', () => {
      const value = boundValue('handed');

      expect(() => toWorkerPayload({ value })).toThrow(DestinationRestrictedError);

      const payload = toWorkerPayload({ value }, { context: toward(HOST) });
      const rebuilt = fromWorkerPayload<{ value: SensitiveString<'sensitive'> }>(
        structuredClone(payload),
        { allowUnaudited: true }
      );

      expect(() => rebuilt.values.value.reveal()).toThrow(DestinationRestrictedError);
      expect(rebuilt.values.value.reveal(toward(HOST))).toBe(CANARY);
    });
  });
});
