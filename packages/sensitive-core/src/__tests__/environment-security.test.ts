/**
 * Environment restrictions, driven through the same two tables the TTL,
 * reveal-budget and revocation suites use: every operation that reaches the raw
 * value, and every operation that derives a new protected value from one.
 *
 * A restriction that lives only in `reveal()` is walked past by
 * `secret.map(v => v).reveal()`, and one a derivation drops hands back an
 * unrestricted copy of a value that was meant to stay in one region. Both are
 * failures this file is here to catch before they ship.
 */
import * as util from 'node:util';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  EnvironmentRestrictedError,
  ExpiredSensitiveValueError,
  lockEnvironmentInfo,
  RenewalNotAllowedError,
  RevealLimitExceededError,
  resetEnvironmentInfo,
  resetPolicies,
  revokeByLabel,
  RevokedSensitiveValueError,
  safeStringify,
  SensitiveString,
  setEnvironmentInfo,
  st,
  toWorkerPayload,
  UnserializableRestrictionError,
  UnshareableConstraintError,
  withRevealContext,
} from '../index.js';
import type { RevealContext, RevealDetails, SensitivityClass } from '../index.js';

const CANARY = 'ENVIRONMENT_SECURITY_CANARY_7a1d';

/** An HMAC key long enough to clear the 16-byte floor. */
const HMAC_KEY = 'k'.repeat(32);

/** EU-only, which is the restriction every case below is refused by. */
const EU_ONLY = { allowedRegions: ['eu-*'] } as const;

function euOnly(label = 'canary'): SensitiveString<'sensitive'> {
  return new SensitiveString(CANARY, 'sensitive', label, { restrictions: EU_ONLY });
}

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
    ['startsWith', (v) => v.startsWith('E')],
    ['endsWith', (v) => v.endsWith('d')],
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
  ];

/**
 * Every operation that produces a new protected value from an existing one. A
 * derivation that dropped the restriction would hand back a copy readable in a
 * region the value it came from is not.
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

/** Where the restricted values below may be read. */
function inEurope(): void {
  resetEnvironmentInfo();
  setEnvironmentInfo({ environment: 'production', region: 'eu-west-1' });
}

/** Where they may not. */
function inAmerica(): void {
  resetEnvironmentInfo();
  setEnvironmentInfo({ environment: 'production', region: 'us-east-1' });
}

describe('environment restriction security', () => {
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
    it('refuses every operation that reaches the raw value, and leaks nothing doing it', () => {
      for (const [name, operation] of RAW_VALUE_OPERATIONS) {
        inEurope();
        const value = euOnly();
        inAmerica();

        let thrown: unknown;
        try {
          operation(value);
          expect.unreachable(`${name} must refuse a value this region may not read`);
        } catch (error) {
          thrown = error;
        }

        expect(thrown, name).toBeInstanceOf(EnvironmentRestrictedError);
        expect(String(thrown), name).not.toContain(CANARY);
        expect((thrown as Error).stack ?? '', name).not.toContain(CANARY);
        expect(util.inspect(thrown), name).not.toContain(CANARY);
      }
    });

    it('refuses even inside an authorized context', () => {
      inAmerica();
      const value = new SensitiveString(CANARY, 'credential', 'token', { restrictions: EU_ONLY });

      withRevealContext({ name: 'authorized', reason: 'still not allowed' }, () => {
        expect(() => value.reveal()).toThrow(EnvironmentRestrictedError);
      });

      expect(() => value.reveal({ name: 'explicit', reason: 'still not allowed' })).toThrow(
        EnvironmentRestrictedError
      );
    });

    it('refuses a comparison in both operand positions', () => {
      inAmerica();
      const restricted = new SensitiveString(CANARY, 'credential', 'token', {
        restrictions: EU_ONLY,
      });
      const open = new SensitiveString(CANARY, 'credential', 'other');

      // Rule R2 names `equals()` a read. A credential that may not be used in
      // this region must not still answer whether a guess matches it here.
      expect(() => restricted.equals(CANARY)).toThrow(EnvironmentRestrictedError);
      expect(() => open.equals(restricted)).toThrow(EnvironmentRestrictedError);
    });

    it('keeps redaction and metadata working on a value it refuses', () => {
      inAmerica();
      const value = euOnly('eu_pii');

      // A value that cannot be used still has to be safe to log, which is the
      // one thing the gate must never refuse.
      expect(String(value)).not.toContain(CANARY);
      expect(JSON.stringify({ value })).not.toContain(CANARY);
      expect(util.inspect(value)).not.toContain(CANARY);
      expect(safeStringify({ value })).not.toContain(CANARY);
      expect(value.length).toBe(CANARY.length);
      expect(value.klass).toBe('sensitive');
      expect(value.label).toBe('eu_pii');
    });

    it('denies before the policy hook and the audit hook run', () => {
      inAmerica();
      const records: RevealDetails[] = [];
      const checked: (RevealContext | null)[] = [];

      const value = new SensitiveString(CANARY, 'sensitive', 'canary', {
        restrictions: EU_ONLY,
      });

      expect(() =>
        value.reveal({
          name: 'audited',
          auditReveal: (_v, details) => records.push(details),
        })
      ).toThrow(EnvironmentRestrictedError);

      expect(records).toEqual([]);
      expect(checked).toEqual([]);
      expect(value.revealCount).toBe(0);
    });

    it('is evaluated at read time, not at construction', () => {
      inEurope();
      const value = euOnly();

      expect(value.reveal()).toBe(CANARY);

      inAmerica();
      expect(() => value.reveal()).toThrow(EnvironmentRestrictedError);

      inEurope();
      expect(value.reveal()).toBe(CANARY);
    });

    it('cannot be lifted by catching the refusal and asking again', () => {
      inAmerica();
      const value = euOnly();

      for (let attempt = 0; attempt < 5; attempt += 1) {
        try {
          value.reveal();
          expect.unreachable('the refusal must not soften on a retry');
        } catch (error) {
          expect(error).toBeInstanceOf(EnvironmentRestrictedError);
        }
      }

      expect(value.revealCount).toBe(0);
    });

    it('cannot be lifted by a subclass or by shadowing on the instance', () => {
      inAmerica();

      class Forged extends SensitiveString<'sensitive'> {
        override reveal(): string {
          return super.reveal();
        }
      }

      const forged = new Forged(CANARY, 'sensitive', 'canary', { restrictions: EU_ONLY });
      expect(() => forged.reveal()).toThrow(EnvironmentRestrictedError);

      const value = euOnly();
      Object.defineProperty(value, 'label', { value: 'relabelled' });
      expect(() => value.reveal()).toThrow(EnvironmentRestrictedError);
    });

    it('cannot be lifted by moving the environment once it is locked', () => {
      inAmerica();
      lockEnvironmentInfo();

      const value = euOnly();

      expect(() => setEnvironmentInfo({ environment: 'production', region: 'eu-west-1' })).toThrow(
        Error
      );
      expect(() => value.reveal()).toThrow(EnvironmentRestrictedError);
    });
  });

  describe('derived values', () => {
    it('gives every derivation the restriction of the value it came from', () => {
      for (const [name, derive] of DERIVING_OPERATIONS) {
        inEurope();
        const value = euOnly();
        const children = derive(value);

        expect(children.length, name).toBeGreaterThan(0);

        inAmerica();

        for (const child of children) {
          let thrown: unknown;
          try {
            child.reveal();
            expect.unreachable(`${name} must hand back a restricted value`);
          } catch (error) {
            thrown = error;
          }

          expect(thrown, name).toBeInstanceOf(EnvironmentRestrictedError);
          expect(String(thrown), name).not.toContain(CANARY);
        }
      }
    });

    it('combines the restrictions of both parents of a concatenation', () => {
      resetEnvironmentInfo();
      setEnvironmentInfo({ environment: 'production', region: 'eu-west-1', datacenter: 'dc-1' });

      const euValue = new SensitiveString(CANARY, 'sensitive', 'eu', {
        restrictions: { allowedRegions: ['eu-*'] },
      });
      const dcValue = new SensitiveString('other', 'sensitive', 'dc', {
        restrictions: { allowedDatacenters: ['dc-1'] },
      });

      const combined = euValue.concat(dcValue);
      expect(combined.reveal()).toBe(`${CANARY}other`);

      // Each parent's restriction still refuses on its own, so the result is at
      // least as restricted as either of them, which is rule R2's combination
      // rule with nothing left to decide.
      resetEnvironmentInfo();
      setEnvironmentInfo({ environment: 'production', region: 'us-east-1', datacenter: 'dc-1' });
      expect(() => combined.reveal()).toThrow(EnvironmentRestrictedError);

      resetEnvironmentInfo();
      setEnvironmentInfo({ environment: 'production', region: 'eu-west-1', datacenter: 'dc-9' });
      expect(() => combined.reveal()).toThrow(EnvironmentRestrictedError);
    });

    it('carries a restriction into a template literal built from two values', () => {
      inEurope();
      const euValue = euOnly('eu');
      const open = new SensitiveString('other', 'sensitive', 'open');
      const combined = st`${open} and ${euValue}`;

      inAmerica();
      expect(() => combined.reveal()).toThrow(EnvironmentRestrictedError);
    });
  });

  describe('alongside the other gates', () => {
    it('reports the revocation first, since a revoked value must never look retryable', () => {
      inAmerica();
      const value = euOnly('revoked_eu_pii');
      revokeByLabel('revoked_eu_pii', 'rotated');

      expect(() => value.reveal()).toThrow(RevokedSensitiveValueError);
    });

    it('reports the deadline before the restriction', () => {
      inAmerica();
      const value = new SensitiveString(CANARY, 'sensitive', 'canary', {
        restrictions: EU_ONLY,
        ttl: 0,
      });

      expect(() => value.reveal()).toThrow(ExpiredSensitiveValueError);
    });

    it('refuses before a reveal budget is spent, so a wrong region costs nothing', () => {
      inEurope();
      const value = new SensitiveString(CANARY, 'sensitive', 'canary', {
        restrictions: EU_ONLY,
        maxReveals: 1,
      });

      inAmerica();
      expect(() => value.reveal()).toThrow(EnvironmentRestrictedError);
      expect(value.revealsRemaining).toBe(1);

      inEurope();
      expect(value.reveal()).toBe(CANARY);
      expect(value.revealsRemaining).toBe(0);
      expect(() => value.reveal()).toThrow(RevealLimitExceededError);
    });
  });

  describe('renew()', () => {
    it('refuses in an environment that may not read the value', () => {
      inEurope();
      const value = new SensitiveString(CANARY, 'sensitive', 'eu_pii', {
        restrictions: EU_ONLY,
        ttl: 60_000,
        allowRenewal: true,
      });
      const deadline = value.expiresAt?.getTime();

      inAmerica();

      // Renewal reads nothing, so it does not go through the gate and needs its
      // own check, exactly as revocation does. Without it a process the value
      // forbids keeps extending the life of a value it may not read.
      expect(() => value.renew(60_000)).toThrow(EnvironmentRestrictedError);
      expect(value.expiresAt?.getTime()).toBe(deadline);

      inEurope();
      value.renew(60_000);
      expect(value.expiresAt?.getTime()).toBeGreaterThan(deadline!);
    });

    it('still reports the revocation first, and a derived value first of all', () => {
      inAmerica();

      const revoked = new SensitiveString(CANARY, 'sensitive', 'revoked_eu', {
        restrictions: EU_ONLY,
        ttl: 60_000,
        allowRenewal: true,
      });
      revokeByLabel('revoked_eu', 'rotated');
      expect(() => revoked.renew(60_000)).toThrow(RevokedSensitiveValueError);

      // Derived where the value may be read, so the substring itself is not
      // what refuses; the derived check runs ahead of everything either way.
      inEurope();
      const derived = new SensitiveString(CANARY, 'sensitive', 'eu', {
        restrictions: EU_ONLY,
        ttl: 60_000,
        allowRenewal: true,
      }).substring(0, 4);

      inAmerica();
      expect(() => derived.renew(60_000)).toThrow(RenewalNotAllowedError);
    });
  });

  describe('the wire format', () => {
    it('carries declarative restrictions to the other side', () => {
      inEurope();
      const value = new SensitiveString(CANARY, 'sensitive', 'eu_pii', {
        restrictions: { allowedRegions: ['eu-*'], deniedEnvironments: ['development'] },
      });

      const wire = value.serialize();
      expect(wire.restrictions).toEqual([
        { allowedRegions: ['eu-*'], deniedEnvironments: ['development'] },
      ]);

      const rebuilt = SensitiveString.deserialize<'sensitive'>(wire);
      expect(rebuilt.reveal()).toBe(CANARY);

      inAmerica();
      expect(() => rebuilt.reveal()).toThrow(EnvironmentRestrictedError);
    });

    it('carries every restriction of a value derived from two restricted values', () => {
      resetEnvironmentInfo();
      setEnvironmentInfo({ environment: 'production', region: 'eu-west-1', datacenter: 'dc-1' });

      const combined = new SensitiveString(CANARY, 'sensitive', 'eu', {
        restrictions: { allowedRegions: ['eu-*'] },
      }).concat(
        new SensitiveString('other', 'sensitive', 'dc', {
          restrictions: { allowedDatacenters: ['dc-1'] },
        })
      );

      const wire = combined.serialize();
      expect(wire.restrictions).toHaveLength(2);

      const rebuilt = SensitiveString.deserialize<'sensitive'>(wire);

      resetEnvironmentInfo();
      setEnvironmentInfo({ environment: 'production', region: 'eu-west-1', datacenter: 'dc-9' });
      expect(() => rebuilt.reveal()).toThrow(EnvironmentRestrictedError);
    });

    it('refuses to serialize a value whose restriction is a function', () => {
      inEurope();
      const value = new SensitiveString(CANARY, 'sensitive', 'eu_pii', {
        restrictions: { custom: () => true },
      });

      let thrown: unknown;
      try {
        value.serialize();
        expect.unreachable('a custom restriction has no wire form');
      } catch (error) {
        thrown = error;
      }

      // Its own class, not an EnvironmentRestrictedError. That one means "not
      // here, try where the value allows"; this one means "not anywhere", and a
      // caller who cannot tell them apart retries in every region forever.
      expect(thrown).toBeInstanceOf(UnserializableRestrictionError);
      expect(thrown).not.toBeInstanceOf(EnvironmentRestrictedError);
      expect(String(thrown)).toContain('no wire form');
      expect(String(thrown)).not.toContain(CANARY);
      // Refused before the read, so nothing was revealed or counted.
      expect(value.revealCount).toBe(0);
    });

    it('refuses a worker handoff of a value whose restriction is a function', () => {
      inEurope();
      const value = new SensitiveString(CANARY, 'sensitive', 'eu_pii', {
        restrictions: { custom: () => true },
      });

      let thrown: unknown;
      try {
        toWorkerPayload({ token: value });
        expect.unreachable('a custom restriction cannot cross an isolate');
      } catch (error) {
        thrown = error;
      }

      expect(thrown).toBeInstanceOf(UnshareableConstraintError);
      expect((thrown as UnshareableConstraintError).constraints).toContain('restrictions');
      expect(String(thrown)).not.toContain(CANARY);
      expect(value.revealCount).toBe(0);
    });

    it('accepts restrictions from a payload, which can only tighten', () => {
      inAmerica();

      const rebuilt = SensitiveString.deserialize<'sensitive'>({
        __sensitive: true,
        klass: 'sensitive',
        value: CANARY,
        label: 'eu_pii',
        restrictions: [{ allowedRegions: ['eu-*'] }],
      });

      expect(() => rebuilt.reveal()).toThrow(EnvironmentRestrictedError);
    });

    it('rejects a restriction entry it cannot enforce rather than ignoring it', () => {
      const payload = {
        __sensitive: true as const,
        klass: 'sensitive' as const,
        value: CANARY,
        restrictions: [{ allowedContinents: ['europe'] }],
      };

      let thrown: unknown;
      try {
        SensitiveString.deserialize(payload);
        expect.unreachable('an unknown restriction key must be refused');
      } catch (error) {
        thrown = error;
      }

      expect(String(thrown)).toContain('allowedContinents');
      expect(String(thrown)).not.toContain(CANARY);
    });

    it('rejects a malformed restrictions field', () => {
      const payload = (restrictions: unknown): unknown => ({
        __sensitive: true,
        klass: 'sensitive',
        value: CANARY,
        restrictions,
      });

      expect(() => SensitiveString.deserialize(payload('eu-*'))).toThrow(/must be an array/);
      expect(() => SensitiveString.deserialize(payload([]))).toThrow(/empty/);
      expect(() => SensitiveString.deserialize(payload([null]))).toThrow(/must be an object/);
      // The lists themselves get the constructor's own validation, so a payload
      // cannot smuggle a pattern shape a local caller would have been refused.
      expect(() =>
        SensitiveString.deserialize(payload([{ allowedRegions: ['*-east-1'] }]))
      ).toThrow(RangeError);
      expect(() => SensitiveString.deserialize(payload([{ allowedRegions: [] }]))).toThrow(
        RangeError
      );
    });
  });
});
