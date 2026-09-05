import * as util from 'node:util';
import { runInNewContext } from 'node:vm';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  pruneRevocations,
  registerPolicy,
  resetPolicies,
  revocationCount,
  RevocationList,
  revokeByLabel,
  revokeByPattern,
  RevokedSensitiveValueError,
  SensitiveString,
  withRevealContext,
} from './index.js';
import type { RevealDetails, RevocationRegistry, RevokeAuditDetails } from './index.js';

const VALUE = 'value-under-test';

/**
 * Drop everything the process-global lists hold.
 *
 * `pruneRevocations` is the only way to shrink them, which is deliberate, so it
 * is also how a test isolates itself. Entries recorded strictly before the
 * cutoff go, and every entry a test wrote is older than one millisecond from
 * now.
 */
function clearGlobalRevocations(): void {
  pruneRevocations(Date.now() + 1);
}

describe('revocation', () => {
  beforeEach(() => {
    resetPolicies();
    clearGlobalRevocations();
  });

  afterEach(() => {
    clearGlobalRevocations();
  });

  describe('an instance', () => {
    it('refuses to be read once revoked', () => {
      const secret = new SensitiveString(VALUE, 'credential', 'api_key');

      expect(secret.reveal()).toBe(VALUE);

      secret.revoke('Rotated 2026-08-01');

      expect(secret.isRevoked).toBe(true);
      expect(secret.revocationReason).toBe('Rotated 2026-08-01');
      expect(() => secret.reveal()).toThrow(RevokedSensitiveValueError);
    });

    it('reports when it was revoked', () => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date('2026-08-01T12:00:00.000Z'));

      try {
        const secret = new SensitiveString(VALUE, 'sensitive', 'note');
        secret.revoke('rotated');

        expect(secret.revokedAt).toEqual(new Date('2026-08-01T12:00:00.000Z'));
      } finally {
        vi.useRealTimers();
      }
    });

    it('reports nothing before it is revoked', () => {
      const secret = new SensitiveString(VALUE, 'sensitive', 'note');

      expect(secret.isRevoked).toBe(false);
      expect(secret.revocationReason).toBeUndefined();
      expect(secret.revokedAt).toBeUndefined();
    });

    it('can be revoked without a label', () => {
      const secret = new SensitiveString(VALUE, 'credential');

      secret.revoke('no label needed');

      expect(secret.isRevoked).toBe(true);
      expect(() => secret.reveal()).toThrow(RevokedSensitiveValueError);
    });

    it('keeps the first reason when revoked twice', () => {
      const secret = new SensitiveString(VALUE, 'credential', 'api_key');

      secret.revoke('first');
      expect(() => secret.revoke('second')).not.toThrow();

      expect(secret.revocationReason).toBe('first');
    });

    it('accepts an empty reason and refuses a reason that is not a string', () => {
      const empty = new SensitiveString(VALUE, 'sensitive', 'empty');
      empty.revoke('');
      expect(empty.isRevoked).toBe(true);
      expect(empty.revocationReason).toBe('');

      const secret = new SensitiveString(VALUE, 'sensitive', 'typed');
      expect(() => (secret as { revoke(reason: unknown): void }).revoke(42)).toThrow(TypeError);
      expect(secret.isRevoked).toBe(false);
    });

    it('keeps a very long reason intact', () => {
      const reason = 'x'.repeat(10_000);
      const secret = new SensitiveString(VALUE, 'sensitive', 'long');

      secret.revoke(reason);

      expect(secret.revocationReason).toBe(reason);
      expect(() => secret.reveal()).toThrow(reason);
    });
  });

  describe('the process-global lists', () => {
    it('revokes every value constructed under a label', () => {
      const first = new SensitiveString(VALUE, 'credential', 'api_key');
      const second = new SensitiveString('other', 'credential', 'api_key');
      const untouched = new SensitiveString('other', 'credential', 'session');

      revokeByLabel('api_key', 'Emergency rotation');

      expect(first.isRevoked).toBe(true);
      expect(second.isRevoked).toBe(true);
      expect(second.revocationReason).toBe('Emergency rotation');
      expect(untouched.isRevoked).toBe(false);
      expect(untouched.reveal()).toBe('other');
    });

    it('revokes a value constructed after the label was revoked', () => {
      revokeByLabel('api_key', 'Emergency rotation');

      const late = new SensitiveString(VALUE, 'credential', 'api_key');

      expect(late.isRevoked).toBe(true);
      expect(() => late.reveal()).toThrow(RevokedSensitiveValueError);
    });

    it('revokes by pattern and leaves non-matching labels alone', () => {
      const session = new SensitiveString(VALUE, 'sensitive', 'session_abc');
      const other = new SensitiveString(VALUE, 'sensitive', 'api_key');

      revokeByPattern(/^session_/, 'User logged out');

      expect(session.isRevoked).toBe(true);
      expect(session.revocationReason).toBe('User logged out');
      expect(other.isRevoked).toBe(false);
    });

    it('treats a pattern as a pattern, not as a literal', () => {
      const literal = new SensitiveString(VALUE, 'sensitive', 'a.c');
      const matched = new SensitiveString(VALUE, 'sensitive', 'abc');

      revokeByPattern(/^a\.c$/, 'escaped dot');

      expect(literal.isRevoked).toBe(true);
      expect(matched.isRevoked).toBe(false);
    });

    it('keeps the first reason for a label revoked twice', () => {
      revokeByLabel('api_key', 'first');
      revokeByLabel('api_key', 'second');

      expect(new SensitiveString(VALUE, 'credential', 'api_key').revocationReason).toBe('first');
    });

    it('answers the same way however often a stateful pattern is consulted', () => {
      revokeByPattern(/session_[a-z]+/g, 'a global pattern');

      for (let attempt = 0; attempt < 5; attempt++) {
        expect(new SensitiveString(VALUE, 'sensitive', 'session_abc').isRevoked).toBe(true);
      }
    });

    it('is not moved by mutating the RegExp that set it', () => {
      const pattern = /^session_/;
      revokeByPattern(pattern, 'User logged out');

      pattern.lastIndex = 500;

      expect(new SensitiveString(VALUE, 'sensitive', 'session_abc').isRevoked).toBe(true);
    });

    it('accepts a pattern from another realm', () => {
      const foreign = runInNewContext('/^session_/') as RegExp;

      revokeByPattern(foreign, 'from another realm');

      expect(new SensitiveString(VALUE, 'sensitive', 'session_abc').isRevoked).toBe(true);
    });

    it('rejects a pattern that nests quantifiers', () => {
      expect(() => revokeByPattern(/^(a+)+$/, 'catastrophic')).toThrow(TypeError);
      expect(() => revokeByPattern(/^(a|a)*$/, 'catastrophic')).toThrow(TypeError);
      expect(() => revokeByPattern(/^(?:\w+\s?)*$/, 'catastrophic')).toThrow(/nested quantifier/);

      expect(revocationCount().patterns).toBe(0);
    });

    it('accepts the patterns a revocation actually needs', () => {
      expect(() => revokeByPattern(/^session:[0-9]+$/, 'ok')).not.toThrow();
      expect(() => revokeByPattern(/^(user|admin):\d+$/, 'ok')).not.toThrow();
      expect(() => revokeByPattern(/^(?<kind>token|session)_[a-z]+$/, 'ok')).not.toThrow();
      expect(() => revokeByPattern(/^api_key:.*$/, 'ok')).not.toThrow();
    });

    it('rejects arguments it cannot use', () => {
      expect(() => revokeByLabel('', 'empty label')).toThrow(RangeError);
      expect(() => (revokeByLabel as (l: unknown, r: string) => void)(7, 'number')).toThrow(
        TypeError
      );
      expect(() => (revokeByLabel as (l: string, r: unknown) => void)('x', 7)).toThrow(TypeError);
      expect(() => (revokeByPattern as (p: unknown, r: string) => void)('x', 'string')).toThrow(
        TypeError
      );
    });

    it('is reachable under the Symbol.for key a second copy of core would use', () => {
      revokeByLabel('api_key', 'shared');

      const key = Symbol.for('@platform-sec/sensitive-string-core/revocations');
      const shared = (globalThis as unknown as Record<symbol, { labels: Map<string, unknown> }>)[
        key
      ];

      // A second physical installation calls getGlobalSingleton with this same
      // key and receives this same object, so a revocation in either copy is
      // seen by values built by the other.
      expect(shared?.labels.has('api_key')).toBe(true);
    });
  });

  describe('pruning', () => {
    it('drops entries older than the cutoff and reports how many', () => {
      revokeByLabel('api_key', 'old');
      revokeByPattern(/^session_/, 'old');

      expect(revocationCount()).toEqual({ labels: 1, patterns: 1 });
      expect(pruneRevocations(Date.now() + 1)).toBe(2);
      expect(revocationCount()).toEqual({ labels: 0, patterns: 0 });
    });

    it('keeps entries newer than the cutoff', () => {
      revokeByLabel('api_key', 'recent');

      expect(pruneRevocations(Date.now() - 60_000)).toBe(0);
      expect(new SensitiveString(VALUE, 'credential', 'api_key').isRevoked).toBe(true);
    });

    it('cannot bring back a value that has already been refused', () => {
      const secret = new SensitiveString(VALUE, 'credential', 'api_key');
      revokeByLabel('api_key', 'rotation');

      expect(() => secret.reveal()).toThrow(RevokedSensitiveValueError);

      pruneRevocations(Date.now() + 1);

      // The refusal is latched onto the value the first time it is observed, so
      // shrinking the list cannot resurrect it.
      expect(secret.isRevoked).toBe(true);
      expect(() => secret.reveal()).toThrow(RevokedSensitiveValueError);
    });

    it('does bring back a value that never looked, which is why pruning has a rule', () => {
      const secret = new SensitiveString(VALUE, 'credential', 'api_key');
      revokeByLabel('api_key', 'rotation');
      pruneRevocations(Date.now() + 1);

      // Documented, not desired: prune only once nothing that could match is
      // still reachable.
      expect(secret.isRevoked).toBe(false);
    });

    it('rejects a cutoff it cannot read', () => {
      expect(() => pruneRevocations(new Date('nonsense'))).toThrow(RangeError);
      expect(() => pruneRevocations(Number.NaN)).toThrow(RangeError);
    });
  });

  describe('an external registry', () => {
    it('revokes a value whose label it holds', () => {
      const registry = new RevocationList();
      registry.revoke('api_key:user_123', 'Account suspended');

      const scoped = new SensitiveString(VALUE, 'credential', 'api_key:user_123', {
        revocationRegistry: registry,
      });
      const unscoped = new SensitiveString(VALUE, 'credential', 'api_key:user_999', {
        revocationRegistry: registry,
      });

      expect(scoped.isRevoked).toBe(true);
      expect(scoped.revocationReason).toBe('Account suspended');
      expect(unscoped.isRevoked).toBe(false);
    });

    it('is consulted on every read, so a later revocation takes effect', () => {
      const registry = new RevocationList();
      const secret = new SensitiveString(VALUE, 'credential', 'api_key:user_123', {
        revocationRegistry: registry,
      });

      expect(secret.reveal()).toBe(VALUE);

      registry.revoke('api_key:user_123', 'Account suspended');

      expect(() => secret.reveal()).toThrow(RevokedSensitiveValueError);
    });

    it('does not leak between registries or into the global lists', () => {
      const mine = new RevocationList();
      const theirs = new RevocationList();
      mine.revoke('api_key', 'mine only');

      expect(theirs.isRevoked('api_key')).toBe(false);
      expect(new SensitiveString(VALUE, 'credential', 'api_key').isRevoked).toBe(false);
    });

    it('fails closed when the store cannot be reached', () => {
      const outage = new Error('ECONNREFUSED');
      const registry: RevocationRegistry = {
        isRevoked() {
          throw outage;
        },
      };

      const secret = new SensitiveString(VALUE, 'credential', 'api_key', {
        revocationRegistry: registry,
      });

      expect(secret.isRevoked).toBe(true);

      try {
        secret.reveal();
        expect.unreachable('an unreachable registry must deny the read');
      } catch (error) {
        expect(error).toBeInstanceOf(RevokedSensitiveValueError);
        expect((error as RevokedSensitiveValueError).scope).toBe('unavailable');
        expect((error as Error).cause).toBe(outage);
      }
    });

    it('does not latch an outage, so the value works again once the store does', () => {
      let reachable = false;
      const registry: RevocationRegistry = {
        isRevoked() {
          if (!reachable) {
            throw new Error('ECONNREFUSED');
          }
          return false;
        },
      };

      const secret = new SensitiveString(VALUE, 'credential', 'api_key', {
        revocationRegistry: registry,
      });

      expect(() => secret.reveal()).toThrow(RevokedSensitiveValueError);

      reachable = true;

      expect(secret.reveal()).toBe(VALUE);
    });

    it('refuses a registry that does not answer synchronously', async () => {
      const registry = {
        isRevoked: () => Promise.resolve(false),
      } as unknown as RevocationRegistry;

      const secret = new SensitiveString(VALUE, 'credential', 'api_key', {
        revocationRegistry: registry,
      });

      // An async registry hands back a Promise, which is neither true nor
      // false. Reading it either way would silently revoke everything or
      // nothing, so the answer is refused instead.
      expect(() => secret.reveal()).toThrow(/synchronously/);
      await Promise.resolve();
    });

    it('still revokes when it cannot say why', () => {
      const registry: RevocationRegistry = {
        isRevoked: () => true,
        getReason() {
          throw new Error('reason lookup failed');
        },
      };

      const secret = new SensitiveString(VALUE, 'credential', 'api_key', {
        revocationRegistry: registry,
      });

      expect(secret.isRevoked).toBe(true);
      expect(secret.revocationReason).toBe('revoked by the registry');
    });

    it('is handed undefined for a value with no label, and decides for itself', () => {
      const asked: (string | undefined)[] = [];
      const registry: RevocationRegistry = {
        isRevoked(label) {
          asked.push(label);
          return false;
        },
      };

      new SensitiveString(VALUE, 'credential', undefined, {
        revocationRegistry: registry,
      }).reveal();

      // Consulted, not skipped. The built-in list answers false for an
      // unlabelled value; a registry that wanted to refuse one could.
      expect(asked).toEqual([undefined]);
    });

    it('rejects an option that cannot answer at all', () => {
      expect(
        () =>
          new SensitiveString(VALUE, 'credential', 'api_key', {
            revocationRegistry: {} as RevocationRegistry,
          })
      ).toThrow(TypeError);

      expect(
        () =>
          new SensitiveString(VALUE, 'credential', 'api_key', {
            revocationRegistry: 'redis' as unknown as RevocationRegistry,
          })
      ).toThrow(TypeError);
    });
  });

  describe('RevocationList', () => {
    it('answers what it holds', () => {
      const list = new RevocationList();

      expect(list.size).toBe(0);
      expect(list.isRevoked('api_key')).toBe(false);
      expect(list.isRevoked(undefined)).toBe(false);
      expect(list.getReason('api_key')).toBeUndefined();
      expect(list.revokedAt('api_key')).toBeUndefined();

      list.revoke('api_key', 'rotated');

      expect(list.size).toBe(1);
      expect(list.isRevoked('api_key')).toBe(true);
      expect(list.getReason('api_key')).toBe('rotated');
      expect(list.revokedAt('api_key')).toBeInstanceOf(Date);
    });

    it('keeps the first reason and prunes by age', () => {
      const list = new RevocationList();
      list.revoke('api_key', 'first');
      list.revoke('api_key', 'second');

      expect(list.getReason('api_key')).toBe('first');
      expect(list.prune(Date.now() - 60_000)).toBe(0);
      expect(list.prune(Date.now() + 1)).toBe(1);
      expect(list.size).toBe(0);
    });

    it('rejects arguments it cannot use', () => {
      const list = new RevocationList();

      expect(() => list.revoke('', 'empty')).toThrow(RangeError);
      expect(() => (list as { revoke(l: unknown, r: string): void }).revoke(7, 'x')).toThrow(
        TypeError
      );
    });
  });

  describe('derived values', () => {
    it('are revoked by the value they came from', () => {
      const token = new SensitiveString(VALUE, 'credential', 'api_key');
      const prefix = token.substring(0, 5);

      token.revoke('rotated');

      expect(prefix.isRevoked).toBe(true);
      expect(() => prefix.reveal()).toThrow(RevokedSensitiveValueError);
    });

    it('revoke the value they came from', () => {
      const token = new SensitiveString(VALUE, 'credential', 'api_key');
      const prefix = token.substring(0, 5);

      prefix.revoke('the derivative leaked');

      // A derivative carries its sources' material, so a leaked substring is a
      // leaked secret.
      expect(token.isRevoked).toBe(true);
      expect(token.revocationReason).toBe('the derivative leaked');
    });

    it('revoke every operand of a two-parent derivation', () => {
      const left = new SensitiveString('left', 'sensitive', 'left');
      const right = new SensitiveString('right', 'sensitive', 'right');
      const combined = left.concat(right);

      combined.revoke('combined leaked');

      expect(left.isRevoked).toBe(true);
      expect(right.isRevoked).toBe(true);
    });

    it('are revoked as soon as either operand is', () => {
      const left = new SensitiveString('left', 'sensitive', 'left');
      const right = new SensitiveString('right', 'sensitive', 'right');
      const combined = left.concat(right);

      right.revoke('one operand is enough');

      expect(combined.isRevoked).toBe(true);
      expect(left.isRevoked).toBe(false);
    });

    it('match label revocation on the label they were constructed with', () => {
      const token = new SensitiveString(VALUE, 'credential', 'api_key');
      const group = token.matchGroups(/(?<head>value)/)?.['head'];

      expect(group?.label).toBe('api_key:head');

      // The derivation's own label was never constructed under, so revoking it
      // matches nothing; revoking the source label reaches the derivative.
      revokeByLabel('api_key:head', 'no value carries this');
      expect(group?.isRevoked).toBe(false);

      revokeByLabel('api_key', 'the label a value was built with');
      expect(group?.isRevoked).toBe(true);
    });

    it('cannot be made at all from a revoked value', () => {
      const token = new SensitiveString(VALUE, 'credential', 'api_key');
      token.revoke('rotated');

      // Deriving reads the value, so the gate refuses before there is anything
      // to launder a revocation into.
      expect(() => token.reclassify('sensitive', 'harmless')).toThrow(RevokedSensitiveValueError);
      expect(() => token.substring(0, 4)).toThrow(RevokedSensitiveValueError);
      expect(() => token.map((raw) => raw)).toThrow(RevokedSensitiveValueError);
    });

    it('made before the revocation is revoked with it', () => {
      const token = new SensitiveString(VALUE, 'credential', 'api_key');
      const laundered = token.reclassify('sensitive', 'harmless');

      token.revoke('rotated');

      expect(laundered.isRevoked).toBe(true);
      expect(() => laundered.reveal()).toThrow(RevokedSensitiveValueError);
    });
  });

  describe('what stays available', () => {
    it('keeps a revoked value safe to log', () => {
      const secret = new SensitiveString(VALUE, 'credential', 'api_key');
      secret.revoke('rotated');

      expect(secret.toString()).toBe('[REDACTED:credential]');
      expect(JSON.stringify({ secret })).toBe('{"secret":"[REDACTED:credential]"}');
      expect(secret.length).toBe(VALUE.length);
      expect(secret.isEmpty()).toBe(false);
      expect(secret.klass).toBe('credential');
      expect(secret.label).toBe('api_key');
    });

    it('marks a revoked value in inspection without replacing the redaction', () => {
      const secret = new SensitiveString(VALUE, 'credential', 'api_key');
      secret.revoke('rotated');

      expect(util.inspect(secret)).toBe(
        'SensitiveString<credential:api_key> { [REDACTED:credential] REVOKED }'
      );
    });

    it('never calls an external registry from inspection', () => {
      let calls = 0;
      const registry: RevocationRegistry = {
        isRevoked() {
          calls++;
          return true;
        },
      };

      const secret = new SensitiveString(VALUE, 'credential', 'api_key', {
        revocationRegistry: registry,
      });

      expect(util.inspect(secret)).not.toContain('REVOKED');
      expect(calls).toBe(0);
    });

    it('refuses a comparison, because a comparison reads the value', () => {
      const secret = new SensitiveString(VALUE, 'credential', 'api_key');
      const other = new SensitiveString(VALUE, 'credential', 'other');
      secret.revoke('rotated');

      expect(() => secret.equals(VALUE)).toThrow(RevokedSensitiveValueError);
      expect(() => other.equals(secret)).toThrow(RevokedSensitiveValueError);
    });
  });

  describe('renewal', () => {
    it('is refused on a revoked value', () => {
      const session = new SensitiveString(VALUE, 'sensitive', 'session', { ttl: 60_000 });
      session.revoke('rotated');

      expect(() => session.renew(60_000)).toThrow(RevokedSensitiveValueError);
    });
  });

  describe('the wire format', () => {
    it('refuses to serialize a revoked value', () => {
      const secret = new SensitiveString(VALUE, 'credential', 'api_key');
      secret.revoke('rotated');

      expect(() => secret.serialize()).toThrow(RevokedSensitiveValueError);
    });

    it('honours a payload that marks the value revoked', () => {
      const received = SensitiveString.deserialize({
        __sensitive: true,
        klass: 'credential',
        value: VALUE,
        label: 'api_key',
        revoked: true,
        revocationReason: 'revoked upstream',
      });

      expect(received.isRevoked).toBe(true);
      expect(received.revocationReason).toBe('revoked upstream');
      expect(() => received.reveal()).toThrow(RevokedSensitiveValueError);
    });

    it('accepts the flag without a reason', () => {
      const received = SensitiveString.deserialize({
        __sensitive: true,
        klass: 'credential',
        value: VALUE,
        revoked: true,
      });

      expect(received.revocationReason).toBe('revoked by the sender');
    });

    it('rejects a payload that tries to say a value is not revoked', () => {
      expect(() =>
        SensitiveString.deserialize({
          __sensitive: true,
          klass: 'credential',
          value: VALUE,
          revoked: false,
        })
      ).toThrow(/revoked must be true or absent/);
    });

    it('rejects a reason with no flag, which would silently revoke nothing', () => {
      expect(() =>
        SensitiveString.deserialize({
          __sensitive: true,
          klass: 'credential',
          value: VALUE,
          revocationReason: 'meant to revoke',
        })
      ).toThrow(/without revoked: true/);

      expect(() =>
        SensitiveString.deserialize({
          __sensitive: true,
          klass: 'credential',
          value: VALUE,
          revoked: true,
          revocationReason: 7,
        })
      ).toThrow(/revocationReason must be a string/);
    });

    it('applies the lists of the receiving process to a received value', () => {
      const payload = new SensitiveString(VALUE, 'credential', 'api_key').serialize();

      revokeByLabel('api_key', 'revoked on this side');

      expect(SensitiveString.deserialize(payload).isRevoked).toBe(true);
    });
  });

  describe('auditing', () => {
    it('reports a revocation without disclosing the value', () => {
      const records: RevealDetails[] = [];
      const secret = new SensitiveString(VALUE, 'credential', 'api_key');

      withRevealContext({ name: 'incident', auditReveal: (_v, d) => records.push(d) }, () => {
        secret.revoke('Rotated 2026-08-01');
      });

      expect(records).toHaveLength(1);
      const record = records[0] as RevokeAuditDetails;
      expect(record.operation).toBe('revoke');
      expect(record.reason).toBe('Rotated 2026-08-01');
      expect(record.scope).toBe('instance');
      expect(record.revokedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
      expect(JSON.stringify(records)).not.toContain(VALUE);
    });

    it('reports nothing for a revocation that changed nothing', () => {
      const records: RevealDetails[] = [];
      const secret = new SensitiveString(VALUE, 'credential', 'api_key');
      secret.revoke('first');

      withRevealContext({ name: 'incident', auditReveal: (_v, d) => records.push(d) }, () => {
        secret.revoke('second');
      });

      expect(records).toEqual([]);
    });

    it('revokes even when the audit sink throws', () => {
      const secret = new SensitiveString(VALUE, 'credential', 'api_key');

      expect(() =>
        secret.revoke('rotated', {
          name: 'incident',
          auditReveal: () => {
            throw new Error('audit sink unavailable');
          },
        })
      ).not.toThrow();

      expect(secret.isRevoked).toBe(true);
    });

    it('is not something a policy may refuse', () => {
      registerPolicy(
        {
          name: 'credential',
          redact: () => '[REDACTED:credential]',
          checkRevealAllowed: () => {
            throw new Error('no reads allowed');
          },
        },
        { overwrite: true }
      );

      const secret = new SensitiveString(VALUE, 'credential', 'api_key');

      expect(() => secret.revoke('rotated')).not.toThrow();
      expect(secret.isRevoked).toBe(true);
    });
  });

  describe('composition with the other lifecycle controls', () => {
    it('reports revocation ahead of expiry, so a revoked value never looks renewable', () => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'));

      try {
        const session = new SensitiveString(VALUE, 'sensitive', 'session', { ttl: 60_000 });
        session.revoke('rotated');
        vi.setSystemTime(new Date('2026-01-01T00:02:00.000Z'));

        expect(() => session.reveal()).toThrow(RevokedSensitiveValueError);
      } finally {
        vi.useRealTimers();
      }
    });

    it('does not spend a reveal budget on a refused read', () => {
      const bootstrap = new SensitiveString(VALUE, 'credential', 'bootstrap', { maxReveals: 1 });
      bootstrap.revoke('rotated');

      expect(() => bootstrap.reveal()).toThrow(RevokedSensitiveValueError);
      expect(bootstrap.revealCount).toBe(0);
    });
  });
});
