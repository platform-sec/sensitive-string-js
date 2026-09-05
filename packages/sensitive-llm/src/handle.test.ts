import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import {
  deriveKeyedToken,
  getPolicy,
  registerPolicy,
  resetPolicies,
  SensitiveString,
  withRevealContext,
  type RevealContext,
} from '@platform-sec/sensitive-string-core';
import { beforeEach, describe, expect, it } from 'vitest';

import { createHandleMap, entityHandle, handlePattern, HandleNotAllowedError } from './handle.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';
const KEY = new Uint8Array(32).fill(7);
const OTHER_KEY = new Uint8Array(32).fill(9);

describe('entityHandle', () => {
  beforeEach(() => {
    resetPolicies();
  });

  describe('derivation', () => {
    it('is stable for the same value, key, scope and class', () => {
      const a = entityHandle(new SensitiveString(CANARY, 'sensitive'), { key: KEY, scope: 'c1' });
      const b = entityHandle(new SensitiveString(CANARY, 'sensitive'), { key: KEY, scope: 'c1' });

      expect(a).toBe(b);
    });

    /**
     * Across processes, not only across calls, because "the same customer in
     * turn 7 as in turn 1" has to survive a deploy. A child process gets a
     * fresh module registry and a fresh heap; anything memoized in this one
     * cannot make this pass.
     */
    it('is stable across processes', () => {
      const local = entityHandle(new SensitiveString(CANARY, 'sensitive'), {
        key: KEY,
        scope: 'c1',
      });

      const script = `
        const { SensitiveString } = require('@platform-sec/sensitive-string-core');
        const { entityHandle } = require('@platform-sec/sensitive-string-llm');
        const key = new Uint8Array(32).fill(7);
        process.stdout.write(
          entityHandle(new SensitiveString(${JSON.stringify(CANARY)}, 'sensitive'), {
            key,
            scope: 'c1',
          })
        );
      `;

      // Resolved from the working directory rather than from `import.meta`,
      // which is unavailable in the CommonJS-capable program the repository
      // type-checks these files against. Vitest runs from the repository root.
      const remote = execFileSync(process.execPath, ['-e', script], {
        cwd: resolve(process.cwd(), 'packages/sensitive-llm'),
        encoding: 'utf8',
      });

      expect(remote).toBe(local);
    });

    it.each([
      ['a different value', () => new SensitiveString('other@test', 'sensitive'), {}],
      ['a different scope', () => new SensitiveString(CANARY, 'sensitive'), { scope: 'c2' }],
      ['a different key', () => new SensitiveString(CANARY, 'sensitive'), { key: OTHER_KEY }],
    ])('differs for %s', (_label, build, overrides) => {
      const base = entityHandle(new SensitiveString(CANARY, 'sensitive'), {
        key: KEY,
        scope: 'c1',
      });
      const other = entityHandle(build(), { key: KEY, scope: 'c1', ...overrides });

      expect(other).not.toBe(base);
    });

    /**
     * The class is a derivation input, so the same string classified two ways
     * gets two handles. Reclassification is an audited operation and a handle
     * that survived it would be a channel around the audit.
     *
     * Asserted against the derivation directly, because the package refuses to
     * mint for the only other class there is, so the two handles this claims
     * differ cannot both be produced through `entityHandle`.
     */
    it('mixes the class into the derivation', () => {
      const handle = entityHandle(new SensitiveString(CANARY, 'sensitive'), {
        key: KEY,
        scope: 'c1',
      });

      const asSensitive = deriveKeyedToken(CANARY, { key: KEY, domain: ['c1', 'sensitive'] });
      const asCredential = deriveKeyedToken(CANARY, { key: KEY, domain: ['c1', 'credential'] });

      expect(handle).toBe(`<<E:${asSensitive}>>`);
      expect(asCredential).not.toBe(asSensitive);
    });

    /**
     * The domain components are NUL-separated rather than joined, so a scope
     * cannot be chosen to impersonate the class segment that follows it.
     */
    it('separates the scope from the class, so a scope cannot spoof one', () => {
      const value = new SensitiveString(CANARY, 'sensitive');

      expect(entityHandle(value, { key: KEY, scope: 'sensitive' })).not.toBe(
        entityHandle(value, { key: KEY })
      );
    });

    it('defaults to 12 hex characters and honours a longer length', () => {
      const value = new SensitiveString(CANARY, 'sensitive');

      expect(entityHandle(value, { key: KEY })).toMatch(/^<<E:[0-9a-f]{12}>>$/);
      expect(entityHandle(value, { key: KEY, length: 16 })).toMatch(/^<<E:[0-9a-f]{16}>>$/);
    });

    it('refuses a length below the collision floor and a key below the entropy floor', () => {
      const value = new SensitiveString(CANARY, 'sensitive');

      expect(() => entityHandle(value, { key: KEY, length: 8 })).toThrow(RangeError);
      expect(() => entityHandle(value, { key: 'short' })).toThrow(RangeError);
    });

    /**
     * A caller's typo must not cost an audit record. Core's raw-value gate
     * refuses a denied read before the audit hook, on the rule that a denied
     * read is not a reveal; a read whose result is thrown away for a bad
     * `length` is the same thing one step later, and an auditor reconciling
     * reveals against derived tokens would find one that does not balance.
     */
    it.each([
      ['a short key', { key: 'short' }],
      ['a length below the floor', { key: KEY, length: 8 }],
      ['a length above the ceiling', { key: KEY, length: 65 }],
    ])('refuses %s before reading the value, so no audit record is produced', (_label, options) => {
      const audited: string[] = [];

      withRevealContext({ name: 'r', auditReveal: (v) => audited.push(v.klass) }, () => {
        expect(() =>
          entityHandle(new SensitiveString(CANARY, 'sensitive'), options as never)
        ).toThrow(RangeError);
      });

      expect(audited).toEqual([]);
    });
  });

  describe('the prefix', () => {
    it('defaults to the label, so a reader can tell what kind of entity it stands for', () => {
      const value = new SensitiveString(CANARY, 'sensitive', 'customer_email');

      expect(entityHandle(value, { key: KEY })).toMatch(/^<<customer_email:[0-9a-f]{12}>>$/);
    });

    it('falls back to E for a label that would not survive the token grammar', () => {
      const value = new SensitiveString(CANARY, 'sensitive', 'customer email (primary)');

      expect(entityHandle(value, { key: KEY })).toMatch(/^<<E:[0-9a-f]{12}>>$/);
    });

    it('refuses an explicit prefix that would not survive it', () => {
      const value = new SensitiveString(CANARY, 'sensitive');

      // A silent fallback here would be found out by a rehydration that
      // matched nothing, which is the wrong place to learn about it.
      expect(() => entityHandle(value, { key: KEY, prefix: 'a b' })).toThrow(TypeError);
    });

    it('does not change the derivation', () => {
      const value = new SensitiveString(CANARY, 'sensitive');
      const a = entityHandle(value, { key: KEY, prefix: 'X' });
      const b = entityHandle(value, { key: KEY, prefix: 'Y' });

      expect(a.slice(a.indexOf(':'))).toBe(b.slice(b.indexOf(':')));
    });
  });

  describe('credentials', () => {
    it('never get a handle', () => {
      expect(() => entityHandle(new SensitiveString(CANARY, 'credential'), { key: KEY })).toThrow(
        HandleNotAllowedError
      );
    });

    /**
     * The refusal is hard-coded, not read from a policy flag, and this test is
     * what keeps it that way. `allowMask` and `allowPartialQueries` are both
     * false on `credential` and are the same question asked about a different
     * derived form; permitting either must not open this one.
     */
    it('stays refused even when the policy is opened all the way up', () => {
      const policy = getPolicy('credential');

      registerPolicy(
        {
          ...policy,
          allowMask: true,
          allowPartialQueries: true,
          advisory: { ...policy.advisory, allowSendToExternal: true, allowHash: true },
        },
        { overwrite: true }
      );

      expect(() => entityHandle(new SensitiveString(CANARY, 'credential'), { key: KEY })).toThrow(
        HandleNotAllowedError
      );
    });

    it('refuses before reading the value, so no audit record is produced', () => {
      const audited: string[] = [];

      withRevealContext({ name: 'r', auditReveal: (v) => audited.push(v.klass) }, () => {
        expect(() => entityHandle(new SensitiveString(CANARY, 'credential'), { key: KEY })).toThrow(
          HandleNotAllowedError
        );
      });

      expect(audited).toEqual([]);
    });
  });

  describe('auditing', () => {
    it('is a reveal, under a handle: context rather than an external: one', () => {
      let captured: RevealContext | undefined;
      const operations: string[] = [];

      const policy = getPolicy('sensitive');
      registerPolicy(
        {
          ...policy,
          checkRevealAllowed: (ctx) => {
            captured = ctx ?? undefined;
          },
        },
        { overwrite: true }
      );

      withRevealContext(
        { name: 'request', auditReveal: (_v, d) => operations.push(d.operation) },
        () => entityHandle(new SensitiveString(CANARY, 'sensitive'), { key: KEY, scope: 'c-9' })
      );

      expect(captured?.name).toBe('handle:c-9');
      expect(captured?.tags).toMatchObject({ handleScope: 'c-9', handlePrefix: 'E' });
      expect(operations).toEqual(['reveal']);
    });

    it('does not run the external sink check, because a handle is not a transmission', () => {
      expect(getPolicy('sensitive').advisory?.allowSendToExternal).toBe(false);

      expect(() =>
        entityHandle(new SensitiveString(CANARY, 'sensitive'), { key: KEY })
      ).not.toThrow();
    });
  });

  describe('the reverse map', () => {
    it('records the handle against the wrapped value, not a string', () => {
      const map = createHandleMap();
      const value = new SensitiveString(CANARY, 'sensitive');
      const handle = entityHandle(value, { key: KEY, record: map });

      expect(map.get(handle)).toBe(value);
      expect(JSON.stringify([...map.values()])).not.toContain(CANARY);
    });

    it('belongs to the caller, so the package holds no state between calls', () => {
      const first = createHandleMap();
      const second = createHandleMap();

      entityHandle(new SensitiveString(CANARY, 'sensitive'), { key: KEY, record: first });

      expect(second.size).toBe(0);
    });
  });

  describe('handlePattern', () => {
    it('returns a fresh matcher each time, so lastIndex cannot carry between scans', () => {
      const text = '<<E:0123456789ab>> and <<E:ba9876543210>>';

      expect(text.match(handlePattern())).toHaveLength(2);
      expect(text.match(handlePattern())).toHaveLength(2);
      expect(handlePattern()).not.toBe(handlePattern());
    });
  });
});
