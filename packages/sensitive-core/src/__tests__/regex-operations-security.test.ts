import * as util from 'node:util';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { registerPolicy, resetPolicies, SensitiveString } from '../index.js';
import type { RevealContext } from '../index.js';

const CANARY = 'REGEX_SECURITY_CANARY_91f7@example.test';

describe('SensitiveString regular-expression security', () => {
  beforeEach(() => {
    resetPolicies();
  });

  it('does not expose matched values through logging or serialization', () => {
    const source = new SensitiveString(CANARY, 'credential', 'email');
    const match = source.match(/(REGEX_SECURITY_CANARY_91f7)@(.+)/) ?? [];
    const groups = source.matchGroups(/^(?<local>[^@]+)@(?<domain>[^@]+)$/) ?? {};
    const all = Array.from(source.matchAll(/(REGEX_SECURITY_CANARY_91f7)@([^\s]+)/g)).flat();

    for (const value of [...match, ...Object.values(groups), ...all]) {
      expect(String(value)).not.toContain(CANARY);
      expect(JSON.stringify(value)).not.toContain(CANARY);
      expect(util.inspect(value)).not.toContain(CANARY);
      expect(value.klass).toBe('credential');
    }
  });

  it('denies regex queries on credentials by default without leaking the value', () => {
    const source = new SensitiveString(CANARY, 'credential');
    const queries = [() => source.test(/^R/), () => source.search(/@/)];

    for (const query of queries) {
      expect(query).toThrow("Partial queries are not allowed for sensitivity class 'credential'");

      try {
        query();
      } catch (error) {
        expect((error as Error).message).not.toContain(CANARY);
        expect((error as Error).stack ?? '').not.toContain(CANARY);
      }
    }
  });

  it('authorizes and audits regex queries when policy permits them', () => {
    const checkRevealAllowed = vi.fn((ctx: RevealContext | null): undefined => {
      if (ctx?.name !== 'approved-regex') {
        throw new Error('Regex context denied');
      }
    });
    registerPolicy(
      {
        name: 'credential',
        redact: () => '[REDACTED:credential]',
        requireConstantTimeEquals: true,
        allowPartialQueries: true,
        checkRevealAllowed,
      },
      { overwrite: true }
    );

    const source = new SensitiveString(CANARY, 'credential');
    const auditReveal = vi.fn();
    const ctx: RevealContext = { name: 'approved-regex', auditReveal };

    expect(source.test(/^REGEX/, ctx)).toBe(true);
    expect(source.search(/@/, ctx)).toBe(26);
    expect(checkRevealAllowed).toHaveBeenCalledTimes(2);
    expect(auditReveal).toHaveBeenCalledTimes(2);
    expect(auditReveal).toHaveBeenCalledWith(source, { operation: 'reveal' });
  });

  it('authorizes and audits regex extraction exactly once per operation', () => {
    const checkRevealAllowed = vi.fn((ctx: RevealContext | null): undefined => {
      if (ctx?.name !== 'approved-extraction') {
        throw new Error('Extraction context denied');
      }
    });
    registerPolicy(
      {
        name: 'credential',
        redact: () => '[REDACTED:credential]',
        checkRevealAllowed,
      },
      { overwrite: true }
    );

    const source = new SensitiveString(CANARY, 'credential');
    const auditReveal = vi.fn();
    const ctx: RevealContext = { name: 'approved-extraction', auditReveal };

    expect(source.match(/CANARY/, ctx)).not.toBeNull();
    expect(source.matchGroups(/(?<marker>CANARY)/, ctx)).not.toBeNull();
    expect(Array.from(source.matchAll(/CANARY/g, ctx))).toHaveLength(1);
    expect(checkRevealAllowed).toHaveBeenCalledTimes(3);
    expect(auditReveal).toHaveBeenCalledTimes(3);
    expect(auditReveal).toHaveBeenCalledWith(source, { operation: 'reveal' });
  });

  it('does not pass the raw value to overridden RegExp hooks', () => {
    const source = new SensitiveString(CANARY, 'sensitive');
    const pattern = /(?<marker>CANARY)/g;
    const exec = vi.fn(() => {
      throw new Error('overridden exec called');
    });
    const match = vi.fn(() => {
      throw new Error('overridden match called');
    });
    const matchAll = vi.fn(() => {
      throw new Error('overridden matchAll called');
    });
    const search = vi.fn(() => {
      throw new Error('overridden search called');
    });
    const split = vi.fn(() => {
      throw new Error('overridden split called');
    });
    const replace = vi.fn(() => {
      throw new Error('overridden replace called');
    });
    const sourceGetter = vi.fn(() => 'NEVER_USED');
    const flagsGetter = vi.fn(() => 'g');

    Object.defineProperties(pattern, {
      exec: { value: exec },
      source: { get: sourceGetter },
      flags: { get: flagsGetter },
      [Symbol.match]: { value: match },
      [Symbol.matchAll]: { value: matchAll },
      [Symbol.search]: { value: search },
      [Symbol.split]: { value: split },
      [Symbol.replace]: { value: replace },
    });

    expect(source.test(pattern)).toBe(true);
    expect(source.search(pattern)).toBe(15);
    expect(source.match(pattern)).not.toBeNull();
    expect(source.matchGroups(pattern)).not.toBeNull();
    expect(Array.from(source.matchAll(pattern))).toHaveLength(1);
    expect(source.split(pattern)).not.toHaveLength(0);
    expect(source.replace(pattern, 'SAFE')).toBeInstanceOf(SensitiveString);
    expect(source.replaceAll(pattern, 'SAFE')).toBeInstanceOf(SensitiveString);
    expect(exec).not.toHaveBeenCalled();
    expect(sourceGetter).not.toHaveBeenCalled();
    expect(flagsGetter).not.toHaveBeenCalled();
    expect(match).not.toHaveBeenCalled();
    expect(matchAll).not.toHaveBeenCalled();
    expect(search).not.toHaveBeenCalled();
    expect(split).not.toHaveBeenCalled();
    expect(replace).not.toHaveBeenCalled();
  });

  it('rejects a non-global replaceAll pattern before authorization or audit', () => {
    const source = new SensitiveString(CANARY, 'credential');
    const checkRevealAllowed = vi.fn();
    const auditReveal = vi.fn();

    registerPolicy(
      {
        name: 'credential',
        redact: () => '[REDACTED:credential]',
        checkRevealAllowed,
      },
      { overwrite: true }
    );

    expect(() => source.replaceAll(/CANARY/, 'SAFE', { name: 'replace-all', auditReveal })).toThrow(
      'SensitiveString.replaceAll requires a global regular expression'
    );
    expect(checkRevealAllowed).not.toHaveBeenCalled();
    expect(auditReveal).not.toHaveBeenCalled();
  });

  it('rejects non-RegExp inputs before authorization or audit', () => {
    const source = new SensitiveString(CANARY, 'credential');
    const checkRevealAllowed = vi.fn();
    const auditReveal = vi.fn();
    const unsafeSource = source as unknown as {
      match(pattern: unknown, context?: RevealContext): SensitiveString<'credential'>[] | null;
    };

    registerPolicy(
      {
        name: 'credential',
        redact: () => '[REDACTED:credential]',
        checkRevealAllowed,
      },
      { overwrite: true }
    );

    expect(() => unsafeSource.match('CANARY', { name: 'regex', auditReveal })).toThrow(
      'SensitiveString.match requires a regular expression'
    );
    expect(checkRevealAllowed).not.toHaveBeenCalled();
    expect(auditReveal).not.toHaveBeenCalled();
  });
});
