import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as util from 'node:util';
import { registerPolicy, resetPolicies, SensitiveString, withRevealContext } from '../index.js';
import type { RevealContext } from '../index.js';

const CANARY = 'STRING_METHODS_CANARY_4f983d';

describe('SensitiveString string-method security', () => {
  beforeEach(() => {
    resetPolicies();
  });

  it('never exposes transformed values through logging or serialization', () => {
    const source = new SensitiveString(`  ${CANARY}-SECOND  `, 'credential', 'token');
    const transformed = [
      source.trim(),
      source.trimStart(),
      source.trimEnd(),
      source.toLowerCase(),
      source.toUpperCase(),
      source.padStart(40, '*'),
      source.padEnd(40, '*'),
      source.slice(2, -2),
      source.replace('SECOND', 'REPLACED'),
      source.replaceAll('N', 'n'),
      source.charAt(2),
      source.at(-3),
      ...source.split('-'),
    ];

    for (const value of transformed) {
      expect(String(value)).not.toContain(CANARY);
      expect(JSON.stringify(value)).not.toContain(CANARY);
      expect(util.inspect(value)).not.toContain(CANARY);
      expect(value?.klass).toBe('credential');
      expect(value?.label).toBe('token');
    }
  });

  it('rejects replacement callbacks at runtime without invoking or auditing them', () => {
    const source = new SensitiveString(CANARY, 'credential', 'token');
    const replacement = vi.fn(() => 'LEAKED');
    const auditReveal = vi.fn();
    const ctx: RevealContext = { name: 'replace', auditReveal };
    const unsafeSource = source as unknown as {
      replace(
        searchValue: string | RegExp,
        replaceValue: (...args: unknown[]) => string,
        context?: RevealContext
      ): SensitiveString<'credential'>;
      replaceAll(
        searchValue: string | RegExp,
        replaceValue: (...args: unknown[]) => string,
        context?: RevealContext
      ): SensitiveString<'credential'>;
    };

    expect(() => unsafeSource.replace(/./, replacement, ctx)).toThrow(
      'SensitiveString replacement value must be a string'
    );
    expect(() => unsafeSource.replaceAll(/./g, replacement, ctx)).toThrow(
      'SensitiveString replacement value must be a string'
    );
    expect(replacement).not.toHaveBeenCalled();
    expect(auditReveal).not.toHaveBeenCalled();
  });

  it('denies every partial query on credentials by default without leaking the value', () => {
    const source = new SensitiveString(CANARY, 'credential', 'token');
    const queries = [
      () => source.startsWith('S'),
      () => source.endsWith('d'),
      () => source.includes('CANARY'),
      () => source.indexOf('CANARY'),
      () => source.lastIndexOf('CANARY'),
    ];

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

  it('honors a policy that disables partial queries for sensitive values', () => {
    registerPolicy(
      {
        name: 'sensitive',
        redact: () => '[REDACTED:sensitive]',
        allowPartialQueries: false,
      },
      { overwrite: true }
    );

    const source = new SensitiveString(CANARY, 'sensitive');

    expect(() => source.includes('CANARY')).toThrow(
      "Partial queries are not allowed for sensitivity class 'sensitive'"
    );
  });

  it('authorizes and audits allowed partial queries', () => {
    const checkRevealAllowed = vi.fn((ctx: RevealContext | null) => {
      if (ctx?.name !== 'approved-query') {
        throw new Error('Query context denied');
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
    const ctx: RevealContext = { name: 'approved-query', auditReveal };

    expect(source.startsWith('STRING', 0, ctx)).toBe(true);
    expect(source.endsWith('4f983d', undefined, ctx)).toBe(true);
    expect(source.includes('CANARY', 0, ctx)).toBe(true);
    expect(source.indexOf('CANARY', 0, ctx)).toBe(15);
    expect(source.lastIndexOf('STRING', undefined, ctx)).toBe(0);
    expect(checkRevealAllowed).toHaveBeenCalledTimes(5);
    expect(auditReveal).toHaveBeenCalledTimes(5);
    expect(auditReveal).toHaveBeenCalledWith(source, { operation: 'reveal' });
  });

  it('authorizes and audits every transformation through explicit context', () => {
    const checkRevealAllowed = vi.fn((ctx: RevealContext | null) => {
      if (ctx?.name !== 'approved-transform') {
        throw new Error('Transform context denied');
      }
    });
    registerPolicy(
      {
        name: 'credential',
        redact: () => '[REDACTED:credential]',
        requireConstantTimeEquals: true,
        allowPartialQueries: false,
        checkRevealAllowed,
      },
      { overwrite: true }
    );

    const source = new SensitiveString(` ${CANARY} `, 'credential');
    const auditReveal = vi.fn();
    const ctx: RevealContext = { name: 'approved-transform', auditReveal };
    const transformations = [
      () => source.trim(ctx),
      () => source.trimStart(ctx),
      () => source.trimEnd(ctx),
      () => source.toLowerCase(ctx),
      () => source.toUpperCase(ctx),
      () => source.padStart(40, '*', ctx),
      () => source.padEnd(40, '*', ctx),
      () => source.slice(0, 4, ctx),
      () => source.split('-', undefined, ctx),
      () => source.replace('CANARY', 'MARKER', ctx),
      () => source.replaceAll('A', 'a', ctx),
      () => source.charAt(1, ctx),
      () => source.at(-2, ctx),
    ];

    for (const transform of transformations) {
      expect(transform).not.toThrow();
    }
    expect(checkRevealAllowed).toHaveBeenCalledTimes(transformations.length);
    expect(auditReveal).toHaveBeenCalledTimes(transformations.length);
    expect(auditReveal).toHaveBeenCalledWith(source, { operation: 'reveal' });
  });

  it('uses AsyncLocalStorage context for transformations', () => {
    registerPolicy(
      {
        name: 'credential',
        redact: () => '[REDACTED:credential]',
        checkRevealAllowed: (ctx) => {
          if (!ctx) throw new Error('Context required');
        },
      },
      { overwrite: true }
    );

    const source = new SensitiveString(CANARY, 'credential');
    const auditReveal = vi.fn();

    withRevealContext({ name: 'transform', auditReveal }, () => {
      source.trim().toLowerCase().slice(0, 6);
    });

    expect(auditReveal).toHaveBeenCalledTimes(3);
  });
});
