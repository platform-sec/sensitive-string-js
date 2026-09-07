import {
  SensitiveString,
  getCurrentRevealContext,
  registerPolicy,
  resetPolicies,
  withDevMode,
  withRevealContext,
} from '@platform-sec/sensitive-string-core';
import type { AuditContext, RevealContext } from '@platform-sec/sensitive-string-core';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { TypeOrmConfigError, TypeOrmMarkerReadError, TypeOrmWriteRefusedError } from './errors.js';
import { resetMarkerCache } from './marker.js';
import { brandOf, resetPlainWriteReports, sensitiveColumn } from './transformer.js';
import { SENSITIVE_TRANSFORMER } from './types.js';
import { CANARY } from './__tests__/fixtures.js';

const options = { table: 'users', column: 'email' } as const;

describe('sensitiveColumn', () => {
  beforeEach(() => {
    resetPlainWriteReports();
  });

  it('refuses an unregistered class at construction', () => {
    expect(() => sensitiveColumn('nope' as 'sensitive', options)).toThrow(TypeOrmConfigError);
  });

  it('returns null for null and undefined for undefined, in both directions', () => {
    // Asserted per value rather than per type, because the two arrive from
    // different places: null from an explicit null insert and from every
    // nullable column of every row, undefined from IsNull() and from an upsert
    // that omits the column.
    const transformer = sensitiveColumn('sensitive', options);
    expect(transformer.to(null)).toBeNull();
    expect(transformer.to(undefined)).toBeUndefined();
    expect(transformer.from(null)).toBeNull();
    expect(transformer.from(undefined)).toBeUndefined();
  });

  it('reveals an instance on the way out and wraps a string on the way back', () => {
    const transformer = sensitiveColumn('credential', { table: 'users', column: 'api_key' });
    expect(transformer.to(new SensitiveString(CANARY, 'credential'))).toBe(CANARY);
    const wrapped = transformer.from(CANARY) as SensitiveString<'credential'>;
    expect(wrapped).toBeInstanceOf(SensitiveString);
    expect(wrapped.klass).toBe('credential');
    expect(wrapped.label).toBe('api_key');
    expect(String(wrapped)).not.toContain(CANARY);
  });

  it('prefers an explicit label over the column name', () => {
    const transformer = sensitiveColumn('sensitive', { ...options, label: 'primary-email' });
    expect((transformer.from('a') as SensitiveString<'sensitive'>).label).toBe('primary-email');
  });

  it('leaves a non-string read value alone', () => {
    // A specification applied to a column that is not text, or a driver that
    // returns a Buffer. Wrapping would put an object where the application's
    // own property type says a string was.
    const transformer = sensitiveColumn('sensitive', options);
    const buffer = Buffer.from('x');
    expect(transformer.from(buffer)).toBe(buffer);
    expect(transformer.from(42)).toBe(42);
  });

  it('raises rather than wrapping a marker read back', () => {
    const transformer = sensitiveColumn('sensitive', options);
    expect(() => transformer.from('[REDACTED:sensitive]')).toThrow(TypeOrmMarkerReadError);
    expect(() => transformer.from('Bearer [REDACTED:credential] etc')).toThrow(
      TypeOrmMarkerReadError
    );
  });

  it('refuses to write a string holding a marker', () => {
    const transformer = sensitiveColumn('sensitive', options);
    expect(() => transformer.to('[REDACTED:sensitive]')).toThrow(TypeOrmWriteRefusedError);
  });

  it('refuses to write an instance whose value is itself a marker', () => {
    const transformer = sensitiveColumn('sensitive', options);
    const rewrapped = new SensitiveString('[REDACTED:sensitive]', 'sensitive');
    expect(() => transformer.to(rewrapped)).toThrow(TypeOrmWriteRefusedError);
  });
});

describe('the plain-string write', () => {
  beforeEach(() => {
    resetPlainWriteReports();
  });

  it('passes through by default, because a literal predicate is legitimate', () => {
    // find({ where: { email: 'a@example.com' } }) with a literal hands to() a
    // plain string and is an ordinary query. An unconditional throw would
    // refuse it.
    const transformer = sensitiveColumn('sensitive', options);
    expect(transformer.to('a@example.com')).toBe('a@example.com');
  });

  it('refuses under strictWrites, naming the literal case as the exception', () => {
    const transformer = sensitiveColumn('sensitive', { ...options, strictWrites: true });
    try {
      transformer.to('a@example.com');
      expect.unreachable('should have refused');
    } catch (error) {
      expect(error).toBeInstanceOf(TypeOrmWriteRefusedError);
      expect((error as Error).message).toContain('where');
      expect((error as Error).message).not.toContain('a@example.com');
    }
  });

  it('refuses a non-string under strictWrites', () => {
    const transformer = sensitiveColumn('sensitive', { ...options, strictWrites: true });
    expect(() => transformer.to(42)).toThrow(TypeOrmWriteRefusedError);
  });

  it('reports once per path and never reports the value', () => {
    const seen: unknown[] = [];
    const transformer = sensitiveColumn('sensitive', {
      ...options,
      onPlainWrite: (info) => seen.push(info),
    });
    transformer.to(CANARY);
    transformer.to(CANARY);
    transformer.to(CANARY);
    expect(seen).toEqual([{ path: 'users.email', klass: 'sensitive', received: 'string' }]);
  });

  it('says nothing at all when development mode is off', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    sensitiveColumn('sensitive', options).to('a@example.com');
    expect(warn).not.toHaveBeenCalled();
    warn.mockRestore();
  });

  it('warns once when development mode is on', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    withDevMode({ enabled: true }, () => {
      const transformer = sensitiveColumn('sensitive', options);
      transformer.to('a@example.com');
      transformer.to('b@example.com');
    });
    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0]?.[0])).not.toContain('a@example.com');
    warn.mockRestore();
  });
});

describe('the reveal context', () => {
  it('inherits the ambient name and reason and adds the column tags', () => {
    const seen: AuditContext[] = [];
    const ambient: (RevealContext | null)[] = [];
    withRevealContext(
      {
        name: 'req-42',
        reason: 'serving a request',
        tags: { requestId: 'r1' },
        // The per-column context reaches the sink as the hook's third
        // argument. Nothing is installed for it: the transformer used to run
        // every reveal inside a `withRevealContext` purely so a sink could
        // find these tags, and `ambient` is what that cost bought.
        auditReveal: (_value, _details, context) => {
          seen.push(context);
          ambient.push(getCurrentRevealContext());
        },
      },
      () => {
        sensitiveColumn('sensitive', options).to(new SensitiveString(CANARY, 'sensitive'));
      }
    );

    expect(seen).toHaveLength(1);
    expect(ambient[0]?.tags).toEqual({ requestId: 'r1' });
    const ctx = seen[0];
    expect(ctx?.name).toBe('req-42');
    expect(ctx?.reason).toBe('serving a request');
    expect(ctx?.tags).toEqual({
      requestId: 'r1',
      sink: 'typeorm',
      operation: 'unknown',
      table: 'users',
      column: 'email',
    });
  });

  it('reports the operation as unknown, permanently and on purpose', () => {
    // A ValueTransformer receives one argument. It is not told whether this is
    // an insert, an update, a predicate or change detection, and the only way
    // to recover that is to read the stack. The audit record from this package
    // is coarser than one from a hook with a statement boundary, and it says so
    // rather than guessing 'update'.
    const seen: AuditContext[] = [];
    withRevealContext(
      { name: 'r', auditReveal: (_value, _details, context) => seen.push(context) },
      () => {
        sensitiveColumn('sensitive', options).to(new SensitiveString(CANARY, 'sensitive'));
      }
    );
    expect(seen[0]?.tags?.['operation']).toBe('unknown');
  });

  it('synthesises a context when there is no ambient one', () => {
    const transformer = sensitiveColumn('sensitive', options);
    expect(transformer.to(new SensitiveString(CANARY, 'sensitive'))).toBe(CANARY);
  });

  it('refuses a write with no ambient context under strictContext', () => {
    const transformer = sensitiveColumn('sensitive', { ...options, strictContext: true });
    expect(() => transformer.to(new SensitiveString(CANARY, 'sensitive'))).toThrow(
      TypeOrmWriteRefusedError
    );
    withRevealContext({ name: 'req' }, () => {
      expect(transformer.to(new SensitiveString(CANARY, 'sensitive'))).toBe(CANARY);
    });
  });
});

describe('the brand', () => {
  it('is not enumerable, so it does not appear in an inspection', () => {
    const transformer = sensitiveColumn('sensitive', options);
    expect(Object.keys(transformer)).toEqual(['to', 'from']);
    expect(JSON.stringify(transformer)).toBe('{}');
  });

  it('names the path, the class and the label', () => {
    const brand = brandOf(sensitiveColumn('sensitive', options));
    expect(brand).toEqual({
      klass: 'sensitive',
      label: 'email',
      path: 'users.email',
      table: 'users',
      column: 'email',
    });
  });

  it('is undefined for anything else', () => {
    expect(brandOf({ to: (v: unknown) => v, from: (v: unknown) => v })).toBeUndefined();
    expect(brandOf(null)).toBeUndefined();
    expect(brandOf('a string')).toBeUndefined();
  });

  it('uses a registry-wide symbol, so two copies of the package agree', () => {
    expect(SENSITIVE_TRANSFORMER).toBe(
      Symbol.for('platform-sec.sensitive-string.typeorm.transformer')
    );
  });
});

describe('a custom policy', () => {
  afterEach(() => {
    resetPolicies();
    resetMarkerCache();
  });

  it('has its marker recognised on both the read and the write path', () => {
    registerPolicy(
      {
        name: 'sensitive',
        redact: () => '<<gone>>',
        requireConstantTimeEquals: false,
        allowPartialQueries: true,
        allowMask: true,
      },
      { overwrite: true }
    );
    resetMarkerCache();

    const transformer = sensitiveColumn('sensitive', options);
    expect(() => transformer.to('<<gone>>')).toThrow(TypeOrmWriteRefusedError);
    expect(() => transformer.from('<<gone>>')).toThrow(TypeOrmMarkerReadError);
  });
});
