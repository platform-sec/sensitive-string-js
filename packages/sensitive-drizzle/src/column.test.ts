import {
  SensitiveString,
  registerPolicy,
  resetPolicies,
  withDevMode,
  withRevealContext,
} from '@platform-sec/sensitive-string-core';
import type { AuditContext, RevealDetails } from '@platform-sec/sensitive-string-core';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  classificationOf,
  classifiedColumnNames,
  resetClassifiedColumnNames,
  resetPlainWriteReports,
  sensitiveMapping,
} from './column.js';
import {
  DrizzleColumnTypeError,
  DrizzleConfigError,
  DrizzleMarkerReadError,
  DrizzleWriteRefusedError,
} from './errors.js';
import { resetMarkerCache } from './marker.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

beforeEach(() => {
  resetPlainWriteReports();
  resetClassifiedColumnNames();
  resetMarkerCache();
});

describe('sensitiveMapping', () => {
  it('wraps a value read back from the driver', () => {
    const mapping = sensitiveMapping('sensitive', 'text', 'email');
    const wrapped = mapping.fromDriver('a@example.com');
    expect(wrapped).toBeInstanceOf(SensitiveString);
    expect(wrapped.klass).toBe('sensitive');
    expect(wrapped.label).toBe('email');
    expect(String(wrapped)).not.toContain('a@example.com');
  });

  it('takes the label from the column name and lets an option override it', () => {
    expect(sensitiveMapping('sensitive', 'text', 'email').fromDriver('x').label).toBe('email');
    expect(
      sensitiveMapping('sensitive', 'text', 'email', { label: 'primary-email' }).fromDriver('x')
        .label
    ).toBe('primary-email');
  });

  it('reveals a SensitiveString on the way to the driver', () => {
    const mapping = sensitiveMapping('credential', 'text', 'token');
    expect(mapping.toDriver(new SensitiveString(CANARY, 'credential'))).toBe(CANARY);
  });

  it('reports the SQL type it was built with, which is what a migration reads', () => {
    expect(sensitiveMapping('sensitive', 'text', 'email').dataType()).toBe('text');
    expect(sensitiveMapping('sensitive', 'varchar(11)', 'ssn').dataType()).toBe('varchar(11)');
  });

  it('refuses an unregistered sensitivity class at declaration time', () => {
    expect(() => sensitiveMapping('secret' as 'sensitive', 'text', 'email')).toThrow(
      DrizzleConfigError
    );
  });

  it('refuses a column with no name, because the audit record and the logger need one', () => {
    expect(() => sensitiveMapping('sensitive', 'text', '')).toThrow(DrizzleConfigError);
  });

  it('registers the column name for the logger to recognise', () => {
    sensitiveMapping('sensitive', 'text', 'Email');
    expect(classifiedColumnNames().has('email')).toBe(true);
  });

  describe('plain strings on the write path', () => {
    it('passes one through by default, because a literal predicate is an ordinary query', () => {
      const mapping = sensitiveMapping('sensitive', 'text', 'email');
      expect(mapping.toDriver('a@example.com')).toBe('a@example.com');
    });

    it('refuses one under strictWrites', () => {
      const mapping = sensitiveMapping('sensitive', 'text', 'email', { strictWrites: true });
      expect(() => mapping.toDriver('a@example.com')).toThrow(DrizzleWriteRefusedError);
    });

    it('reports once per path under development mode, not once per row', () => {
      const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
      withDevMode({ enabled: true }, () => {
        const mapping = sensitiveMapping('sensitive', 'text', 'email', { table: 'users' });
        mapping.toDriver('a@example.com');
        mapping.toDriver('b@example.com');
        mapping.toDriver('c@example.com');
      });
      expect(warn).toHaveBeenCalledTimes(1);
      expect(warn.mock.calls[0]?.[0]).toContain('users.email');
      warn.mockRestore();
    });

    it('says nothing at all when development mode is off', () => {
      const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
      sensitiveMapping('sensitive', 'text', 'email').toDriver('a@example.com');
      expect(warn).not.toHaveBeenCalled();
      warn.mockRestore();
    });

    it('routes the report to a caller-supplied hook', () => {
      const seen: unknown[] = [];
      const mapping = sensitiveMapping('sensitive', 'text', 'email', {
        table: 'users',
        onPlainWrite: (info) => seen.push(info),
      });
      mapping.toDriver('a@example.com');
      expect(seen).toEqual([{ path: 'users.email', klass: 'sensitive', received: 'string' }]);
    });
  });

  describe('redaction markers', () => {
    it('refuses a plain string that is already a marker', () => {
      const mapping = sensitiveMapping('credential', 'text', 'token');
      expect(() => mapping.toDriver('[REDACTED:credential]')).toThrow(DrizzleWriteRefusedError);
    });

    it('refuses a marker embedded in a longer string', () => {
      const mapping = sensitiveMapping('credential', 'text', 'token');
      expect(() => mapping.toDriver('Bearer [REDACTED:credential] suffix')).toThrow(
        DrizzleWriteRefusedError
      );
    });

    it('refuses a SensitiveString built from a marker', () => {
      const mapping = sensitiveMapping('credential', 'text', 'token');
      const rewrapped = new SensitiveString('[REDACTED:credential]', 'credential');
      expect(() => mapping.toDriver(rewrapped)).toThrow(DrizzleWriteRefusedError);
    });

    it('refuses to read one back rather than handing on a corrupt value', () => {
      const mapping = sensitiveMapping('credential', 'text', 'token');
      expect(() => mapping.fromDriver('[REDACTED:credential]')).toThrow(DrizzleMarkerReadError);
    });

    it('recognises a marker a custom policy produces, on both directions', () => {
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
      try {
        const mapping = sensitiveMapping('sensitive', 'text', 'email');
        expect(() => mapping.toDriver('<<gone>>')).toThrow(DrizzleWriteRefusedError);
        expect(() => mapping.fromDriver('<<gone>>')).toThrow(DrizzleMarkerReadError);
      } finally {
        resetPolicies();
        resetMarkerCache();
      }
    });
  });

  describe('nullish and non-text values', () => {
    it('passes null through on the write path', () => {
      // Not defensive coding. Drizzle skips the mapping for null everywhere
      // except a prepared statement's placeholder fill, which does send one,
      // and refusing it would make writing NULL to a nullable classified column
      // an error on exactly that path.
      const mapping = sensitiveMapping('sensitive', 'text', 'email');
      expect(mapping.toDriver(null)).toBeNull();
    });

    it('refuses undefined rather than treating it as null', () => {
      // They arrive by the same route and mean different things. A missing
      // placeholder key throws inside Drizzle, so an undefined here is a caller
      // who thought they were passing a value, and writing NULL for it would
      // overwrite a stored credential on the quietest path available.
      const mapping = sensitiveMapping('credential', 'text', 'token');
      expect(() => mapping.toDriver(undefined)).toThrow(DrizzleWriteRefusedError);
      expect(() => mapping.toDriver(undefined)).toThrow(/undefined/);
    });

    it('refuses a value that is neither text nor an instance', () => {
      const mapping = sensitiveMapping('sensitive', 'text', 'email');
      expect(() => mapping.toDriver(42 as unknown as string)).toThrow(DrizzleWriteRefusedError);
      expect(() => mapping.toDriver(new Date() as unknown as string)).toThrow(
        DrizzleWriteRefusedError
      );
    });

    it('refuses a non-string from the driver rather than inventing a value', () => {
      const mapping = sensitiveMapping('sensitive', 'text', 'email');
      expect(() => mapping.fromDriver(Buffer.from('abc'))).toThrow(DrizzleColumnTypeError);
      expect(() => mapping.fromDriver(42)).toThrow(DrizzleColumnTypeError);
      expect(() => mapping.fromDriver(null)).toThrow(DrizzleColumnTypeError);
    });

    it('names what it read back, and never the value', () => {
      const mapping = sensitiveMapping('credential', 'text', 'token', { table: 'users' });
      try {
        mapping.fromDriver(Buffer.from(CANARY));
        expect.unreachable('should have refused');
      } catch (error) {
        expect(error).toBeInstanceOf(DrizzleColumnTypeError);
        const refusal = error as DrizzleColumnTypeError;
        expect(refusal.path).toBe('users.token');
        expect(refusal.received).toBe('object');
        expect(refusal.message).not.toContain(CANARY);
        expect(refusal.code).toBe('DRIZZLE_UNEXPECTED_COLUMN_TYPE');
      }
    });

    it('separates a type mismatch from a corrupted column', () => {
      // Different failures with different fixes: one is a column that is not
      // carrying text, the other is a column an earlier write destroyed.
      const mapping = sensitiveMapping('sensitive', 'text', 'email');
      expect(() => mapping.fromDriver(42)).not.toThrow(DrizzleMarkerReadError);
      expect(() => mapping.fromDriver('[REDACTED:sensitive]')).toThrow(DrizzleMarkerReadError);
    });
  });

  describe('the reveal context', () => {
    it('takes name and reason from the ambient context and tags the column', () => {
      const audits: { ctx: AuditContext | undefined; details: RevealDetails }[] = [];
      const mapping = sensitiveMapping('credential', 'text', 'token', { table: 'users' });
      withRevealContext(
        {
          name: 'checkout',
          reason: 'charging the card',
          tags: { requestId: 'r1' },
          auditReveal: (_value, details, ctx) => audits.push({ ctx, details }),
        },
        () => {
          mapping.toDriver(new SensitiveString(CANARY, 'credential'));
        }
      );
      expect(audits).toHaveLength(1);
      const ctx = audits[0]?.ctx;
      expect(ctx?.name).toBe('checkout');
      expect(ctx?.reason).toBe('charging the card');
      expect(ctx?.tags).toMatchObject({
        requestId: 'r1',
        sink: 'drizzle',
        table: 'users',
        column: 'token',
        klass: 'credential',
        operation: 'unknown',
      });
    });

    it('falls back to a name derived from the column when nothing is ambient', () => {
      const seen: (AuditContext | undefined)[] = [];
      const value = new SensitiveString(CANARY, 'credential');
      const mapping = sensitiveMapping('credential', 'text', 'token', {
        table: 'users',
        onPlainWrite: () => undefined,
      });
      // The audit hook has to come from somewhere, and with no ambient context
      // the value's own reveal is what is observed instead.
      const spy = vi.spyOn(value, 'reveal');
      mapping.toDriver(value);
      seen.push(spy.mock.calls[0]?.[0]);
      expect(seen[0]?.name).toBe('drizzle:users.token');
      expect(seen[0]?.reason).toBe('column write or predicate');
    });

    it('honours explicit name and reason options when nothing is ambient', () => {
      const value = new SensitiveString(CANARY, 'credential');
      const mapping = sensitiveMapping('credential', 'text', 'token', {
        name: 'batch-import',
        reason: 'seeding',
      });
      const spy = vi.spyOn(value, 'reveal');
      mapping.toDriver(value);
      expect((spy.mock.calls[0]?.[0] as AuditContext).name).toBe('batch-import');
    });

    it('refuses a write with no ambient context under strictContext', () => {
      const mapping = sensitiveMapping('credential', 'text', 'token', { strictContext: true });
      expect(() => mapping.toDriver(new SensitiveString(CANARY, 'credential'))).toThrow(
        DrizzleWriteRefusedError
      );
    });

    it('allows one under strictContext when a context is established', () => {
      const mapping = sensitiveMapping('credential', 'text', 'token', { strictContext: true });
      withRevealContext({ name: 'req' }, () => {
        expect(mapping.toDriver(new SensitiveString(CANARY, 'credential'))).toBe(CANARY);
      });
    });
  });
});

describe('classificationOf', () => {
  const columnFor = (klass: 'sensitive' | 'credential', name: string): unknown => {
    const mapping = sensitiveMapping(klass, 'text', name);
    return { name, mapFromDriverValue: mapping.fromDriver, getSQLType: mapping.dataType };
  };

  it('recognises a classified column and reports its class and label', () => {
    expect(classificationOf(columnFor('credential', 'token'))).toEqual({
      klass: 'credential',
      label: 'token',
    });
  });

  it('returns undefined for a plain column', () => {
    expect(classificationOf({ name: 'n', mapFromDriverValue: (v: unknown) => v })).toBeUndefined();
  });

  it('returns undefined for something that is not a column at all', () => {
    expect(classificationOf(undefined)).toBeUndefined();
    expect(classificationOf(null)).toBeUndefined();
    expect(classificationOf('users')).toBeUndefined();
    expect(classificationOf({})).toBeUndefined();
  });

  it('returns undefined rather than throwing for a column whose read side throws', () => {
    expect(
      classificationOf({
        name: 'n',
        mapFromDriverValue: () => {
          throw new Error('nope');
        },
      })
    ).toBeUndefined();
  });

  it('probes with a value that is not a redaction marker', () => {
    // A classified column refuses to read a marker back. If the probe were one,
    // every classified column would look like a broken column instead.
    expect(() => classificationOf(columnFor('sensitive', 'email'))).not.toThrow();
    expect(classificationOf(columnFor('sensitive', 'email'))).toBeDefined();
  });
});
