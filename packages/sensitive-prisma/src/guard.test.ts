import {
  SensitiveString,
  registerPolicy,
  resetPolicies,
} from '@platform-sec/sensitive-string-core';
import { afterEach, describe, expect, it } from 'vitest';

import { PrismaUnwrappedValueError } from './errors.js';
import { assertNoUnwrapped, findUnwrapped, isUnwrappedResidue } from './guard.js';

const CANARY = 'LEAKED_SECRET_abc123xyz';

/**
 * Reproduce Prisma's `deepCloneValue` for the case that matters.
 *
 * A `for...in` copy into a fresh object is exactly what it does for a class it
 * does not recognise, which is every class but `Decimal`, `Date` and a typed
 * array. Using the real thing here would mean booting a client for a unit test;
 * the integration suite does that and asserts the same behaviour end to end.
 */
function flatten(value: object): Record<string, unknown> {
  const copy: Record<string, unknown> = {};
  for (const key in value) copy[key] = (value as Record<string, unknown>)[key];
  return copy;
}

describe('isUnwrappedResidue', () => {
  it('recognises what is left of a SensitiveString', () => {
    expect(isUnwrappedResidue(flatten(new SensitiveString(CANARY, 'sensitive')))).toBe(true);
    expect(isUnwrappedResidue(flatten(new SensitiveString(CANARY, 'credential', 'pw')))).toBe(true);
  });

  it('recognises the residue of a derived value', () => {
    const derived = new SensitiveString('abcdef', 'sensitive').substring(1, 3);
    expect(isUnwrappedResidue(flatten(derived))).toBe(true);
  });

  it('does not fire on a live instance, which the extension unwraps elsewhere', () => {
    expect(isUnwrappedResidue(new SensitiveString(CANARY, 'sensitive'))).toBe(false);
  });

  it.each([
    ['a primitive', 'sensitive'],
    ['null', null],
    ['an array', [{ klass: 'sensitive', label: undefined }]],
    ['an extra key', { klass: 'sensitive', label: 'x', extra: 1 }],
    ['a missing key', { klass: 'sensitive' }],
    ['a different key', { klass: 'sensitive', name: 'x' }],
    ['an unregistered class', { klass: 'not-a-class', label: 'x' }],
    ['a non-string class', { klass: 7, label: 'x' }],
    ['a non-string label', { klass: 'sensitive', label: 7 }],
    ['a Date', new Date()],
  ])('does not fire on %s', (_label, value) => {
    expect(isUnwrappedResidue(value)).toBe(false);
  });

  it('does not fire on an object with a prototype', () => {
    class Shaped {
      klass = 'sensitive';
      label: string | undefined = 'x';
    }
    expect(isUnwrappedResidue(new Shaped())).toBe(false);
  });

  describe('custom classes', () => {
    afterEach(() => {
      resetPolicies();
    });

    it('follows the policy registry rather than a hardcoded list', () => {
      expect(isUnwrappedResidue({ klass: 'pii', label: 'x' })).toBe(false);

      registerPolicy({
        name: 'pii' as never,
        redact: () => '[REDACTED:pii]',
        requireContext: false,
        constantTimeCompare: false,
        allowPersistPlain: false,
      } as never);

      expect(isUnwrappedResidue({ klass: 'pii', label: 'x' })).toBe(true);
    });
  });
});

describe('findUnwrapped', () => {
  it('reports the argument path of the first residue', () => {
    const args = {
      where: { id: 1 },
      data: { name: 'A', passwordHash: flatten(new SensitiveString(CANARY, 'credential', 'pw')) },
    };

    expect(findUnwrapped(args)).toEqual({
      path: 'data.passwordHash',
      residue: { klass: 'credential', label: 'pw' },
    });
  });

  it('descends into arrays and reports the index', () => {
    const args = {
      data: [{ email: 'a' }, { email: flatten(new SensitiveString(CANARY, 'sensitive')) }],
    };

    expect(findUnwrapped(args)?.path).toBe('data.1.email');
  });

  it('descends into a nested write', () => {
    const args = {
      data: { posts: { create: [{ secret: flatten(new SensitiveString(CANARY, 'credential')) }] } },
    };

    expect(findUnwrapped(args)?.path).toBe('data.posts.create.0.secret');
  });

  it('returns undefined for clean arguments', () => {
    expect(findUnwrapped({ data: { name: 'A' }, include: { posts: true } })).toBeUndefined();
    expect(findUnwrapped(undefined)).toBeUndefined();
    expect(findUnwrapped('text')).toBeUndefined();
  });

  it('does not descend into a class instance', () => {
    class Holder {
      constructor(readonly inner: Record<string, unknown>) {}
    }
    const args = {
      data: { amount: new Holder(flatten(new SensitiveString(CANARY, 'sensitive'))) },
    };

    expect(findUnwrapped(args)).toBeUndefined();
  });

  it('terminates on a cycle', () => {
    const args: Record<string, unknown> = { data: {} };
    args['self'] = args;

    expect(() => findUnwrapped(args)).not.toThrow();
  });
});

describe('assertNoUnwrapped', () => {
  it('passes clean arguments through', () => {
    expect(() =>
      assertNoUnwrapped({ data: { name: 'A' } }, { model: 'User', operation: 'create' })
    ).not.toThrow();
  });

  it('names the model, the operation and the path', () => {
    const args = { data: { passwordHash: flatten(new SensitiveString(CANARY, 'credential')) } };

    expect(() => assertNoUnwrapped(args, { model: 'User', operation: 'create' })).toThrow(
      PrismaUnwrappedValueError
    );
    expect(() => assertNoUnwrapped(args, { model: 'User', operation: 'create' })).toThrow(
      /create on User received a SensitiveString at 'data\.passwordHash'/
    );
  });

  it('points at the fix', () => {
    const args = { data: { passwordHash: flatten(new SensitiveString(CANARY, 'credential')) } };

    expect(() => assertNoUnwrapped(args, { model: 'User', operation: 'create' })).toThrow(
      /sensitiveInput\(\) at the call site/
    );
  });

  it('describes a raw operation with no model', () => {
    const args = ['SELECT ?', flatten(new SensitiveString(CANARY, 'credential'))];

    expect(() =>
      assertNoUnwrapped(args, { model: undefined, operation: '$queryRawUnsafe' })
    ).toThrow(/\$queryRawUnsafe received a SensitiveString at '1'/);
  });

  it('carries a stable code and the class, and never the value', () => {
    const args = {
      data: { passwordHash: flatten(new SensitiveString(CANARY, 'credential', 'pw')) },
    };

    try {
      assertNoUnwrapped(args, { model: 'User', operation: 'create' });
      expect.unreachable('should have thrown');
    } catch (error) {
      const refusal = error as PrismaUnwrappedValueError;
      expect(refusal.code).toBe('PRISMA_UNWRAPPED_VALUE');
      expect(refusal.klass).toBe('credential');
      expect(refusal.path).toBe('data.passwordHash');
      expect(`${refusal.message} ${String(refusal.stack)}`).not.toContain(CANARY);
    }
  });
});
