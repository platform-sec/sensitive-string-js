import { registerPolicy, resetPolicies } from '@platform-sec/sensitive-string-core';
import { afterEach, describe, expect, it } from 'vitest';

import { clientKey, normalizeConfig, normalizeModelFields } from './config.js';
import { PrismaConfigError } from './errors.js';

describe('clientKey', () => {
  it('lowercases only the first character, matching Prisma', () => {
    expect(clientKey('User')).toBe('user');
    expect(clientKey('PaymentMethod')).toBe('paymentMethod');
    expect(clientKey('URLMapping')).toBe('uRLMapping');
  });

  it('is idempotent, so a configuration already in client casing still works', () => {
    expect(clientKey(clientKey('PaymentMethod'))).toBe('paymentMethod');
    expect(clientKey('user')).toBe('user');
  });

  it('leaves a name with no leading letter alone', () => {
    expect(clientKey('')).toBe('');
    expect(clientKey('_Internal')).toBe('_Internal');
  });
});

describe('normalizeConfig', () => {
  // TEST-PRISMA-U001
  it('accepts both spec forms and fills in the defaults', () => {
    const config = normalizeConfig({
      models: {
        User: {
          email: 'sensitive',
          passwordHash: 'credential',
          ssn: { klass: 'sensitive', label: 'ssn_us' },
        },
      },
    });

    const user = config.models.get('user')?.fields;
    expect(user?.get('email')).toEqual({
      klass: 'sensitive',
      label: 'email',
      nullable: false,
      list: false,
    });
    expect(user?.get('passwordHash')?.klass).toBe('credential');
    expect(user?.get('ssn')?.label).toBe('ssn_us');
  });

  it('keeps the schema name alongside the client key, for refusal messages', () => {
    const config = normalizeConfig({ models: { PaymentMethod: { cardNumber: 'credential' } } });
    expect(config.models.get('paymentMethod')?.name).toBe('PaymentMethod');
  });

  it('keys models by the client property name', () => {
    const config = normalizeConfig({
      models: { PaymentMethod: { cardNumber: 'credential' } },
    });

    expect([...config.models.keys()]).toEqual(['paymentMethod']);
  });

  // INV-PRISMA-021: the lookup a compute closure is built from is a Map, not a scan.
  it('indexes fields for O(1) lookup', () => {
    const config = normalizeConfig({ models: { User: { email: 'sensitive' } } });

    expect(config.models).toBeInstanceOf(Map);
    expect(config.models.get('user')?.fields).toBeInstanceOf(Map);
  });

  it('carries the shape flags through', () => {
    const config = normalizeConfig({
      models: {
        User: {
          nickname: { klass: 'sensitive', nullable: true },
          recoveryCodes: { klass: 'credential', list: true },
        },
      },
    });

    expect(config.models.get('user')?.fields.get('nickname')?.nullable).toBe(true);
    expect(config.models.get('user')?.fields.get('recoveryCodes')?.list).toBe(true);
  });

  it('normalizes writeContext and omits absent keys', () => {
    expect(normalizeConfig({ models: {} }).writeContext).toEqual({});
    expect(normalizeConfig({ models: {}, writeContext: { name: 'w' } }).writeContext).toEqual({
      name: 'w',
    });
  });

  it('accepts an empty configuration', () => {
    expect(normalizeConfig({ models: {} }).models.size).toBe(0);
    expect(normalizeConfig({ models: { User: {} } }).models.get('user')?.fields.size).toBe(0);
  });

  describe('refusals', () => {
    // TEST-PRISMA-U002 / TEST-PRISMA-S007
    it('rejects a sensitivity class with no registered policy', () => {
      expect(() => normalizeConfig({ models: { User: { email: 'secert' as never } } })).toThrow(
        PrismaConfigError
      );
      expect(() => normalizeConfig({ models: { User: { email: 'secert' as never } } })).toThrow(
        /User\.email names sensitivity class 'secert', which is not registered/
      );
    });

    it('rejects an unregistered class in the object form too', () => {
      expect(() =>
        normalizeConfig({ models: { User: { email: { klass: 'nope' as never } } } })
      ).toThrow(PrismaConfigError);
    });

    it.each([
      ['a number', 42],
      ['null', null],
      ['an array', ['sensitive']],
      ['a boolean', true],
    ])('rejects %s as a field spec', (_label, spec) => {
      expect(() => normalizeConfig({ models: { User: { email: spec as never } } })).toThrow(
        PrismaConfigError
      );
    });

    it('names an unknown key rather than ignoring it', () => {
      expect(() =>
        normalizeConfig({
          models: { User: { email: { klass: 'sensitive', nulable: true } as never } },
        })
      ).toThrow(/unknown key 'nulable'/);
    });

    it('rejects a non-string label and non-boolean flags', () => {
      expect(() =>
        normalizeConfig({ models: { User: { email: { klass: 'sensitive', label: 1 } as never } } })
      ).toThrow(/non-string 'label'/);
      expect(() =>
        normalizeConfig({
          models: { User: { email: { klass: 'sensitive', nullable: 'yes' } as never } },
        })
      ).toThrow(/non-boolean 'nullable'/);
      expect(() =>
        normalizeConfig({ models: { User: { email: { klass: 'sensitive', list: 1 } as never } } })
      ).toThrow(/non-boolean 'list'/);
    });

    it('rejects a missing klass', () => {
      expect(() =>
        normalizeConfig({ models: { User: { email: { label: 'x' } as never } } })
      ).toThrow(/is missing 'klass'/);
    });

    it('rejects a malformed top level', () => {
      expect(() => normalizeConfig(null as never)).toThrow(/expects a configuration object/);
      expect(() => normalizeConfig({} as never)).toThrow(/expects 'models' to be an object/);
      expect(() => normalizeConfig({ models: { User: 'sensitive' as never } })).toThrow(
        /must map field names/
      );
    });

    // Prisma matches a `result` key against no model and ignores it, so this
    // would otherwise classify nothing and report nothing.
    it('rejects an empty model or field name', () => {
      expect(() => normalizeConfig({ models: { '': { email: 'sensitive' } } })).toThrow(
        /empty name/
      );
      expect(() => normalizeConfig({ models: { User: { '': 'sensitive' } } })).toThrow(
        /field with an empty name/
      );
    });

    it('rejects a malformed writeContext', () => {
      expect(() => normalizeConfig({ models: {}, writeContext: 'prisma' as never })).toThrow(
        /'writeContext' must be an object/
      );
      expect(() => normalizeConfig({ models: {}, writeContext: { name: 1 } as never })).toThrow(
        /'writeContext.name' must be a string/
      );
      expect(() => normalizeConfig({ models: {}, writeContext: { reason: 1 } as never })).toThrow(
        /'writeContext.reason' must be a string/
      );
    });

    // Two casings of one model silently drop a field set, which is the kind of
    // gap this package exists to prevent.
    it('rejects the same model configured twice in different casing', () => {
      expect(() =>
        normalizeConfig({
          models: { User: { email: 'sensitive' }, user: { passwordHash: 'credential' } },
        })
      ).toThrow(/is configured twice/);
    });

    it('carries a stable code on every refusal', () => {
      try {
        normalizeConfig({ models: { User: { email: 'secert' as never } } });
        expect.unreachable('should have thrown');
      } catch (error) {
        expect((error as PrismaConfigError).code).toBe('PRISMA_INVALID_CONFIG');
      }
    });
  });

  describe('custom policies', () => {
    afterEach(() => {
      resetPolicies();
    });

    it('accepts a class registered before the extension is built', () => {
      registerPolicy({
        name: 'pii' as never,
        redact: () => '[REDACTED:pii]',
        requireContext: false,
        constantTimeCompare: false,
        allowPersistPlain: false,
      } as never);

      const config = normalizeConfig({ models: { User: { email: 'pii' as never } } });
      expect(config.models.get('user')?.fields.get('email')?.klass).toBe('pii');
    });
  });
});

describe('normalizeModelFields', () => {
  it('validates the same shapes the extension configuration does', () => {
    expect(() => normalizeModelFields('wrapRows', { email: 'secert' as never })).toThrow(
      PrismaConfigError
    );
    expect(
      normalizeModelFields('wrapRows', { email: 'sensitive' }).fields.get('email')?.label
    ).toBe('email');
  });

  it('rejects a non-object field map', () => {
    expect(() => normalizeModelFields('wrapRows', null as never)).toThrow(
      /must map field names to sensitivity classes/
    );
  });
});
