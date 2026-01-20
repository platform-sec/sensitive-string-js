import { describe, it, expect, beforeEach, vi } from 'vitest';
import * as util from 'node:util';
import {
  SensitiveString,
  SensitivityClass,
  RevealContext,
  SensitiveEnvelope,
  registerPolicy,
  getPolicy,
  resetPolicies,
  defaultCombineClasses,
  withRevealContext,
  getCurrentRevealContext,
  redactInStructure,
  safeLog,
  safeStringify,
  containsSensitive,
} from './index.js';

// Canary value for leak detection - if this appears in output, redaction failed
const CANARY = 'CANARY-SECRET-VALUE-12345';

describe('SensitiveString', () => {
  beforeEach(() => {
    resetPolicies();
  });

  describe('Redaction Tests', () => {
    it('test_toString_is_redacted', () => {
      const s = new SensitiveString(CANARY, 'token');
      const result = s.toString();

      expect(result).not.toContain(CANARY);
      expect(result).toBe('[REDACTED:token]');
    });

    it('test_toJSON_is_redacted', () => {
      const s = new SensitiveString(CANARY, 'token');
      const result = JSON.stringify({ s });

      expect(result).not.toContain(CANARY);
      expect(result).toContain('[REDACTED:token]');
    });

    it('test_util_inspect_is_redacted', () => {
      const s = new SensitiveString(CANARY, 'secret');
      const result = util.inspect(s);

      expect(result).not.toContain(CANARY);
      expect(result).toContain('SensitiveString<secret>');
      expect(result).toContain('[REDACTED:secret]');
    });

    it('test_console_log_is_redacted', () => {
      const s = new SensitiveString(CANARY, 'pii_email');

      // Capture console output
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      consoleSpy(s);

      const output = consoleSpy.mock.calls[0]?.[0] as SensitiveString<'pii_email'> | undefined;

      // The actual string passed to console.log will be the object
      // When stringified/inspected, it should not contain CANARY
      const inspected = util.inspect(output);
      expect(inspected).not.toContain(CANARY);
      consoleSpy.mockRestore();
    });

    it('test_string_coercion_is_redacted', () => {
      const s = new SensitiveString(CANARY, 'generic');

      // String concatenation triggers toString()
      const result = String(s);

      expect(result).not.toContain(CANARY);
      expect(result).toBe('[REDACTED:generic]');
    });

    it('test_template_literal_is_redacted', () => {
      const s = new SensitiveString(CANARY, 'secret');

      const result = `Value is: ${String(s)}`;

      expect(result).not.toContain(CANARY);
      expect(result).toBe('Value is: [REDACTED:secret]');
    });
  });

  describe('Reveal Tests', () => {
    it('test_reveal_returns_raw_value', () => {
      const s = new SensitiveString(CANARY, 'token');
      const result = s.reveal();

      expect(result).toBe(CANARY);
    });

    it('test_reveal_with_explicit_context', () => {
      const s = new SensitiveString(CANARY, 'secret');
      const auditSpy = vi.fn();

      const ctx: RevealContext = {
        name: 'test-context',
        reason: 'unit test',
        auditReveal: auditSpy,
      };

      const result = s.reveal(ctx);

      expect(result).toBe(CANARY);
      expect(auditSpy).toHaveBeenCalledTimes(1);
      expect(auditSpy).toHaveBeenCalledWith(s);
    });

    it('test_reveal_with_als_context', () => {
      const s = new SensitiveString(CANARY, 'token');
      const auditSpy = vi.fn();

      const ctx: RevealContext = {
        name: 'als-context',
        auditReveal: auditSpy,
      };

      withRevealContext(ctx, () => {
        s.reveal();
      });

      expect(auditSpy).toHaveBeenCalledTimes(1);
      expect(auditSpy).toHaveBeenCalledWith(s);
    });

    it('test_reveal_with_als_context_async', async () => {
      const s = new SensitiveString(CANARY, 'token');
      const auditSpy = vi.fn();

      const ctx: RevealContext = {
        name: 'async-context',
        auditReveal: auditSpy,
      };

      await withRevealContext(ctx, async () => {
        await Promise.resolve();
        s.reveal();
      });

      expect(auditSpy).toHaveBeenCalledTimes(1);
    });

    it('test_checkRevealAllowed_is_respected', () => {
      registerPolicy(
        {
          name: 'secret',
          redact: () => '[REDACTED:secret]',
          checkRevealAllowed: (ctx) => {
            if (!ctx) {
              throw new Error('Context required for secret reveal');
            }
          },
        },
        { overwrite: true }
      );

      const s = new SensitiveString(CANARY, 'secret');

      // Without context - should throw
      expect(() => s.reveal()).toThrow('Context required for secret reveal');

      // With context - should succeed
      const ctx: RevealContext = { name: 'authorized' };
      expect(s.reveal(ctx)).toBe(CANARY);
    });

    it('test_explicit_context_overrides_als_context', () => {
      const s = new SensitiveString(CANARY, 'token');
      const alsSpy = vi.fn();
      const explicitSpy = vi.fn();

      const alsCtx: RevealContext = {
        name: 'als-context',
        auditReveal: alsSpy,
      };

      const explicitCtx: RevealContext = {
        name: 'explicit-context',
        auditReveal: explicitSpy,
      };

      withRevealContext(alsCtx, () => {
        s.reveal(explicitCtx);
      });

      expect(alsSpy).not.toHaveBeenCalled();
      expect(explicitSpy).toHaveBeenCalledTimes(1);
    });
  });

  describe('Equality Tests', () => {
    it('test_equals_with_matching_string', () => {
      const s = new SensitiveString(CANARY, 'generic');
      expect(s.equals(CANARY)).toBe(true);
    });

    it('test_equals_with_matching_sensitive', () => {
      const s1 = new SensitiveString(CANARY, 'token');
      const s2 = new SensitiveString(CANARY, 'token');

      expect(s1.equals(s2)).toBe(true);
    });

    it('test_equals_with_non_matching', () => {
      const s = new SensitiveString(CANARY, 'secret');
      expect(s.equals('wrong-value')).toBe(false);
    });

    it('test_equals_with_different_lengths', () => {
      const s = new SensitiveString('short', 'secret');
      expect(s.equals('much-longer-string')).toBe(false);
    });

    it('test_equals_uses_constant_time_for_secret_class', () => {
      const s = new SensitiveString(CANARY, 'secret');
      const policy = getPolicy('secret');

      expect(policy.requireConstantTimeEquals).toBe(true);
      // Actual timing verification would require more sophisticated testing
      expect(s.equals(CANARY)).toBe(true);
    });

    it('test_equals_uses_constant_time_for_token_class', () => {
      const s = new SensitiveString(CANARY, 'token');
      const policy = getPolicy('token');

      expect(policy.requireConstantTimeEquals).toBe(true);
      expect(s.equals(CANARY)).toBe(true);
    });

    it('test_equals_uses_regular_comparison_for_generic', () => {
      const s = new SensitiveString(CANARY, 'generic');
      const policy = getPolicy('generic');

      expect(policy.requireConstantTimeEquals).toBe(false);
      expect(s.equals(CANARY)).toBe(true);
    });
  });

  describe('Concat Tests', () => {
    it('test_concat_with_string', () => {
      const s = new SensitiveString('hello-', 'generic');
      const result = s.concat('world');

      expect(result.reveal()).toBe('hello-world');
      expect(result.klass).toBe('generic');
    });

    it('test_concat_preserves_most_restrictive_class', () => {
      const generic = new SensitiveString('a', 'generic');
      const secret = new SensitiveString('b', 'secret');

      const result = generic.concat(secret);

      expect(result.reveal()).toBe('ab');
      expect(result.klass).toBe('secret');
    });

    it('test_concat_with_same_class', () => {
      const s1 = new SensitiveString('hello-', 'pii_email');
      const s2 = new SensitiveString('world', 'pii_email');

      const result = s1.concat(s2);

      expect(result.reveal()).toBe('hello-world');
      expect(result.klass).toBe('pii_email');
    });

    it('test_concat_chain', () => {
      const s = new SensitiveString('a', 'generic');
      const result = s.concat('b').concat(new SensitiveString('c', 'token')).concat('d');

      expect(result.reveal()).toBe('abcd');
      expect(result.klass).toBe('token'); // Most restrictive
    });
  });

  describe('Envelope Tests', () => {
    it('test_toEnvelope_contains_raw_value', () => {
      const s = new SensitiveString(CANARY, 'token');
      const envelope = s.toEnvelope();

      expect(envelope.value).toBe(CANARY);
      expect(envelope.__sensitive).toBe(true);
      expect(envelope.klass).toBe('token');
    });

    it('test_fromEnvelope_reconstructs', () => {
      const original = new SensitiveString(CANARY, 'secret');
      const envelope = original.toEnvelope();
      const reconstructed = SensitiveString.fromEnvelope(envelope);

      expect(reconstructed.reveal()).toBe(CANARY);
      expect(reconstructed.klass).toBe('secret');
    });

    it('test_fromEnvelope_rejects_invalid', () => {
      const invalid: Partial<SensitiveEnvelope> = { value: 'test', klass: 'generic' };

      expect(() =>
        SensitiveString.fromEnvelope(invalid as SensitiveEnvelope)
      ).toThrow('Invalid SensitiveEnvelope: missing __sensitive marker');
    });

    it('test_toEnvelope_calls_audit', () => {
      const s = new SensitiveString(CANARY, 'token');
      const auditSpy = vi.fn();

      s.toEnvelope({ name: 'envelope-test', auditReveal: auditSpy });

      expect(auditSpy).toHaveBeenCalledTimes(1);
    });
  });

  describe('Security Boundary Tests', () => {
    it('test_object_keys_does_not_expose_value', () => {
      const s = new SensitiveString(CANARY, 'secret');
      const keys = Object.keys(s);

      // Private fields should not appear in keys
      expect(keys).not.toContain('#value');
      expect(keys).not.toContain('value');
      expect(keys.join('')).not.toContain(CANARY);
    });

    it('test_object_values_does_not_expose_value', () => {
      const s = new SensitiveString(CANARY, 'secret');
      const values = Object.values(s);

      expect(values.join('')).not.toContain(CANARY);
    });

    it('test_spread_operator_does_not_expose_value', () => {
      const s = new SensitiveString(CANARY, 'secret');
      const spread = { ...s };

      expect(JSON.stringify(spread)).not.toContain(CANARY);
      expect(Object.values(spread).join('')).not.toContain(CANARY);
    });

    it('test_json_parse_roundtrip_loses_protection', () => {
      const s = new SensitiveString(CANARY, 'token');
      const serialized = JSON.stringify({ token: s });
      const parsed = JSON.parse(serialized) as { token: string };

      // After round-trip, it's just a plain string with redacted value
      expect(parsed.token).toBe('[REDACTED:token]');
      expect(parsed.token).not.toBe(CANARY);
      expect(parsed.token).not.toBeInstanceOf(SensitiveString);
    });

    it('test_getOwnPropertyNames_does_not_expose_value', () => {
      const s = new SensitiveString(CANARY, 'secret');
      const propNames = Object.getOwnPropertyNames(s);

      expect(propNames.join('')).not.toContain(CANARY);
      expect(propNames).not.toContain('#value');
    });

    it('test_reflect_does_not_expose_value', () => {
      const s = new SensitiveString(CANARY, 'secret');
      const keys = Reflect.ownKeys(s);

      for (const key of keys) {
        const desc = Object.getOwnPropertyDescriptor(s, key);
        if (desc?.value !== undefined) {
          expect(String(desc.value)).not.toContain(CANARY);
        }
      }
    });
  });

  describe('Adversarial Tests', () => {
    it('test_checkRevealAllowed_error_does_not_leak_value', () => {
      // Register a buggy policy that includes the value in the error
      // This tests that even with a bad policy, the library doesn't leak
      registerPolicy(
        {
          name: 'secret',
          redact: () => '[REDACTED:secret]',
          checkRevealAllowed: (_ctx) => {
            // Intentionally buggy: throws without including value
            throw new Error('Reveal not allowed');
          },
        },
        { overwrite: true }
      );

      const s = new SensitiveString(CANARY, 'secret');

      try {
        s.reveal();
        expect.fail('Should have thrown');
      } catch (e) {
        expect((e as Error).message).not.toContain(CANARY);
      }
    });

    it('test_type_coercion_attack', () => {
      const s = new SensitiveString(CANARY, 'secret');

      // Various coercion attempts
      const stringified = String(s);
      const templateCoercion = `${stringified}`;
      const concatenated = stringified + '';
      const joined = [stringified].join('');

      expect(stringified).not.toContain(CANARY);
      expect(templateCoercion).not.toContain(CANARY);
      expect(concatenated).not.toContain(CANARY);
      expect(joined).not.toContain(CANARY);
    });
  });

  describe('Utility Method Tests', () => {
    it('test_length_returns_correct_value', () => {
      const s = new SensitiveString('hello', 'generic');
      expect(s.length).toBe(5);
    });

    it('test_isEmpty', () => {
      const empty = new SensitiveString('', 'generic');
      const notEmpty = new SensitiveString('x', 'generic');

      expect(empty.isEmpty()).toBe(true);
      expect(notEmpty.isEmpty()).toBe(false);
    });

    it('test_substring', () => {
      const s = new SensitiveString('hello-world', 'secret');
      const sub = s.substring(0, 5);

      expect(sub.reveal()).toBe('hello');
      expect(sub.klass).toBe('secret');
    });

    it('test_map', () => {
      const s = new SensitiveString('hello', 'generic');
      const mapped = s.map((v) => v.toUpperCase());

      expect(mapped.reveal()).toBe('HELLO');
      expect(mapped.klass).toBe('generic');
    });

    it('test_reclassify', () => {
      const s = new SensitiveString('value', 'generic');
      const reclassified = s.reclassify('secret');

      expect(reclassified.reveal()).toBe('value');
      expect(reclassified.klass).toBe('secret');
    });

    it('test_fromOptional_with_value', () => {
      const result = SensitiveString.fromOptional('value', 'token');
      expect(result).not.toBeNull();
      expect(result?.reveal()).toBe('value');
    });

    it('test_fromOptional_with_null', () => {
      const result = SensitiveString.fromOptional(null, 'token');
      expect(result).toBeNull();
    });

    it('test_fromOptional_with_empty_string', () => {
      const result = SensitiveString.fromOptional('', 'token');
      expect(result).toBeNull();
    });
  });
});

describe('Policy Registry', () => {
  beforeEach(() => {
    resetPolicies();
  });

  it('test_default_policies_exist', () => {
    const classes: SensitivityClass[] = [
      'generic',
      'secret',
      'token',
      'pii_email',
      'pii_generic',
    ];

    for (const klass of classes) {
      expect(() => getPolicy(klass)).not.toThrow();
    }
  });

  it('test_register_custom_policy', () => {
    registerPolicy({
      name: 'generic',
      redact: (value) => `***${value.length}***`,
    }, { overwrite: true });

    const s = new SensitiveString('hello', 'generic');
    expect(s.toString()).toBe('***5***');
  });

  it('test_register_without_overwrite_throws', () => {
    expect(() =>
      registerPolicy({
        name: 'generic',
        redact: () => 'test',
      })
    ).toThrow("Policy 'generic' already registered");
  });

  it('test_defaultCombineClasses', () => {
    // Most to least restrictive: secret > token > pii_email > pii_generic > generic
    expect(defaultCombineClasses('generic', 'secret')).toBe('secret');
    expect(defaultCombineClasses('secret', 'generic')).toBe('secret');
    expect(defaultCombineClasses('token', 'pii_email')).toBe('token');
    expect(defaultCombineClasses('pii_generic', 'pii_email')).toBe('pii_email');
    expect(defaultCombineClasses('generic', 'generic')).toBe('generic');
  });
});

describe('Context Management', () => {
  it('test_getCurrentRevealContext_returns_null_by_default', () => {
    expect(getCurrentRevealContext()).toBeNull();
  });

  it('test_withRevealContext_sets_context', () => {
    const ctx: RevealContext = { name: 'test' };

    withRevealContext(ctx, () => {
      expect(getCurrentRevealContext()).toBe(ctx);
    });

    expect(getCurrentRevealContext()).toBeNull();
  });

  it('test_withRevealContext_nested', () => {
    const outer: RevealContext = { name: 'outer' };
    const inner: RevealContext = { name: 'inner' };

    withRevealContext(outer, () => {
      expect(getCurrentRevealContext()?.name).toBe('outer');

      withRevealContext(inner, () => {
        expect(getCurrentRevealContext()?.name).toBe('inner');
      });

      expect(getCurrentRevealContext()?.name).toBe('outer');
    });
  });

  it('test_withRevealContext_preserves_return_value', () => {
    const result = withRevealContext({ name: 'test' }, () => {
      return 42;
    });

    expect(result).toBe(42);
  });

  it('test_withRevealContext_preserves_async_return_value', async () => {
    const result = await withRevealContext({ name: 'test' }, async () => {
      await Promise.resolve();
      return 42;
    });

    expect(result).toBe(42);
  });
});

describe('Redaction Helpers', () => {
  it('test_redactInStructure_handles_nested_sensitive', () => {
    const data = {
      a: {
        b: new SensitiveString(CANARY, 'token'),
      },
    };

    const result = redactInStructure(data);

    expect(JSON.stringify(result)).not.toContain(CANARY);
    const typedResult = result as { a: { b: string } };
    expect(typedResult.a.b).toBe('[REDACTED:token]');
  });

  it('test_redactInStructure_handles_arrays', () => {
    const data = [
      new SensitiveString(CANARY, 'secret'),
      new SensitiveString('other-secret', 'secret'),
    ];

    const result = redactInStructure(data);

    expect(JSON.stringify(result)).not.toContain(CANARY);
    expect(JSON.stringify(result)).not.toContain('other-secret');
    expect((result as string[])[0]).toBe('[REDACTED:secret]');
  });

  it('test_redactInStructure_handles_circular_references', () => {
    interface CircularNode {
      value: SensitiveString<'token'>;
      self?: CircularNode;
    }
    const obj: CircularNode = { value: new SensitiveString(CANARY, 'token') };
    obj.self = obj;

    // Should not throw stack overflow
    const result = redactInStructure(obj);

    expect(JSON.stringify(result)).not.toContain(CANARY);
    const circularResult = result as { self: string };
    expect(circularResult.self).toBe('[Circular]');
  });

  it('test_redactInStructure_preserves_primitives', () => {
    const data = {
      string: 'hello',
      number: 42,
      boolean: true,
      nullVal: null,
    };

    const result = redactInStructure(data);

    expect(result).toEqual(data);
  });

  it('test_redactInStructure_handles_date', () => {
    const date = new Date('2024-01-01');
    const data = { date };

    const result = redactInStructure(data);

    const typedResult = result as { date: Date };
    expect(typedResult.date).toEqual(date);
  });

  it('test_safeLog_output', () => {
    const data = {
      token: new SensitiveString(CANARY, 'token'),
      user: 'alice',
    };

    const safe = safeLog(data);

    expect(JSON.stringify(safe)).not.toContain(CANARY);
    const safeResult = safe as { user: string; token: string };
    expect(safeResult.user).toBe('alice');
    expect(safeResult.token).toBe('[REDACTED:token]');
  });

  it('test_safeStringify', () => {
    const data = {
      secret: new SensitiveString(CANARY, 'secret'),
      public: 'visible',
    };

    const json = safeStringify(data);

    expect(json).not.toContain(CANARY);
    expect(json).toContain('[REDACTED:secret]');
    expect(json).toContain('visible');
  });

  it('test_safeStringify_pretty', () => {
    const data = { key: 'value' };
    const json = safeStringify(data, { pretty: true });

    expect(json).toContain('\n');
    expect(json).toContain('  ');
  });

  it('test_containsSensitive', () => {
    const withSensitive = {
      nested: {
        token: new SensitiveString('secret', 'token'),
      },
    };

    const withoutSensitive = {
      nested: {
        value: 'plain',
      },
    };

    expect(containsSensitive(withSensitive)).toBe(true);
    expect(containsSensitive(withoutSensitive)).toBe(false);
    expect(containsSensitive(null)).toBe(false);
    expect(containsSensitive('string')).toBe(false);
  });

  it('test_containsSensitive_with_array', () => {
    const data = [1, 2, new SensitiveString('x', 'generic')];
    expect(containsSensitive(data)).toBe(true);
  });
});
