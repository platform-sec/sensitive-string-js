import { describe, it, expect } from 'vitest';
import { SensitiveString, zConditionalSensitive } from './index.js';

const CANARY = 'CANARY-CONDITIONAL-VALUE-91';

const Setting = zConditionalSensitive({
  discriminator: 'type',
  valueField: 'value',
  conditions: {
    secret: { klass: 'credential', label: 'secret_data' },
    private: { klass: 'sensitive', label: 'private_data' },
    public: null,
  },
});

describe('zConditionalSensitive', () => {
  it('test_conditional_wraps_the_credential_case', () => {
    const result = Setting.parse({ type: 'secret', value: CANARY });

    expect(result.value).toBeInstanceOf(SensitiveString);
    if (result.type === 'secret') {
      expect(result.value.klass).toBe('credential');
      expect(result.value.label).toBe('secret_data');
    }
  });

  it('test_conditional_wraps_the_sensitive_case', () => {
    const result = Setting.parse({ type: 'private', value: CANARY });

    if (result.type === 'private') {
      expect(result.value.klass).toBe('sensitive');
    }
  });

  it('test_conditional_leaves_the_null_case_a_plain_string', () => {
    const result = Setting.parse({ type: 'public', value: 'motd' });

    expect(result.value).toBe('motd');
    expect(result.value).not.toBeInstanceOf(SensitiveString);
  });

  it('test_conditional_redacts_the_wrapped_case_in_json', () => {
    const json = JSON.stringify(Setting.parse({ type: 'secret', value: CANARY }));

    expect(json).not.toContain(CANARY);
    expect(json).toContain('[REDACTED:credential]');
  });

  it('test_conditional_rejects_an_unknown_discriminator', () => {
    const result = Setting.safeParse({ type: 'other', value: CANARY });

    expect(result.success).toBe(false);
    if (!result.success) {
      // v4 folded `invalid_union_discriminator` into `invalid_union`, carrying
      // a `note` instead of its own code. Neither shape leaks.
      expect(result.error.issues[0]?.code).toBe('invalid_union');
      expect(result.error.issues[0]).toMatchObject({ note: 'No matching discriminator' });
      // The discriminator is rejected before the value is looked at.
      expect(JSON.stringify(result.error.issues)).not.toContain(CANARY);
    }
  });

  it('test_conditional_rejects_a_non_string_value', () => {
    expect(Setting.safeParse({ type: 'secret', value: 7 }).success).toBe(false);
  });

  it('test_conditional_requires_at_least_one_condition', () => {
    expect(() =>
      zConditionalSensitive({ discriminator: 'type', valueField: 'value', conditions: {} })
    ).toThrow(TypeError);
  });

  it('test_conditional_rejects_a_discriminator_that_is_also_the_value_field', () => {
    // Both names would become keys of one object literal, and the value field
    // would vanish without a word.
    expect(() =>
      zConditionalSensitive({
        discriminator: 'value',
        valueField: 'value',
        conditions: { secret: { klass: 'credential' } },
      })
    ).toThrow(TypeError);
  });

  it('test_conditional_honours_custom_field_names', () => {
    const schema = zConditionalSensitive({
      discriminator: 'kind',
      valueField: 'payload',
      conditions: { token: { klass: 'credential' } },
    });

    const result = schema.parse({ kind: 'token', payload: CANARY });

    expect(result.payload).toBeInstanceOf(SensitiveString);
  });
});
