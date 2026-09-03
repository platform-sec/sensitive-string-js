import { describe, it, expect } from 'vitest';
import { z } from 'zod';
import {
  SensitiveString,
  zCredentialPreprocess,
  zSensitivePreprocess,
  zSensitiveStringPreprocess,
} from './index.js';

describe('Preprocessing', () => {
  it('test_preprocess_trims_and_lowercases', () => {
    const schema = zSensitivePreprocess({ trim: true, lowercase: true }, 'email');
    const result = schema.parse('  Alice@Example.COM  ');

    expect(result).toBeInstanceOf(SensitiveString);
    expect(result.reveal()).toBe('alice@example.com');
  });

  it('test_preprocess_uppercases', () => {
    expect(zSensitivePreprocess({ uppercase: true }).parse('ab').reveal()).toBe('AB');
  });

  it('test_preprocess_strips_whitespace', () => {
    const schema = zCredentialPreprocess({ stripWhitespace: true }, 'api_key');

    expect(schema.parse('sk_live\n abc\t123').reveal()).toBe('sk_liveabc123');
  });

  it('test_preprocess_collapses_whitespace', () => {
    const schema = zSensitivePreprocess({ collapseWhitespace: true, trim: true }, 'name');

    expect(schema.parse('  Ada   Lovelace  ').reveal()).toBe('Ada Lovelace');
  });

  it('test_preprocess_applies_unicode_normalization_first', () => {
    // 'e' plus a combining acute, which NFC folds into a single code point.
    const decomposed = 'Café';
    const schema = zSensitivePreprocess({ normalize: 'NFC' }, 'name');

    expect(schema.parse(decomposed).reveal()).toBe('Café');
    expect(schema.parse(decomposed).length).toBe(4);
  });

  it('test_preprocess_rejects_lowercase_and_uppercase_together', () => {
    expect(() => zSensitivePreprocess({ lowercase: true, uppercase: true })).toThrow(TypeError);
  });

  it('test_preprocess_accepts_a_single_function', () => {
    const schema = zSensitivePreprocess((value) => value.trim().toLowerCase(), 'email');

    expect(schema.parse('  A@B.COM ').reveal()).toBe('a@b.com');
  });

  it('test_preprocess_accepts_a_list_of_functions_run_left_to_right', () => {
    const schema = zCredentialPreprocess(
      [(value) => value.trim(), (value) => value.replace(/\s+/gu, ''), (value) => `sk_${value}`],
      'api_key'
    );

    expect(schema.parse('  ab cd  ').reveal()).toBe('sk_abcd');
  });

  it('test_preprocess_rejects_a_non_function_step', () => {
    expect(() => zSensitivePreprocess([null as unknown as (value: string) => string])).toThrow(
      TypeError
    );
  });

  it('test_preprocess_validates_after_normalizing', () => {
    const schema = zSensitivePreprocess(
      { trim: true, lowercase: true },
      'email',
      z.string().email()
    );

    // Only valid once the surrounding whitespace is gone.
    expect(schema.safeParse('  Alice@Example.com  ').success).toBe(true);
    expect(schema.safeParse('  not-an-email  ').success).toBe(false);
  });

  it('test_preprocess_passes_a_non_string_through_to_the_type_error', () => {
    const result = zSensitivePreprocess({ trim: true }).safeParse(42);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues[0]?.code).toBe('invalid_type');
    }
  });

  it('test_preprocess_takes_an_explicit_class', () => {
    const schema = zSensitiveStringPreprocess('credential', { trim: true }, 'token');
    const result = schema.parse(' t ');

    expect(result.klass).toBe('credential');
    expect(result.label).toBe('token');
  });

  it('test_preprocess_result_carries_refine_sensitive', () => {
    const schema = zCredentialPreprocess({ trim: true }, 'api_key').refineSensitive(
      (raw) => raw.startsWith('sk_'),
      { message: 'must start with sk_' }
    );

    expect(schema.safeParse('  pk_x  ').success).toBe(false);
    expect(schema.safeParse('  sk_x  ').success).toBe(true);
  });

  it('test_preprocess_field_is_required_in_an_object', () => {
    const schema = z.object({ email: zSensitivePreprocess({ trim: true }, 'email') });

    // `z.preprocess` declares an `unknown` input, which would mark the field
    // optional in the input type while still failing here at runtime.
    expect(schema.safeParse({}).success).toBe(false);
  });

  it('test_preprocess_composes_inside_an_object', () => {
    const schema = z.object({
      email: zSensitivePreprocess({ trim: true, lowercase: true }, 'email'),
    });

    expect(schema.parse({ email: ' A@B.COM ' }).email.reveal()).toBe('a@b.com');
  });
});
