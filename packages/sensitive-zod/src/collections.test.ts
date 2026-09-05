import { describe, it, expect } from 'vitest';
import { z } from 'zod';
import {
  SensitiveString,
  zCredential,
  zCredentialArray,
  zCredentialRecord,
  zSensitive,
  zSensitiveArray,
  zSensitiveDeserialize,
  zSensitiveRecord,
  zSensitiveStringArray,
  zSensitiveStringRecord,
} from './index.js';

const CANARY = 'CANARY-COLLECTION-VALUE-42';

describe('Collections', () => {
  describe('zSensitiveArray', () => {
    it('test_array_wraps_every_element', () => {
      const schema = zSensitiveArray('email');
      const result = schema.parse(['a@example.com', 'b@example.com']);

      expect(result).toHaveLength(2);
      expect(result[0]).toBeInstanceOf(SensitiveString);
      expect(result[1]).toBeInstanceOf(SensitiveString);
      expect(result[0]?.klass).toBe('sensitive');
      expect(result[0]?.label).toBe('email');
    });

    it('test_array_elements_redact_in_json', () => {
      const schema = z.object({ recipients: zSensitiveArray('email') });
      const result = schema.parse({ recipients: [CANARY] });
      const json = JSON.stringify(result);

      expect(json).not.toContain(CANARY);
      expect(json).toContain('[REDACTED:sensitive]');
    });

    it('test_array_handles_empty_input', () => {
      expect(zSensitiveArray('email').parse([])).toEqual([]);
    });

    it('test_array_keeps_zod_array_combinators', () => {
      const schema = zCredentialArray('backup_code').min(2).max(3);

      expect(() => schema.parse(['a'])).toThrow();
      expect(() => schema.parse(['a', 'b', 'c', 'd'])).toThrow();
      expect(schema.parse(['a', 'b'])).toHaveLength(2);
    });

    it('test_array_reports_the_failing_index_in_the_path', () => {
      const schema = zSensitiveArray('email');
      const result = schema.safeParse(['ok', 123]);

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0]?.path).toEqual([1]);
      }
    });

    it('test_array_rejects_non_string_elements', () => {
      expect(() => zSensitiveArray().parse([null])).toThrow();
      expect(() => zSensitiveArray().parse([{}])).toThrow();
    });

    it('test_array_handles_large_input', () => {
      const result = zSensitiveArray('item').parse(Array<string>(10_000).fill('value'));

      expect(result).toHaveLength(10_000);
      expect(result[9_999]).toBeInstanceOf(SensitiveString);
    });
  });

  describe('zCredentialArray', () => {
    it('test_credential_array_uses_the_credential_class', () => {
      const result = zCredentialArray('api_key').parse(['sk-a', 'sk-b']);

      expect(result[0]?.klass).toBe('credential');
      expect(result[0]?.label).toBe('api_key');
    });
  });

  describe('zSensitiveStringArray', () => {
    it('test_string_array_takes_an_explicit_class', () => {
      const result = zSensitiveStringArray('credential', 'token').parse(['t']);

      expect(result[0]?.klass).toBe('credential');
    });
  });

  describe('zSensitiveRecord', () => {
    it('test_record_wraps_every_value', () => {
      const schema = zSensitiveStringRecord('credential', 'secret');
      const result = schema.parse({ stripe: 'sk-a', twilio: 'sk-b' });

      expect(result['stripe']).toBeInstanceOf(SensitiveString);
      expect(result['twilio']).toBeInstanceOf(SensitiveString);
      expect(result['stripe']?.klass).toBe('credential');
    });

    it('test_record_keeps_keys_in_the_clear', () => {
      const result = zCredentialRecord('secret').parse({ stripe: CANARY });

      expect(Object.keys(result)).toEqual(['stripe']);
      expect(JSON.stringify(result)).not.toContain(CANARY);
    });

    it('test_record_handles_empty_input', () => {
      expect(zSensitiveRecord('secret').parse({})).toEqual({});
    });

    it('test_record_reports_the_failing_key_in_the_path', () => {
      const result = zSensitiveRecord('secret').safeParse({ ok: 'x', bad: 7 });

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues[0]?.path).toEqual(['bad']);
      }
    });

    it('test_record_rejects_non_string_values', () => {
      expect(() => zSensitiveRecord().parse({ a: null })).toThrow();
    });
  });

  describe('composition with plain Zod', () => {
    it('test_zod_array_of_a_sensitive_schema_works_directly', () => {
      const result = z.array(zCredential('api_key')).parse(['sk-a']);

      expect(result[0]).toBeInstanceOf(SensitiveString);
    });

    it('test_zod_record_of_a_sensitive_schema_works_directly', () => {
      const result = z.record(z.string(), zCredential()).parse({ a: 'sk-a' });

      expect(result['a']).toBeInstanceOf(SensitiveString);
    });

    it('test_collections_compose_with_the_base_helpers', () => {
      const schema = z.object({
        email: zSensitive('email'),
        emails: zSensitiveArray('email'),
      });

      const result = schema.parse({
        email: 'primary@example.com',
        emails: ['alt1@example.com', 'alt2@example.com'],
      });

      expect(result.email).toBeInstanceOf(SensitiveString);
      expect(result.emails[0]).toBeInstanceOf(SensitiveString);
    });

    it('test_arrays_of_the_serialized_wire_format', () => {
      const schema = z.array(zSensitiveDeserialize('credential'));

      const result = schema.parse([
        { __sensitive: true, klass: 'credential', value: 'secret1', label: 'key' },
        { __sensitive: true, klass: 'credential', value: 'secret2', label: 'key' },
      ]);

      expect(result[0]).toBeInstanceOf(SensitiveString);
      expect(result[1]?.reveal()).toBe('secret2');
    });

    it('test_deeply_nested_sensitive_fields', () => {
      const schema = z.object({
        level1: z.object({ level2: z.object({ level3: zSensitive('deep') }) }),
      });

      const result = schema.parse({ level1: { level2: { level3: CANARY } } });

      expect(result.level1.level2.level3).toBeInstanceOf(SensitiveString);
      expect(JSON.stringify(result)).not.toContain(CANARY);
    });

    it('test_recursive_schemas', () => {
      type Node = { value: SensitiveString<'sensitive'>; children: Node[] };
      const schema: z.ZodType<Node, unknown> = z.lazy(() =>
        z.object({ value: zSensitive('node_value'), children: z.array(schema) })
      );

      const result = schema.parse({ value: 'root', children: [{ value: CANARY, children: [] }] });

      expect(result.value).toBeInstanceOf(SensitiveString);
      expect(result.children[0]?.value).toBeInstanceOf(SensitiveString);
      expect(JSON.stringify(result)).not.toContain(CANARY);
    });

    it('test_partial_pick_and_omit', () => {
      const base = z.object({
        id: z.string(),
        email: zSensitive('email'),
        password: zCredential('password'),
      });

      const partial = base.partial();
      expect(partial.parse({}).email).toBeUndefined();
      expect(partial.parse({ email: 'a@example.com' }).email).toBeInstanceOf(SensitiveString);

      const picked = base.pick({ email: true, password: true });
      const pickedResult = picked.parse({ email: 'a@example.com', password: 'pw' });
      expect(pickedResult.password).toBeInstanceOf(SensitiveString);
      expect('id' in pickedResult).toBe(false);

      const omitted = base.omit({ password: true });
      const omittedResult = omitted.parse({ id: '1', email: 'a@example.com' });
      expect(omittedResult.email).toBeInstanceOf(SensitiveString);
      expect('password' in omittedResult).toBe(false);
    });

    it('test_unions_of_sensitive_branches', () => {
      const schema = z.union([
        z.object({ type: z.literal('email'), value: zSensitive('email') }),
        z.object({ type: z.literal('phone'), value: zSensitive('phone') }),
      ]);

      const result = schema.parse({ type: 'email', value: 'test@example.com' });

      expect(result.value).toBeInstanceOf(SensitiveString);
    });
  });
});
