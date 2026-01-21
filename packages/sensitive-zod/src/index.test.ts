import { describe, it, expect } from 'vitest';
import { z } from 'zod';
import {
  zSensitiveString,
  zSensitive,
  zCredential,
  zSensitiveWithValidation,
  zSensitiveOptional,
  zSensitiveDeserialize,
  SensitiveString,
} from './index.js';

const CANARY = 'CANARY-SECRET-VALUE-12345';

describe('Zod Integration', () => {
  describe('zSensitiveString', () => {
    it('test_zSensitiveString_parses_to_SensitiveString', () => {
      const schema = z.object({
        token: zSensitiveString('credential', 'session_token'),
      });

      const result = schema.parse({ token: CANARY });

      expect(result.token).toBeInstanceOf(SensitiveString);
      expect(result.token.klass).toBe('credential');
      expect(result.token.label).toBe('session_token');
      expect(result.token.reveal()).toBe(CANARY);
    });

    it('test_zSensitiveString_redacts_in_json', () => {
      const schema = z.object({
        secret: zSensitiveString('credential', 'api_key'),
      });

      const result = schema.parse({ secret: CANARY });
      const json = JSON.stringify(result);

      expect(json).not.toContain(CANARY);
      expect(json).toContain('[REDACTED:credential]');
    });

    it('test_zSensitiveString_rejects_non_string', () => {
      const schema = z.object({
        token: zSensitiveString('credential'),
      });

      expect(() => schema.parse({ token: 123 })).toThrow();
      expect(() => schema.parse({ token: null })).toThrow();
      expect(() => schema.parse({ token: undefined })).toThrow();
    });

    it('test_zSensitiveString_type_inference', () => {
      const schema = z.object({
        token: zSensitiveString('credential', 'token'),
        email: zSensitiveString('sensitive', 'email'),
      });

      type SchemaType = z.infer<typeof schema>;

      // Type assertions - these would fail at compile time if types were wrong
      const result: SchemaType = schema.parse({
        token: 'tok',
        email: 'email@example.com',
      });

      expect(result.token.klass).toBe('credential');
      expect(result.email.klass).toBe('sensitive');
    });
  });

  describe('zSensitive', () => {
    it('test_zSensitive_creates_sensitive_class', () => {
      const schema = z.object({
        email: zSensitive('email'),
      });

      const result = schema.parse({ email: 'user@example.com' });

      expect(result.email).toBeInstanceOf(SensitiveString);
      expect(result.email.klass).toBe('sensitive');
      expect(result.email.label).toBe('email');
    });

    it('test_zSensitive_without_label', () => {
      const schema = z.object({
        data: zSensitive(),
      });

      const result = schema.parse({ data: 'some-data' });

      expect(result.data.klass).toBe('sensitive');
      expect(result.data.label).toBeUndefined();
    });

    it('test_zSensitive_redacts_output', () => {
      const schema = z.object({
        email: zSensitive('email'),
      });

      const result = schema.parse({ email: 'secret@example.com' });

      expect(result.email.toString()).not.toContain('secret@example.com');
      expect(result.email.toString()).toBe('[REDACTED:sensitive]');
    });
  });

  describe('zCredential', () => {
    it('test_zCredential_creates_credential_class', () => {
      const schema = z.object({
        password: zCredential('password'),
      });

      const result = schema.parse({ password: 'hunter2' });

      expect(result.password.klass).toBe('credential');
      expect(result.password.label).toBe('password');
    });

    it('test_zCredential_without_label', () => {
      const schema = z.object({
        token: zCredential(),
      });

      const result = schema.parse({ token: 'sess_abc123' });

      expect(result.token.klass).toBe('credential');
      expect(result.token.label).toBeUndefined();
    });
  });

  describe('zSensitiveWithValidation', () => {
    it('test_validation_chain_min_length', () => {
      const schema = z.object({
        apiKey: zSensitiveWithValidation(
          'credential',
          z.string().min(32, 'API key must be at least 32 characters'),
          'api_key'
        ),
      });

      // Too short
      expect(() => schema.parse({ apiKey: 'short' })).toThrow(
        'API key must be at least 32 characters'
      );

      // Valid
      const validKey = 'a'.repeat(32);
      const result = schema.parse({ apiKey: validKey });
      expect(result.apiKey.reveal()).toBe(validKey);
      expect(result.apiKey.label).toBe('api_key');
    });

    it('test_validation_chain_regex', () => {
      const schema = z.object({
        password: zSensitiveWithValidation(
          'credential',
          z
            .string()
            .min(8)
            .regex(/[A-Z]/, 'Must contain uppercase')
            .regex(/[0-9]/, 'Must contain number'),
          'password'
        ),
      });

      // Missing uppercase
      expect(() => schema.parse({ password: 'password123' })).toThrow('Must contain uppercase');

      // Missing number
      expect(() => schema.parse({ password: 'PasswordABC' })).toThrow('Must contain number');

      // Valid
      const result = schema.parse({ password: 'Password123' });
      expect(result.password.klass).toBe('credential');
    });
  });

  describe('zSensitiveOptional', () => {
    it('test_optional_with_value', () => {
      const schema = z.object({
        apiKey: zSensitiveOptional('credential', 'api_key'),
      });

      const result = schema.parse({ apiKey: 'sk-xxx' });

      expect(result.apiKey).toBeInstanceOf(SensitiveString);
      expect(result.apiKey?.reveal()).toBe('sk-xxx');
      expect(result.apiKey?.label).toBe('api_key');
    });

    it('test_optional_with_undefined', () => {
      const schema = z.object({
        apiKey: zSensitiveOptional('credential'),
      });

      const result = schema.parse({ apiKey: undefined });

      expect(result.apiKey).toBeNull();
    });

    it('test_optional_with_null', () => {
      const schema = z.object({
        apiKey: zSensitiveOptional('credential'),
      });

      const result = schema.parse({ apiKey: null });

      expect(result.apiKey).toBeNull();
    });

    it('test_optional_with_empty_string', () => {
      const schema = z.object({
        apiKey: zSensitiveOptional('credential'),
      });

      const result = schema.parse({ apiKey: '' });

      expect(result.apiKey).toBeNull();
    });

    it('test_optional_missing_field', () => {
      const schema = z.object({
        apiKey: zSensitiveOptional('credential'),
      });

      const result = schema.parse({});

      expect(result.apiKey).toBeNull();
    });
  });

  describe('zSensitiveDeserialize', () => {
    it('test_serialized_parsing', () => {
      const schema = z.object({
        token: zSensitiveDeserialize('credential'),
      });

      const result = schema.parse({
        token: {
          __sensitive: true,
          klass: 'credential',
          value: CANARY,
        },
      });

      expect(result.token).toBeInstanceOf(SensitiveString);
      expect(result.token.reveal()).toBe(CANARY);
      expect(result.token.klass).toBe('credential');
    });

    it('test_serialized_with_label', () => {
      const schema = z.object({
        token: zSensitiveDeserialize('credential'),
      });

      const result = schema.parse({
        token: {
          __sensitive: true,
          klass: 'credential',
          value: CANARY,
          label: 'api_key',
        },
      });

      expect(result.token.label).toBe('api_key');
    });

    it('test_serialized_validates_marker', () => {
      const schema = z.object({
        token: zSensitiveDeserialize(),
      });

      expect(() =>
        schema.parse({
          token: {
            __sensitive: false,
            klass: 'credential',
            value: 'test',
          },
        })
      ).toThrow();
    });

    it('test_serialized_validates_class', () => {
      const schema = z.object({
        token: zSensitiveDeserialize('credential'),
      });

      expect(() =>
        schema.parse({
          token: {
            __sensitive: true,
            klass: 'sensitive', // Wrong class
            value: 'test',
          },
        })
      ).toThrow("Expected sensitivity class 'credential', got 'sensitive'");
    });

    it('test_serialized_accepts_any_class_when_not_specified', () => {
      const schema = z.object({
        data: zSensitiveDeserialize(), // No expected class
      });

      const result = schema.parse({
        data: {
          __sensitive: true,
          klass: 'sensitive',
          value: 'test',
        },
      });

      expect(result.data.klass).toBe('sensitive');
    });
  });

  describe('Complex Schema Examples', () => {
    it('test_webhook_schema', () => {
      const WebhookSchema = z.object({
        token: zCredential('session_token'),
        email: zSensitive('email'),
        note: z.string().max(1024).optional(),
      });

      type Webhook = z.infer<typeof WebhookSchema>;

      const webhook: Webhook = WebhookSchema.parse({
        token: 'tok_abc123',
        email: 'user@example.com',
        note: 'Test webhook',
      });

      // Test JSON serialization doesn't leak
      const json = JSON.stringify(webhook);
      expect(json).not.toContain('tok_abc123');
      expect(json).not.toContain('user@example.com');
      expect(json).toContain('[REDACTED:credential]');
      expect(json).toContain('[REDACTED:sensitive]');
      expect(json).toContain('Test webhook');
    });

    it('test_user_registration_schema', () => {
      const RegistrationSchema = z.object({
        email: zSensitive('email'),
        password: zSensitiveWithValidation('credential', z.string().min(8), 'password'),
        fullName: zSensitive('name'),
        phone: zSensitiveOptional('sensitive', 'phone'),
      });

      const result = RegistrationSchema.parse({
        email: 'new@user.com',
        password: 'securepassword123',
        fullName: 'Jane Doe',
      });

      expect(result.email.klass).toBe('sensitive');
      expect(result.email.label).toBe('email');
      expect(result.password.klass).toBe('credential');
      expect(result.password.label).toBe('password');
      expect(result.fullName.klass).toBe('sensitive');
      expect(result.fullName.label).toBe('name');
      expect(result.phone).toBeNull();
    });

    it('test_nested_schema', () => {
      const NestedSchema = z.object({
        user: z.object({
          credentials: z.object({
            token: zCredential('session_token'),
            apiKey: zCredential('api_key'),
          }),
          profile: z.object({
            email: zSensitive('email'),
            displayName: z.string(),
          }),
        }),
      });

      const result = NestedSchema.parse({
        user: {
          credentials: {
            token: 'session_token',
            apiKey: 'api_key_secret',
          },
          profile: {
            email: 'user@test.com',
            displayName: 'Test User',
          },
        },
      });

      const json = JSON.stringify(result);
      expect(json).not.toContain('session_token');
      expect(json).not.toContain('api_key_secret');
      expect(json).not.toContain('user@test.com');
      expect(json).toContain('Test User'); // Non-sensitive data preserved
    });

    it('test_array_of_sensitive', () => {
      const ArraySchema = z.object({
        tokens: z.array(zCredential('token')),
      });

      const result = ArraySchema.parse({
        tokens: ['tok1', 'tok2', 'tok3'],
      });

      expect(result.tokens).toHaveLength(3);
      expect(result.tokens[0]).toBeInstanceOf(SensitiveString);

      const json = JSON.stringify(result);
      expect(json).not.toContain('tok1');
      expect(json).toContain('[REDACTED:credential]');
    });
  });
});
