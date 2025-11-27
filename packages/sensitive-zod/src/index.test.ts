import { describe, it, expect } from 'vitest';
import { z } from 'zod';
import {
  zSensitive,
  zSensitiveEmail,
  zSensitivePII,
  zSensitiveSecret,
  zSensitiveToken,
  zSensitiveWithValidation,
  zSensitiveOptional,
  zSensitiveFromEnvelope,
  SensitiveString,
} from './index.js';

const CANARY = 'CANARY-SECRET-VALUE-12345';

describe('Zod Integration', () => {
  describe('zSensitive', () => {
    it('test_zSensitive_parses_to_SensitiveString', () => {
      const schema = z.object({
        token: zSensitive('token'),
      });

      const result = schema.parse({ token: CANARY });

      expect(result.token).toBeInstanceOf(SensitiveString);
      expect(result.token.klass).toBe('token');
      expect(result.token.reveal()).toBe(CANARY);
    });

    it('test_zSensitive_redacts_in_json', () => {
      const schema = z.object({
        secret: zSensitive('secret'),
      });

      const result = schema.parse({ secret: CANARY });
      const json = JSON.stringify(result);

      expect(json).not.toContain(CANARY);
      expect(json).toContain('[REDACTED:secret]');
    });

    it('test_zSensitive_rejects_non_string', () => {
      const schema = z.object({
        token: zSensitive('token'),
      });

      expect(() => schema.parse({ token: 123 })).toThrow();
      expect(() => schema.parse({ token: null })).toThrow();
      expect(() => schema.parse({ token: undefined })).toThrow();
    });

    it('test_zSensitive_type_inference', () => {
      const schema = z.object({
        token: zSensitive('token'),
        secret: zSensitive('secret'),
        email: zSensitive('pii_email'),
      });

      type SchemaType = z.infer<typeof schema>;

      // Type assertions - these would fail at compile time if types were wrong
      const result: SchemaType = schema.parse({
        token: 'tok',
        secret: 'sec',
        email: 'email',
      });

      expect(result.token.klass).toBe('token');
      expect(result.secret.klass).toBe('secret');
      expect(result.email.klass).toBe('pii_email');
    });
  });

  describe('zSensitiveEmail', () => {
    it('test_zSensitiveEmail_validates_email_format', () => {
      const schema = z.object({
        email: zSensitiveEmail(),
      });

      // Invalid email should throw
      expect(() => schema.parse({ email: 'not-an-email' })).toThrow();
      expect(() => schema.parse({ email: 'missing@domain' })).toThrow();
    });

    it('test_zSensitiveEmail_parses_valid_email', () => {
      const schema = z.object({
        email: zSensitiveEmail(),
      });

      const result = schema.parse({ email: 'user@example.com' });

      expect(result.email).toBeInstanceOf(SensitiveString);
      expect(result.email.klass).toBe('pii_email');
      expect(result.email.reveal()).toBe('user@example.com');
    });

    it('test_zSensitiveEmail_redacts_output', () => {
      const schema = z.object({
        email: zSensitiveEmail(),
      });

      const result = schema.parse({ email: 'secret@example.com' });

      expect(result.email.toString()).not.toContain('secret@example.com');
      expect(result.email.toString()).toBe('[REDACTED:pii_email]');
    });
  });

  describe('Convenience functions', () => {
    it('test_zSensitivePII', () => {
      const schema = z.object({
        name: zSensitivePII(),
      });

      const result = schema.parse({ name: 'John Doe' });

      expect(result.name.klass).toBe('pii_generic');
    });

    it('test_zSensitiveSecret', () => {
      const schema = z.object({
        password: zSensitiveSecret(),
      });

      const result = schema.parse({ password: 'hunter2' });

      expect(result.password.klass).toBe('secret');
    });

    it('test_zSensitiveToken', () => {
      const schema = z.object({
        session: zSensitiveToken(),
      });

      const result = schema.parse({ session: 'sess_abc123' });

      expect(result.session.klass).toBe('token');
    });
  });

  describe('zSensitiveWithValidation', () => {
    it('test_validation_chain_min_length', () => {
      const schema = z.object({
        apiKey: zSensitiveWithValidation(
          'secret',
          z.string().min(32, 'API key must be at least 32 characters')
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
    });

    it('test_validation_chain_regex', () => {
      const schema = z.object({
        password: zSensitiveWithValidation(
          'secret',
          z
            .string()
            .min(8)
            .regex(/[A-Z]/, 'Must contain uppercase')
            .regex(/[0-9]/, 'Must contain number')
        ),
      });

      // Missing uppercase
      expect(() => schema.parse({ password: 'password123' })).toThrow(
        'Must contain uppercase'
      );

      // Missing number
      expect(() => schema.parse({ password: 'PasswordABC' })).toThrow(
        'Must contain number'
      );

      // Valid
      const result = schema.parse({ password: 'Password123' });
      expect(result.password.klass).toBe('secret');
    });
  });

  describe('zSensitiveOptional', () => {
    it('test_optional_with_value', () => {
      const schema = z.object({
        apiKey: zSensitiveOptional('secret'),
      });

      const result = schema.parse({ apiKey: 'sk-xxx' });

      expect(result.apiKey).toBeInstanceOf(SensitiveString);
      expect(result.apiKey?.reveal()).toBe('sk-xxx');
    });

    it('test_optional_with_undefined', () => {
      const schema = z.object({
        apiKey: zSensitiveOptional('secret'),
      });

      const result = schema.parse({ apiKey: undefined });

      expect(result.apiKey).toBeNull();
    });

    it('test_optional_with_null', () => {
      const schema = z.object({
        apiKey: zSensitiveOptional('secret'),
      });

      const result = schema.parse({ apiKey: null });

      expect(result.apiKey).toBeNull();
    });

    it('test_optional_with_empty_string', () => {
      const schema = z.object({
        apiKey: zSensitiveOptional('secret'),
      });

      const result = schema.parse({ apiKey: '' });

      expect(result.apiKey).toBeNull();
    });

    it('test_optional_missing_field', () => {
      const schema = z.object({
        apiKey: zSensitiveOptional('secret'),
      });

      const result = schema.parse({});

      expect(result.apiKey).toBeNull();
    });
  });

  describe('zSensitiveFromEnvelope', () => {
    it('test_envelope_parsing', () => {
      const schema = z.object({
        token: zSensitiveFromEnvelope('token'),
      });

      const result = schema.parse({
        token: {
          __sensitive: true,
          klass: 'token',
          value: CANARY,
        },
      });

      expect(result.token).toBeInstanceOf(SensitiveString);
      expect(result.token.reveal()).toBe(CANARY);
      expect(result.token.klass).toBe('token');
    });

    it('test_envelope_validates_marker', () => {
      const schema = z.object({
        token: zSensitiveFromEnvelope(),
      });

      expect(() =>
        schema.parse({
          token: {
            __sensitive: false,
            klass: 'token',
            value: 'test',
          },
        })
      ).toThrow();
    });

    it('test_envelope_validates_class', () => {
      const schema = z.object({
        token: zSensitiveFromEnvelope('token'),
      });

      expect(() =>
        schema.parse({
          token: {
            __sensitive: true,
            klass: 'secret', // Wrong class
            value: 'test',
          },
        })
      ).toThrow("Expected sensitivity class 'token', got 'secret'");
    });

    it('test_envelope_accepts_any_class_when_not_specified', () => {
      const schema = z.object({
        data: zSensitiveFromEnvelope(), // No expected class
      });

      const result = schema.parse({
        data: {
          __sensitive: true,
          klass: 'secret',
          value: 'test',
        },
      });

      expect(result.data.klass).toBe('secret');
    });
  });

  describe('Complex Schema Examples', () => {
    it('test_webhook_schema', () => {
      const WebhookSchema = z.object({
        token: zSensitive('token'),
        email: zSensitiveEmail(),
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
      expect(json).toContain('[REDACTED:token]');
      expect(json).toContain('[REDACTED:pii_email]');
      expect(json).toContain('Test webhook');
    });

    it('test_user_registration_schema', () => {
      const RegistrationSchema = z.object({
        email: zSensitiveEmail(),
        password: zSensitiveWithValidation(
          'secret',
          z.string().min(8)
        ),
        fullName: zSensitivePII(),
        phone: zSensitiveOptional('pii_generic'),
      });

      const result = RegistrationSchema.parse({
        email: 'new@user.com',
        password: 'securepassword123',
        fullName: 'Jane Doe',
      });

      expect(result.email.klass).toBe('pii_email');
      expect(result.password.klass).toBe('secret');
      expect(result.fullName.klass).toBe('pii_generic');
      expect(result.phone).toBeNull();
    });

    it('test_nested_schema', () => {
      const NestedSchema = z.object({
        user: z.object({
          credentials: z.object({
            token: zSensitiveToken(),
            apiKey: zSensitiveSecret(),
          }),
          profile: z.object({
            email: zSensitiveEmail(),
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
        tokens: z.array(zSensitiveToken()),
      });

      const result = ArraySchema.parse({
        tokens: ['tok1', 'tok2', 'tok3'],
      });

      expect(result.tokens).toHaveLength(3);
      expect(result.tokens[0]).toBeInstanceOf(SensitiveString);

      const json = JSON.stringify(result);
      expect(json).not.toContain('tok1');
      expect(json).toContain('[REDACTED:token]');
    });
  });
});
