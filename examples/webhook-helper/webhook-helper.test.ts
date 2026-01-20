/**
 * Tests for webhook helper utilities.
 *
 * These tests demonstrate usage patterns for the parseAndProtectWebhook
 * helper and validate the sensitive field configurations.
 */

import { describe, it, expect } from 'vitest';
import * as util from 'node:util';
import {
  parseAndProtectWebhook,
  unprotectWebhook,
  createWebhookHandler,
  PSP_SENSITIVE_FIELDS,
  parsePspWebhookPayload,
} from './webhook-helper';
import type { PspWebhookPayload } from './webhook-helper';
import {
  SensitiveString,
  validateSensitiveFieldConfig,
  checkSensitiveFieldsWrapped,
  safeStringify,
  withRevealContext,
} from '@anthropic-security/sensitive-core';

/**
 * Sample webhook payload matching the PSP_SENSITIVE_FIELDS structure.
 * This represents what a payment provider might send.
 */
const SAMPLE_WEBHOOK_BODY = JSON.stringify({
  notification: {
    metadata: {
      webhookSignature: 'dGVzdC1zaWduYXR1cmU=',
      cardLastFour: '4242',
      cardBinPrefix: '424242',
      cardExpiry: '12/2028',
      cardholderName: 'Test User',
      customerIpAddress: '10.0.0.1',
      customerEmail: 'test@example.local',
      paymentTokenAlias: 'tok_test_123',
      networkReference: 'net_ref_456',
      riskScore: '15',
      fraudCheckPassed: 'true',
    },
    transaction: {
      gatewayReference: 'gw_ref_789',
      authorizationDetails: '123456:4242:12/2028',
      status: 'AUTHORIZED',
      amount: { currency: 'USD', value: 9999 },
      merchantId: 'merchant_001',
    },
  },
});

const parseSampleWebhook = (body: string): PspWebhookPayload =>
  parsePspWebhookPayload(body);

describe('parseAndProtectWebhook', () => {
  it('should parse and wrap sensitive fields atomically', () => {
    const result = parseAndProtectWebhook(
      SAMPLE_WEBHOOK_BODY,
      parseSampleWebhook,
      PSP_SENSITIVE_FIELDS
    );

    // Sensitive fields should be wrapped
    expect(result.notification.metadata.webhookSignature).toBeInstanceOf(SensitiveString);
    expect(result.notification.metadata.cardLastFour).toBeInstanceOf(SensitiveString);
    expect(result.notification.metadata.customerIpAddress).toBeInstanceOf(SensitiveString);
    expect(result.notification.transaction.gatewayReference).toBeInstanceOf(SensitiveString);

    // Non-sensitive fields should remain plain
    expect(result.notification.metadata.riskScore).toBe('15');
    expect(result.notification.transaction.status).toBe('AUTHORIZED');
  });

  it('should produce safe JSON for logging', () => {
    const result = parseAndProtectWebhook(
      SAMPLE_WEBHOOK_BODY,
      parseSampleWebhook,
      PSP_SENSITIVE_FIELDS
    );

    const json = safeStringify(result);

    // Sensitive data should be redacted
    expect(json).not.toContain('4242');
    expect(json).not.toContain('dGVzdC1zaWduYXR1cmU=');
    expect(json).not.toContain('10.0.0.1');

    // Should contain redaction markers
    expect(json).toContain('[REDACTED:secret]');
    expect(json).toContain('[REDACTED:pii_generic]');
    expect(json).toContain('[REDACTED:token]');

    // Non-sensitive data should be present
    expect(json).toContain('AUTHORIZED');
    expect(json).toContain('merchant_001');
  });
});

describe('auto-redaction without safeLog', () => {
  // These tests verify that protected webhooks auto-redact through all
  // serialization paths, making safeLog() unnecessary after parseAndProtectWebhook()

  it('should auto-redact via JSON.stringify (toJSON)', () => {
    const result = parseAndProtectWebhook(
      SAMPLE_WEBHOOK_BODY,
      parseSampleWebhook,
      PSP_SENSITIVE_FIELDS
    );

    // JSON.stringify calls toJSON() on SensitiveString instances
    const json = JSON.stringify(result);

    // Sensitive data should be redacted
    expect(json).not.toContain('4242');
    expect(json).not.toContain('dGVzdC1zaWduYXR1cmU=');
    expect(json).not.toContain('10.0.0.1');
    expect(json).not.toContain('test@example.local');
    expect(json).not.toContain('tok_test_123');
    expect(json).not.toContain('gw_ref_789');

    // Should contain redaction markers
    expect(json).toContain('[REDACTED:secret]');
    expect(json).toContain('[REDACTED:pii_generic]');
    expect(json).toContain('[REDACTED:pii_email]');
    expect(json).toContain('[REDACTED:token]');

    // Non-sensitive data should still be present
    expect(json).toContain('AUTHORIZED');
    expect(json).toContain('merchant_001');
    expect(json).toContain('9999');
  });

  it('should auto-redact via util.inspect (console.log)', () => {
    const result = parseAndProtectWebhook(
      SAMPLE_WEBHOOK_BODY,
      parseSampleWebhook,
      PSP_SENSITIVE_FIELDS
    );

    // util.inspect is what console.log uses internally
    const inspected = util.inspect(result, { depth: null });

    // Sensitive data should be redacted
    expect(inspected).not.toContain('4242');
    expect(inspected).not.toContain('dGVzdC1zaWduYXR1cmU=');
    expect(inspected).not.toContain('10.0.0.1');
    expect(inspected).not.toContain('test@example.local');
    expect(inspected).not.toContain('tok_test_123');
    expect(inspected).not.toContain('gw_ref_789');

    // Should show SensitiveString wrapper with redacted value
    expect(inspected).toContain('SensitiveString<secret>');
    expect(inspected).toContain('SensitiveString<pii_generic>');
    expect(inspected).toContain('SensitiveString<pii_email>');
    expect(inspected).toContain('SensitiveString<token>');
    expect(inspected).toContain('[REDACTED:');

    // Non-sensitive data should still be present
    expect(inspected).toContain('AUTHORIZED');
    expect(inspected).toContain('merchant_001');
  });

  it('should auto-redact individual SensitiveString via toString', () => {
    const result = parseAndProtectWebhook(
      SAMPLE_WEBHOOK_BODY,
      parseSampleWebhook,
      PSP_SENSITIVE_FIELDS
    );

    // Direct toString() on a sensitive field
    const cardStr = String(result.notification.metadata.cardLastFour);
    expect(cardStr).not.toContain('4242');
    expect(cardStr).toBe('[REDACTED:pii_generic]');

    // Template literal interpolation
    const message = `Card ending in ${String(result.notification.metadata.cardLastFour)}`;
    expect(message).not.toContain('4242');
    expect(message).toBe('Card ending in [REDACTED:pii_generic]');
  });

  it('should auto-redact in nested JSON.stringify', () => {
    const result = parseAndProtectWebhook(
      SAMPLE_WEBHOOK_BODY,
      parseSampleWebhook,
      PSP_SENSITIVE_FIELDS
    );

    // Wrapping in another object (common in logging)
    const logPayload = {
      event: 'webhook_received',
      timestamp: '2024-01-01T00:00:00Z',
      data: result,
    };

    const json = JSON.stringify(logPayload);

    // Sensitive data should still be redacted in nested structure
    expect(json).not.toContain('4242');
    expect(json).not.toContain('dGVzdC1zaWduYXR1cmU=');
    expect(json).toContain('[REDACTED:');
    expect(json).toContain('webhook_received');
  });
});

describe('unprotectWebhook', () => {
  it('should unwrap sensitive fields back to strings', () => {
    const protected_ = parseAndProtectWebhook(
      SAMPLE_WEBHOOK_BODY,
      parseSampleWebhook,
      PSP_SENSITIVE_FIELDS
    );

    withRevealContext(
      { name: 'test', reason: 'Testing unwrap' },
      () => {
        const unprotected = unprotectWebhook(protected_, PSP_SENSITIVE_FIELDS);

        // Should be back to plain strings
        expect(unprotected.notification.metadata.cardLastFour).toBe('4242');
        expect(unprotected.notification.metadata.webhookSignature).toBe('dGVzdC1zaWduYXR1cmU=');
        expect(unprotected.notification.transaction.gatewayReference).toBe('gw_ref_789');
      }
    );
  });

  it('should audit reveals when context provided', () => {
    const protected_ = parseAndProtectWebhook(
      SAMPLE_WEBHOOK_BODY,
      parseSampleWebhook,
      PSP_SENSITIVE_FIELDS
    );

    const reveals: string[] = [];

    withRevealContext(
      {
        name: 'forward-to-processor',
        reason: 'Forwarding payment data',
        auditReveal: (value) => reveals.push(value.klass),
      },
      () => {
        unprotectWebhook(protected_, PSP_SENSITIVE_FIELDS);
      }
    );

    // Should have audited reveals for sensitive fields
    expect(reveals).toContain('secret');
    expect(reveals).toContain('pii_generic');
    expect(reveals).toContain('token');
  });
});

describe('createWebhookHandler', () => {
  it('should create a pre-configured handler', () => {
    const handler = createWebhookHandler(parseSampleWebhook, PSP_SENSITIVE_FIELDS);

    const result = handler(SAMPLE_WEBHOOK_BODY);

    expect(result.notification.metadata.webhookSignature).toBeInstanceOf(SensitiveString);
    expect(result.notification.transaction.status).toBe('AUTHORIZED');
  });
});

describe('PSP_SENSITIVE_FIELDS configuration', () => {
  it('should have valid paths matching the sample payload', () => {
    const sample = parseSampleWebhook(SAMPLE_WEBHOOK_BODY);
    const result = validateSensitiveFieldConfig(sample, PSP_SENSITIVE_FIELDS);

    expect(result.valid).toBe(true);
    expect(result.missingPaths).toEqual([]);
  });

  it('should detect when webhook is not yet protected', () => {
    const raw = parseSampleWebhook(SAMPLE_WEBHOOK_BODY);
    const result = checkSensitiveFieldsWrapped(raw, PSP_SENSITIVE_FIELDS);

    expect(result.allWrapped).toBe(false);
    expect(result.unwrappedPaths.length).toBeGreaterThan(0);
  });

  it('should confirm webhook is protected after wrapping', () => {
    const protected_ = parseAndProtectWebhook(
      SAMPLE_WEBHOOK_BODY,
      parseSampleWebhook,
      PSP_SENSITIVE_FIELDS
    );
    const result = checkSensitiveFieldsWrapped(protected_, PSP_SENSITIVE_FIELDS);

    expect(result.allWrapped).toBe(true);
    expect(result.unwrappedPaths).toEqual([]);
  });
});

describe('error handling', () => {
  it('should propagate parse errors', () => {
    expect(() => {
      parseAndProtectWebhook(
        'invalid json',
        parseSampleWebhook,
        PSP_SENSITIVE_FIELDS
      );
    }).toThrow();
  });

  it('should handle empty object gracefully', () => {
    const result = parseAndProtectWebhook('{}', parseSampleWebhook, PSP_SENSITIVE_FIELDS);
    expect(result).toEqual({});
  });
});
