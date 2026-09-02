import { describe, it, expect } from 'vitest';
import {
  wrapSensitiveByPath,
  unwrapSensitiveByPath,
  validateSensitiveFieldConfig,
  checkSensitiveFieldsWrapped,
  SensitiveFieldConfig,
} from './wrap.js';
import { SensitiveString } from './sensitive-string.js';
import { withRevealContext } from './context.js';
import { safeStringify } from './redact.js';

/**
 * Sample Payment Service Platform (PSP) authorization webhook payload.
 * Represents a typical structure from payment gateway webhooks.
 */
const PSP_AUTHORIZATION_WEBHOOK = {
  notification: {
    metadata: {
      riskScore: '12',
      fraudCheckPassed: 'true',
      deviceType: 'Desktop',
      browserInfo: 'Mozilla/5.0',
      transactionType: 'Ecommerce',
      currency: 'USD',
      // Sensitive fields
      webhookSignature: 'dGVzdC1zaWduYXR1cmUtYmFzZTY0LWVuY29kZWQ=',
      cardLastFour: '1234',
      cardBinPrefix: '411111',
      cardExpiry: '12/2028',
      cardholderName: 'Test Cardholder',
      customerIpAddress: '10.0.0.1',
      paymentTokenAlias: 'tok_test_abc123',
      networkReference: 'net_ref_xyz789',
    },
    transaction: {
      amount: { currency: 'USD', value: 9999 },
      status: 'AUTHORIZED',
      timestamp: '2025-01-15T10:30:00Z',
      merchantId: 'merchant_test_001',
      orderId: 'order_test_12345',
      allowedActions: ['CAPTURE', 'VOID', 'REFUND'],
      paymentMethod: 'card',
      gatewayReference: 'gw_ref_test_001',
      // Composite sensitive field (contains card info)
      authorizationDetails: '123456:1234:12/2028',
      outcome: 'approved',
    },
  },
};

/**
 * PSP-specific sensitive field configuration.
 * Maps dot-notation paths to sensitivity classifications.
 */
const PSP_SENSITIVE_FIELDS: SensitiveFieldConfig = {
  // Secrets
  'notification.metadata.webhookSignature': 'credential',

  // PII - Card data
  'notification.metadata.cardLastFour': 'sensitive',
  'notification.metadata.cardBinPrefix': 'sensitive',
  'notification.metadata.cardExpiry': 'sensitive',
  'notification.metadata.cardholderName': 'sensitive',

  // PII - Customer data
  'notification.metadata.customerIpAddress': 'sensitive',

  // Tokens
  'notification.metadata.paymentTokenAlias': 'credential',
  'notification.metadata.networkReference': 'credential',
  'notification.transaction.gatewayReference': 'credential',

  // Composite sensitive field (contains card info)
  'notification.transaction.authorizationDetails': 'sensitive',
};

describe('wrapSensitiveByPath', () => {
  describe('basic functionality', () => {
    it('should wrap specified fields as SensitiveString', () => {
      const config: SensitiveFieldConfig = {
        'user.email': 'sensitive',
        'user.identifier': 'sensitive',
      };

      const input = {
        user: {
          name: 'TestUser',
          email: 'user@test.local',
          identifier: 'id-000-000-000',
        },
      };

      const result = wrapSensitiveByPath(input, config);

      // Non-sensitive fields unchanged
      expect(result.user.name).toBe('TestUser');

      // Sensitive fields wrapped
      expect(result.user.email).toBeInstanceOf(SensitiveString);
      expect(result.user.identifier).toBeInstanceOf(SensitiveString);

      // Verify classes
      expect((result.user.email as unknown as SensitiveString).klass).toBe('sensitive');
      expect((result.user.identifier as unknown as SensitiveString).klass).toBe('sensitive');
    });

    it('should apply class and label from object field configuration', () => {
      const config: SensitiveFieldConfig = {
        'user.email': { klass: 'sensitive', label: 'contact_email' },
        'credentials.apiKey': { klass: 'credential', label: 'partner_api_key' },
      };
      const input = {
        user: { email: 'user@test.local' },
        credentials: { apiKey: 'key_test_12345' },
      };

      const result = wrapSensitiveByPath(input, config);
      const email = result.user.email as unknown as SensitiveString;
      const apiKey = result.credentials.apiKey as unknown as SensitiveString;

      expect(email.klass).toBe('sensitive');
      expect(email.label).toBe('contact_email');
      expect(apiKey.klass).toBe('credential');
      expect(apiKey.label).toBe('partner_api_key');
    });

    it('should not mutate the original object', () => {
      const config: SensitiveFieldConfig = { email: 'sensitive' };
      const original = { email: 'original@test.local', name: 'Test' };
      const originalEmail = original.email;

      wrapSensitiveByPath(original, config);

      expect(original.email).toBe(originalEmail);
      expect(typeof original.email).toBe('string');
    });

    it('should handle missing paths gracefully', () => {
      const config: SensitiveFieldConfig = {
        'user.email': 'sensitive',
        'user.phone': 'sensitive', // doesn't exist
      };

      const input = { user: { email: 'user@test.local' } };
      const result = wrapSensitiveByPath(input, config);

      expect(result.user.email).toBeInstanceOf(SensitiveString);
      expect((result.user as Record<string, unknown>)['phone']).toBeUndefined();
    });

    it('should preserve non-string values', () => {
      const config: SensitiveFieldConfig = {
        'data.count': 'sensitive', // number, not string
        'data.active': 'sensitive', // boolean, not string
      };

      const input = {
        data: {
          count: 42,
          active: true,
          secret: 'sensitive',
        },
      };

      const result = wrapSensitiveByPath(input, config);

      expect(result.data.count).toBe(42);
      expect(result.data.active).toBe(true);
      expect(result.data.secret).toBe('sensitive'); // not in config
    });

    it('should handle arrays in the object', () => {
      const config: SensitiveFieldConfig = {
        'user.email': 'sensitive',
      };

      const input = {
        user: { email: 'user@test.local' },
        tags: ['admin', 'user'],
        items: [{ id: 1 }, { id: 2 }],
      };

      const result = wrapSensitiveByPath(input, config);

      expect(result.user.email).toBeInstanceOf(SensitiveString);
      expect(result.tags).toEqual(['admin', 'user']);
      expect(result.items).toEqual([{ id: 1 }, { id: 2 }]);
    });

    it('should preserve Date objects', () => {
      const config: SensitiveFieldConfig = { secret: 'credential' };
      const date = new Date('2025-01-01');
      const input = { secret: 'value', createdAt: date };

      const result = wrapSensitiveByPath(input, config);

      expect(result.createdAt).toBeInstanceOf(Date);
      expect(result.createdAt.getTime()).toBe(date.getTime());
    });
  });

  describe('Payment Service Platform webhook integration', () => {
    it('should wrap all sensitive fields in PSP webhook', () => {
      const wrapped = wrapSensitiveByPath(PSP_AUTHORIZATION_WEBHOOK, PSP_SENSITIVE_FIELDS);

      const metadata = wrapped.notification.metadata;
      const transaction = wrapped.notification.transaction;

      // Secret fields
      expect(metadata.webhookSignature).toBeInstanceOf(SensitiveString);
      expect((metadata.webhookSignature as unknown as SensitiveString).klass).toBe('credential');

      // PII fields
      expect(metadata.cardLastFour).toBeInstanceOf(SensitiveString);
      expect(metadata.cardBinPrefix).toBeInstanceOf(SensitiveString);
      expect(metadata.cardExpiry).toBeInstanceOf(SensitiveString);
      expect(metadata.cardholderName).toBeInstanceOf(SensitiveString);
      expect(metadata.customerIpAddress).toBeInstanceOf(SensitiveString);
      expect(transaction.authorizationDetails).toBeInstanceOf(SensitiveString);

      // Token fields
      expect(metadata.paymentTokenAlias).toBeInstanceOf(SensitiveString);
      expect(metadata.networkReference).toBeInstanceOf(SensitiveString);
      expect(transaction.gatewayReference).toBeInstanceOf(SensitiveString);

      // Non-sensitive fields unchanged
      expect(transaction.status).toBe('AUTHORIZED');
      expect(transaction.outcome).toBe('approved');
      expect(transaction.paymentMethod).toBe('card');
      expect(metadata.fraudCheckPassed).toBe('true');
      expect(metadata.riskScore).toBe('12');
    });

    it('should produce safe JSON output for logging', () => {
      const wrapped = wrapSensitiveByPath(PSP_AUTHORIZATION_WEBHOOK, PSP_SENSITIVE_FIELDS);
      const json = safeStringify(wrapped);
      const parsed = JSON.parse(json) as typeof PSP_AUTHORIZATION_WEBHOOK;

      const metadata = parsed.notification.metadata;
      const transaction = parsed.notification.transaction;

      // Sensitive fields should be redacted
      expect(metadata.webhookSignature).toBe('[REDACTED:credential]');
      expect(metadata.cardLastFour).toBe('[REDACTED:sensitive]');
      expect(metadata.cardBinPrefix).toBe('[REDACTED:sensitive]');
      expect(metadata.customerIpAddress).toBe('[REDACTED:sensitive]');
      expect(transaction.gatewayReference).toBe('[REDACTED:credential]');
      expect(transaction.authorizationDetails).toBe('[REDACTED:sensitive]');

      // Non-sensitive fields should be present
      expect(transaction.status).toBe('AUTHORIZED');
      expect(metadata.fraudCheckPassed).toBe('true');
    });

    it('should allow reveal with proper context', () => {
      const wrapped = wrapSensitiveByPath(PSP_AUTHORIZATION_WEBHOOK, PSP_SENSITIVE_FIELDS);
      const signature = wrapped.notification.metadata
        .webhookSignature as unknown as SensitiveString;

      const reveals: string[] = [];

      withRevealContext(
        {
          name: 'signature-verification',
          reason: 'Verify webhook signature',
          auditReveal: (value) => reveals.push(value.klass),
        },
        () => {
          const raw = signature.reveal();
          expect(raw).toBe('dGVzdC1zaWduYXR1cmUtYmFzZTY0LWVuY29kZWQ=');
        }
      );

      expect(reveals).toContain('credential');
    });
  });
});

describe('unwrapSensitiveByPath', () => {
  it('should unwrap SensitiveString fields back to raw strings', () => {
    const config: SensitiveFieldConfig = {
      'user.email': 'sensitive',
      'user.token': 'credential',
    };

    const input = {
      user: {
        name: 'TestUser',
        email: new SensitiveString('user@test.local', 'sensitive'),
        token: new SensitiveString('tok_test_123', 'credential'),
      },
    };

    const result = unwrapSensitiveByPath(input, config);

    expect(result.user.name).toBe('TestUser');
    expect(result.user.email).toBe('user@test.local');
    expect(result.user.token).toBe('tok_test_123');
  });

  it('should not mutate the original object', () => {
    const config: SensitiveFieldConfig = { email: 'sensitive' };
    const sensitive = new SensitiveString('test@test.local', 'sensitive');
    const original = { email: sensitive };

    unwrapSensitiveByPath(original, config);

    expect(original.email).toBe(sensitive);
    expect(original.email).toBeInstanceOf(SensitiveString);
  });

  it('should audit reveals when context is provided', () => {
    const config: SensitiveFieldConfig = {
      'credentials.apiKey': 'credential',
      'credentials.token': 'credential',
    };

    const wrapped = {
      credentials: {
        apiKey: new SensitiveString('key_test_12345', 'credential'),
        token: new SensitiveString('tok_test_abc', 'credential'),
      },
    };

    const reveals: string[] = [];

    withRevealContext(
      {
        name: 'api-call',
        reason: 'Forward credentials',
        auditReveal: (value) => reveals.push(value.klass),
      },
      () => {
        const unwrapped = unwrapSensitiveByPath(wrapped, config);
        expect(unwrapped.credentials.apiKey).toBe('key_test_12345');
        expect(unwrapped.credentials.token).toBe('tok_test_abc');
      }
    );

    expect(reveals).toContain('credential');
    expect(reveals).toContain('credential');
  });

  it('should round-trip wrap and unwrap correctly', () => {
    const original = {
      user: {
        email: 'user@test.local',
        name: 'TestUser',
      },
      metadata: {
        ip: '10.0.0.1',
        ua: 'TestBrowser/1.0',
      },
    };

    const config: SensitiveFieldConfig = {
      'user.email': 'sensitive',
      'metadata.ip': 'sensitive',
    };

    const wrapped = wrapSensitiveByPath(original, config);

    // Verify wrapped
    expect(wrapped.user.email).toBeInstanceOf(SensitiveString);
    expect(wrapped.metadata.ip).toBeInstanceOf(SensitiveString);

    // Unwrap
    const unwrapped = unwrapSensitiveByPath(wrapped, config);

    // Should match original
    expect(unwrapped).toEqual(original);
  });
});

describe('validateSensitiveFieldConfig', () => {
  it('should validate all paths exist', () => {
    const config: SensitiveFieldConfig = {
      'user.email': 'sensitive',
      'user.name': 'sensitive',
    };

    const sample = {
      user: { email: 'test@test.local', name: 'Test' },
    };

    const result = validateSensitiveFieldConfig(sample, config);

    expect(result.valid).toBe(true);
    expect(result.missingPaths).toEqual([]);
  });

  it('should report missing paths', () => {
    const config: SensitiveFieldConfig = {
      'user.email': 'sensitive',
      'user.phone': 'sensitive', // doesn't exist
      'credentials.apiKey': 'credential', // doesn't exist
    };

    const sample = {
      user: { email: 'test@test.local' },
    };

    const result = validateSensitiveFieldConfig(sample, config);

    expect(result.valid).toBe(false);
    expect(result.missingPaths).toContain('user.phone');
    expect(result.missingPaths).toContain('credentials.apiKey');
  });

  it('should validate PSP config against sample payload', () => {
    const result = validateSensitiveFieldConfig(PSP_AUTHORIZATION_WEBHOOK, PSP_SENSITIVE_FIELDS);

    expect(result.valid).toBe(true);
    expect(result.missingPaths).toEqual([]);
  });
});

describe('checkSensitiveFieldsWrapped', () => {
  it('should detect unwrapped sensitive fields', () => {
    const config: SensitiveFieldConfig = {
      'user.email': 'sensitive',
      'user.token': 'credential',
    };

    const partiallyWrapped = {
      user: {
        email: 'raw@test.local', // not wrapped!
        token: new SensitiveString('tok_123', 'credential'),
      },
    };

    const result = checkSensitiveFieldsWrapped(partiallyWrapped, config);

    expect(result.allWrapped).toBe(false);
    expect(result.unwrappedPaths).toContain('user.email');
    expect(result.unwrappedPaths).not.toContain('user.token');
  });

  it('should pass when all fields are wrapped', () => {
    const config: SensitiveFieldConfig = {
      'user.email': 'sensitive',
      'user.token': 'credential',
    };

    const fullyWrapped = {
      user: {
        email: new SensitiveString('user@test.local', 'sensitive'),
        token: new SensitiveString('tok_123', 'credential'),
      },
    };

    const result = checkSensitiveFieldsWrapped(fullyWrapped, config);

    expect(result.allWrapped).toBe(true);
    expect(result.unwrappedPaths).toEqual([]);
  });

  it('should verify PSP webhook is properly wrapped', () => {
    const wrapped = wrapSensitiveByPath(PSP_AUTHORIZATION_WEBHOOK, PSP_SENSITIVE_FIELDS);
    const result = checkSensitiveFieldsWrapped(wrapped, PSP_SENSITIVE_FIELDS);

    expect(result.allWrapped).toBe(true);
    expect(result.unwrappedPaths).toEqual([]);
  });

  it('should detect raw PSP webhook as unwrapped', () => {
    const result = checkSensitiveFieldsWrapped(PSP_AUTHORIZATION_WEBHOOK, PSP_SENSITIVE_FIELDS);

    expect(result.allWrapped).toBe(false);
    expect(result.unwrappedPaths.length).toBeGreaterThan(0);
    expect(result.unwrappedPaths).toContain('notification.metadata.webhookSignature');
    expect(result.unwrappedPaths).toContain('notification.metadata.cardLastFour');
  });
});

describe('edge cases', () => {
  it('should handle empty config', () => {
    const input = { user: { email: 'test@test.local' } };
    const result = wrapSensitiveByPath(input, {});

    expect(result).toEqual(input);
    expect(result.user.email).toBe('test@test.local');
  });

  it('should handle empty object', () => {
    const config: SensitiveFieldConfig = { 'user.email': 'sensitive' };
    const result = wrapSensitiveByPath({}, config);

    expect(result).toEqual({});
  });

  it('should handle deeply nested paths', () => {
    const config: SensitiveFieldConfig = {
      'a.b.c.d.e.secret': 'credential',
    };

    const input = {
      a: {
        b: {
          c: {
            d: {
              e: {
                secret: 'deep-secret-value',
                public: 'visible',
              },
            },
          },
        },
      },
    };

    const result = wrapSensitiveByPath(input, config);

    expect(result.a.b.c.d.e.secret).toBeInstanceOf(SensitiveString);
    expect(result.a.b.c.d.e.public).toBe('visible');
  });

  it('should handle nested path structures', () => {
    // Note: Some payment providers use keys with dots in the name
    // Our implementation uses dots as path separators, so these keys
    // cannot be directly addressed. This is a known limitation.
    // For such cases, a different accessor syntax would be needed.

    const config: SensitiveFieldConfig = {
      'data.nested.value': 'credential',
    };

    const input = {
      data: {
        nested: {
          value: 'secret-value',
        },
      },
    };

    const result = wrapSensitiveByPath(input, config);
    expect(result.data.nested.value).toBeInstanceOf(SensitiveString);
  });

  it('should preserve already-wrapped SensitiveString values', () => {
    const config: SensitiveFieldConfig = {
      secret: 'credential',
    };

    const existingSensitive = new SensitiveString('already-wrapped', 'credential');
    const input = {
      secret: existingSensitive,
    };

    const result = wrapSensitiveByPath(input, config);

    // Should preserve the existing SensitiveString, not double-wrap
    expect(result.secret).toBe(existingSensitive);
    expect((result.secret as unknown as SensitiveString).klass).toBe('credential');
  });
});
