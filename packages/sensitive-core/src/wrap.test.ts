import { describe, it, expect } from 'vitest';
import {
  wrapSensitiveByPath,
  unwrapSensitiveByPath,
  validateSensitiveFieldConfig,
  checkSensitiveFieldsWrapped,
  wrapSensitiveByClassification,
  checkClassifiedFieldsWrapped,
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

    it('wraps every string element of an array at a declared path', () => {
      // MeltStudio/config-loader's shape: one declaration over a list of
      // connection strings. Until 2026-09-19 the list was skipped silently.
      const CANARY_A = 'LEAKED_SECRET_replica_ddd444';
      const CANARY_B = 'LEAKED_SECRET_replica_eee555';
      const config: SensitiveFieldConfig = {
        'db.replicaUrls': { klass: 'credential', label: 'replica', options: { ttl: 60_000 } },
      };
      const input = { db: { replicaUrls: [CANARY_A, [CANARY_B], 5, null, { url: CANARY_B }] } };

      const result = wrapSensitiveByPath(input, config);
      const list = result.db.replicaUrls as unknown[];

      expect(list[0]).toBeInstanceOf(SensitiveString);
      expect((list[0] as SensitiveString).klass).toBe('credential');
      expect((list[0] as SensitiveString).label).toBe('replica');
      expect((list[0] as SensitiveString).expiresAt).toBeInstanceOf(Date);
      expect((list[1] as unknown[])[0]).toBeInstanceOf(SensitiveString);
      // A number, null and an object are not strings and are left alone; the
      // object's own string is reached by a deeper path or not at all, and
      // `validateSensitiveFieldConfig` reports this list for that reason.
      expect(list[2]).toBe(5);
      expect(list[3]).toBeNull();
      expect(list[4]).toEqual({ url: CANARY_B });
      // The caller's array is untouched.
      expect(input.db.replicaUrls[0]).toBe(CANARY_A);
      expect(safeStringify({ list: list.slice(0, 2) })).not.toContain(CANARY_A);
      expect(safeStringify({ list: list.slice(0, 2) })).not.toContain(CANARY_B);
    });

    it('keeps an already wrapped element of an array as it is', () => {
      const existing = new SensitiveString('tok', 'sensitive', 'existing');
      const config: SensitiveFieldConfig = { list: 'credential' };

      const result = wrapSensitiveByPath({ list: [existing, 'plain'] }, config);

      expect(result.list[0]).toBe(existing);
      expect((result.list[1] as unknown as SensitiveString).klass).toBe('credential');
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

  it('unwraps every instance in an array at a declared path, auditing each', () => {
    const config: SensitiveFieldConfig = { 'db.replicaUrls': 'credential' };
    const wrapped = wrapSensitiveByPath({ db: { replicaUrls: ['a', ['b'], 5] } }, config);
    const audited: string[] = [];

    const result = unwrapSensitiveByPath(wrapped, config, {
      name: 'forward',
      auditReveal: (value) => audited.push(value.klass),
    });

    expect(result.db.replicaUrls).toEqual(['a', ['b'], 5]);
    expect(audited).toEqual(['credential', 'credential']);
    // The wrapped structure is not mutated by the unwrap.
    expect(wrapped.db.replicaUrls[0]).toBeInstanceOf(SensitiveString);
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

  it('reports a declared path holding a value nothing will wrap', () => {
    // The case that used to pass silently, found by the corpus study on
    // MeltStudio/config-loader: one declaration, on a list, written once and
    // read by nothing. Before 2026-09-19 this function answered `valid: true`
    // for a config that protected nothing. The list itself is wrappable now;
    // an object, a number and a list with either in it are still not.
    const CANARY = 'LEAKED_SECRET_pg_replica_aaa111';
    const config: SensitiveFieldConfig = {
      'db.primaryUrl': 'credential',
      'db.replicaUrls': 'credential',
      'db.pool': 'credential',
      'db.mixed': 'credential',
    };
    const sample = {
      db: {
        primaryUrl: 'postgres://primary',
        replicaUrls: [CANARY, [CANARY]],
        pool: { size: 4 },
        mixed: [CANARY, { url: CANARY }],
      },
    };

    const result = validateSensitiveFieldConfig(sample, config);

    expect(result.valid).toBe(false);
    expect(result.unwrappablePaths).toEqual(['db.pool', 'db.mixed']);
    // Not a typo, so not a missing path: the two lists mean different things and
    // have different fixes.
    expect(result.missingPaths).toEqual([]);
  });

  it('separates a path that is absent from one that is the wrong shape', () => {
    const config: SensitiveFieldConfig = { 'a.gone': 'credential', 'a.count': 'credential' };
    const sample = { a: { count: 3 } };

    const result = validateSensitiveFieldConfig(sample, config);

    expect(result.missingPaths).toEqual(['a.gone']);
    expect(result.unwrappablePaths).toEqual(['a.count']);
  });

  it('accepts an array of strings and an empty array at a declared path', () => {
    const config: SensitiveFieldConfig = {
      'db.replicaUrls': 'credential',
      'db.none': 'credential',
    };
    const sample = { db: { replicaUrls: ['a', 'b'], none: [] } };

    expect(validateSensitiveFieldConfig(sample, config)).toEqual({
      valid: true,
      missingPaths: [],
      unwrappablePaths: [],
    });
  });

  it('accepts a path already holding a SensitiveString', () => {
    // Validation runs against a sample payload, which may be pre-wrapped. An
    // instance is the goal state, not a problem to report.
    const config: SensitiveFieldConfig = { 'user.token': 'credential' };
    const sample = { user: { token: new SensitiveString('tok_123', 'credential') } };

    expect(validateSensitiveFieldConfig(sample, config).valid).toBe(true);
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

  it('reports a declared path holding an unwrapped non-string', () => {
    // The fail-open this function's own documentation walked a caller into:
    // `if (!check.allWrapped) throw` was the documented guard, and a config
    // declaring a list of secrets passed it while the secrets went out in the
    // clear. The list is wrapped now, so the unwrapped shapes are an object at
    // the path and a list with a plain string still in it. The canary is the
    // point: it must not reach a serialized surface while the check says
    // everything is wrapped.
    const CANARY = 'LEAKED_SECRET_replica_bbb222';
    const config: SensitiveFieldConfig = {
      'db.pool': 'credential',
      'db.replicaUrls': 'credential',
    };
    const wrapped = wrapSensitiveByPath({ db: { pool: { url: CANARY } } }, config);
    (wrapped.db as { replicaUrls?: unknown[] }).replicaUrls = [
      new SensitiveString(CANARY, 'credential'),
      CANARY,
    ];

    const result = checkSensitiveFieldsWrapped(wrapped, config);

    expect(result.allWrapped).toBe(false);
    expect(result.unwrappedPaths).toEqual(['db.pool', 'db.replicaUrls']);
    // And the reason it matters, stated as the canary test the house style asks
    // for: the value the guard vouched for is still in the output.
    expect(JSON.stringify(wrapped)).toContain(CANARY);
  });

  it('counts a declared array as wrapped once every element is', () => {
    const CANARY = 'LEAKED_SECRET_replica_ccc333';
    const config: SensitiveFieldConfig = { 'db.replicaUrls': 'credential' };
    const wrapped = wrapSensitiveByPath({ db: { replicaUrls: [CANARY, [CANARY]] } }, config);

    expect(checkSensitiveFieldsWrapped(wrapped, config)).toEqual({
      allWrapped: true,
      unwrappedPaths: [],
    });
    expect(JSON.stringify(wrapped)).not.toContain(CANARY);
  });

  it('does not count an absent field as unwrapped', () => {
    // An optional field that is not there carries no secret.
    // `validateSensitiveFieldConfig` is what reports a path that should exist.
    const config: SensitiveFieldConfig = { 'user.token': 'credential' };

    expect(checkSensitiveFieldsWrapped({ user: {} }, config).allWrapped).toBe(true);
    expect(checkSensitiveFieldsWrapped({ user: { token: null } }, config).allWrapped).toBe(true);
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

describe('wrapSensitiveByPath construction options', () => {
  it('binds a deadline supplied per field', () => {
    const config: SensitiveFieldConfig = {
      'creds.password': { klass: 'credential', label: 'db#password', options: { ttl: 60_000 } },
    };

    const result = wrapSensitiveByPath({ creds: { password: 'pw' } }, config);
    const wrapped = result.creds.password as unknown as SensitiveString;

    expect(wrapped.label).toBe('db#password');
    expect(wrapped.isExpired()).toBe(false);
    expect(wrapped.ttlRemaining()).toBeGreaterThan(0);
    expect(wrapped.ttlRemaining()).toBeLessThanOrEqual(60_000);
  });

  it('leaves a field with no options unbounded', () => {
    const result = wrapSensitiveByPath({ token: 'tok' }, { token: { klass: 'credential' } });
    const wrapped = result.token as unknown as SensitiveString;

    expect(wrapped.expiresAt).toBeUndefined();
  });

  it('applies an expired deadline rather than ignoring it', () => {
    const result = wrapSensitiveByPath(
      { token: 'tok' },
      { token: { klass: 'credential', options: { expiresAt: new Date(Date.now() - 1000) } } }
    );

    expect((result.token as unknown as SensitiveString).isExpired()).toBe(true);
  });
});

describe('wrapSensitiveByClassification', () => {
  const CANARY_A = 'CLASSIFIED_CANARY_a1f0';
  const CANARY_B = 'CLASSIFIED_CANARY_b2e1';
  const CANARY_C = 'CLASSIFIED_CANARY_c3d2';

  describe('the inverted entry', () => {
    it('wraps every string leaf under a fallback, and keeps what fields declares plain', () => {
      // A header bag: the caller knows one header is wanted readable and
      // cannot enumerate the rest, which is the shape the path helper cannot
      // express.
      const headers = {
        referer: 'https://app.example.com/page',
        host: 'api.example.com',
        authorization: `Bearer ${CANARY_A}`,
        'x-forwarded-for': CANARY_B,
        'x-unexpected-header': CANARY_C,
      };

      const wrapped = wrapSensitiveByClassification(headers, {
        fields: { referer: 'plain', host: 'plain' },
        fallback: 'sensitive',
      });

      expect(wrapped.referer).toBe(headers.referer);
      expect(wrapped.host).toBe(headers.host);
      expect(wrapped.authorization).toBeInstanceOf(SensitiveString);
      expect(wrapped['x-forwarded-for']).toBeInstanceOf(SensitiveString);
      // The key nobody anticipated is the one the path helper would have missed.
      expect(wrapped['x-unexpected-header']).toBeInstanceOf(SensitiveString);

      const out = safeStringify(wrapped);
      expect(out).not.toContain(CANARY_A);
      expect(out).not.toContain(CANARY_B);
      expect(out).not.toContain(CANARY_C);
      expect(out).toContain('app.example.com');
    });

    it('does not mutate the input', () => {
      const input = { token: CANARY_A, nested: { key: CANARY_B } };
      wrapSensitiveByClassification(input, { fallback: 'credential' });

      expect(input.token).toBe(CANARY_A);
      expect(input.nested.key).toBe(CANARY_B);
    });

    it('wraps every element of an array of strings under the array’s own name', () => {
      // The case the path helper skips silently: a declared path holding a
      // list of connection strings.
      const config = { db: { replicaUrls: [CANARY_A, CANARY_B], poolSize: 4 } };

      const wrapped = wrapSensitiveByClassification(config, {
        fields: { 'db.replicaUrls': 'credential' },
      });

      expect(wrapped.db.replicaUrls).toHaveLength(2);
      for (const url of wrapped.db.replicaUrls) {
        expect(url).toBeInstanceOf(SensitiveString);
        expect((url as unknown as SensitiveString).klass).toBe('credential');
      }
      expect(wrapped.db.poolSize).toBe(4);
      expect(safeStringify(wrapped)).not.toContain(CANARY_A);
      expect(safeStringify(wrapped)).not.toContain(CANARY_B);
    });

    it('classifies a nested leaf by its full path, its key path, and its nearest key', () => {
      const payload = {
        db: { password: CANARY_A, port: '5432' },
        cache: { password: CANARY_B },
        items: [{ apiKey: CANARY_C, name: 'first' }],
      };

      const wrapped = wrapSensitiveByClassification(payload, {
        // Full path names one leaf; a rule on the nearest key reaches the
        // other password and the key inside the array element.
        fields: { 'db.port': 'plain' },
        rules: [
          { pattern: /^password$/, klass: 'credential' },
          { pattern: /Key$/, klass: 'credential' },
        ],
        fallback: 'sensitive',
      });

      expect(wrapped.db.port).toBe('5432');
      expect((wrapped.db.password as unknown as SensitiveString).klass).toBe('credential');
      expect((wrapped.cache.password as unknown as SensitiveString).klass).toBe('credential');
      expect((wrapped.items[0]!.apiKey as unknown as SensitiveString).klass).toBe('credential');
      expect((wrapped.items[0]!.name as unknown as SensitiveString).klass).toBe('sensitive');
    });

    it('classifies by name pattern alone when the spec has no fallback', () => {
      // A provider credential object whose keys are data: one rule set rather
      // than one list per provider.
      const provider = {
        apiKey: CANARY_A,
        secretKey: CANARY_B,
        region: 'us-east-1',
        from: 'noreply@x',
      };

      const wrapped = wrapSensitiveByClassification(provider, {
        rules: [{ pattern: /key$/i, klass: 'credential' }],
      });

      expect(wrapped.apiKey).toBeInstanceOf(SensitiveString);
      expect(wrapped.secretKey).toBeInstanceOf(SensitiveString);
      expect(wrapped.region).toBe('us-east-1');
      expect(wrapped.from).toBe('noreply@x');
    });

    it('leaves numbers, booleans, null and dates as they are whatever the spec says', () => {
      const when = new Date('2026-01-01T00:00:00Z');
      const input = { port: 5432, tls: true, none: null, when, name: CANARY_A };

      const wrapped = wrapSensitiveByClassification(input, { fallback: 'credential' });

      expect(wrapped.port).toBe(5432);
      expect(wrapped.tls).toBe(true);
      expect(wrapped.none).toBeNull();
      expect(wrapped.when).toBeInstanceOf(Date);
      expect(wrapped.when.getTime()).toBe(when.getTime());
      expect(wrapped.name).toBeInstanceOf(SensitiveString);
    });

    it('keeps an already wrapped value and does not descend into it', () => {
      const existing = new SensitiveString(CANARY_A, 'credential', 'existing');
      const wrapped = wrapSensitiveByClassification({ token: existing }, { fallback: 'sensitive' });

      expect(wrapped.token).toBe(existing);
      expect(wrapped.token.klass).toBe('credential');
    });

    it('applies a label and construction options to every wrapped leaf', () => {
      const wrapped = wrapSensitiveByClassification(
        { a: { token: CANARY_A }, b: [CANARY_B] },
        { fallback: 'credential' },
        { label: (path, key) => `plugin:${path}:${key}`, options: { ttl: 60_000 } }
      );

      const token = wrapped.a.token as unknown as SensitiveString;
      const element = wrapped.b[0] as unknown as SensitiveString;
      expect(token.label).toBe('plugin:a.token:token');
      expect(element.label).toBe('plugin:b.0:b');
      expect(token.expiresAt).toBeInstanceOf(Date);
      expect(element.expiresAt).toBeInstanceOf(Date);

      const fixed = wrapSensitiveByClassification(
        { x: CANARY_A },
        { fallback: 'sensitive' },
        {
          label: 'fixed',
        }
      );
      expect((fixed.x as unknown as SensitiveString).label).toBe('fixed');
    });

    it('keeps an own __proto__ key inert, and wraps a string under any key the payload chose', () => {
      const body = JSON.parse(
        `{"__proto__": {"isAdmin": true}, "token": "${CANARY_A}", "constructor": "${CANARY_B}", "prototype": "${CANARY_C}"}`
      ) as { token: string; isAdmin?: boolean; constructor: unknown; prototype: unknown };

      const wrapped = wrapSensitiveByClassification(body, { fallback: 'credential' });

      expect(wrapped.isAdmin).toBeUndefined();
      expect(Object.getPrototypeOf(wrapped)).toBe(Object.prototype);
      expect(wrapped.token).toBeInstanceOf(SensitiveString);
      // A header named `constructor` is a legal header, and under a fallback
      // a string beneath it is exactly what the caller meant to wrap. The
      // review that found this had the check function vouching for it.
      expect(wrapped.constructor).toBeInstanceOf(SensitiveString);
      expect(wrapped.prototype).toBeInstanceOf(SensitiveString);
      const out = safeStringify(wrapped);
      expect(out).not.toContain(CANARY_B);
      expect(out).not.toContain(CANARY_C);

      const proto = JSON.parse(`{"__proto__": "${CANARY_A}"}`) as Record<string, unknown>;
      const wrappedProto = wrapSensitiveByClassification(proto, { fallback: 'credential' });
      expect(Object.getPrototypeOf(wrappedProto)).toBe(Object.prototype);
      expect(Object.getOwnPropertyDescriptor(wrappedProto, '__proto__')?.value).toBeInstanceOf(
        SensitiveString
      );
      expect(JSON.stringify(wrappedProto)).not.toContain(CANARY_A);
    });

    it('refuses a protected value as the whole object, rather than corrupting it', () => {
      const instance = new SensitiveString(CANARY_A, 'credential', 'whole');

      expect(() => wrapSensitiveByClassification(instance, { fallback: 'credential' })).toThrow(
        TypeError
      );
      expect(() => wrapSensitiveByPath(instance, { klass: 'credential' })).toThrow(TypeError);
      // Untouched: the deep clone returns an instance by reference, and a walk
      // over it would have wrapped its own `klass` in place.
      expect(instance.klass).toBe('credential');
      expect(instance.reveal()).toBe(CANARY_A);
    });

    it('names a root-level array element by its index alone', () => {
      const labels: string[] = [];
      wrapSensitiveByClassification(
        [CANARY_A],
        { fallback: 'credential' },
        {
          label: (path) => {
            labels.push(path);
            return undefined;
          },
        }
      );

      expect(labels).toEqual(['0']);
      expect(
        checkClassifiedFieldsWrapped([CANARY_A], { fallback: 'credential' }).unwrappedPaths
      ).toEqual(['0']);
    });

    it('refuses a non-object input', () => {
      expect(() =>
        wrapSensitiveByClassification('a string' as unknown as object, { fallback: 'sensitive' })
      ).toThrow(TypeError);
      expect(() =>
        wrapSensitiveByClassification(null as unknown as object, { fallback: 'sensitive' })
      ).toThrow(TypeError);
    });

    it('pairs with unwrapSensitiveByPath as the allowlist on the way out', () => {
      const wrapped = wrapSensitiveByClassification(
        { token: CANARY_A, other: CANARY_B },
        { fallback: 'credential' }
      );

      const out = unwrapSensitiveByPath(wrapped, { token: 'credential' }, { name: 'forward' });

      expect(out.token).toBe(CANARY_A);
      expect(out.other).toBeInstanceOf(SensitiveString);
    });
  });

  describe('checkClassifiedFieldsWrapped', () => {
    it('reports the string leaves the spec says are sensitive and that are still plain', () => {
      const payload = {
        referer: 'https://app.example.com',
        authorization: CANARY_A,
        nested: { list: [CANARY_B, 'x'] },
        port: 5432,
      };

      const check = checkClassifiedFieldsWrapped(payload, {
        fields: { referer: 'plain' },
        fallback: 'credential',
      });

      expect(check.allWrapped).toBe(false);
      expect(check.unwrappedPaths).toEqual(['authorization', 'nested.list.0', 'nested.list.1']);
      expect(JSON.stringify(check)).not.toContain(CANARY_A);
      expect(JSON.stringify(check)).not.toContain(CANARY_B);
    });

    it('reports a key the object carries and no config named', () => {
      // The gap `checkSensitiveFieldsWrapped` cannot see: it walks the config.
      const fromPlugin = { accessKeyId: 'AKIA', secretAccessKey: CANARY_A, sessionToken: CANARY_B };
      const declared: SensitiveFieldConfig = { secretAccessKey: 'credential' };

      const wrapped = wrapSensitiveByPath(fromPlugin, declared);
      expect(checkSensitiveFieldsWrapped(wrapped, declared).allWrapped).toBe(true);

      const check = checkClassifiedFieldsWrapped(wrapped, {
        fields: { accessKeyId: 'plain' },
        fallback: 'credential',
      });
      expect(check.allWrapped).toBe(false);
      expect(check.unwrappedPaths).toEqual(['sessionToken']);
    });

    it('passes once the same spec has wrapped the object', () => {
      const spec = { fields: { name: 'plain' as const }, fallback: 'sensitive' as const };
      const wrapped = wrapSensitiveByClassification(
        { name: 'n', a: CANARY_A, b: [CANARY_B] },
        spec
      );

      expect(checkClassifiedFieldsWrapped(wrapped, spec)).toEqual({
        allWrapped: true,
        unwrappedPaths: [],
      });
    });

    it('reports a plain string under constructor, prototype or an own __proto__', () => {
      const body = JSON.parse(
        `{"constructor": "${CANARY_A}", "prototype": "x", "__proto__": "y"}`
      ) as Record<string, unknown>;

      const check = checkClassifiedFieldsWrapped(body, { fallback: 'credential' });

      expect(check.allWrapped).toBe(false);
      expect(check.unwrappedPaths).toEqual(['constructor', 'prototype', '__proto__']);
    });

    it('answers allWrapped for something that is not a container', () => {
      expect(checkClassifiedFieldsWrapped('string', { fallback: 'sensitive' }).allWrapped).toBe(
        true
      );
      expect(checkClassifiedFieldsWrapped(null, { fallback: 'sensitive' }).allWrapped).toBe(true);
    });
  });
});
