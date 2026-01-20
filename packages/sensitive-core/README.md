# @anthropic-security/sensitive-core

Core library for handling sensitive string data with automatic redaction, type-safe classification, and audit-ready reveal patterns.

## Installation

```bash
pnpm add @anthropic-security/sensitive-core
```

## Requirements

- Node.js 20+
- TypeScript 5.4+ (for best type inference)

## Quick Start

```typescript
import { 
  SensitiveString, 
  safeLog, 
  withRevealContext 
} from '@anthropic-security/sensitive-core';

// Create a sensitive value
const apiKey = new SensitiveString(process.env.API_KEY!, 'secret');

// Safe for logging - automatically redacted
console.log('Using API key:', apiKey);
// Output: Using API key: SensitiveString<secret> { [REDACTED:secret] }

// JSON serialization is safe
console.log(JSON.stringify({ key: apiKey }));
// Output: {"key":"[REDACTED:secret]"}

// Explicit reveal when needed
const raw = apiKey.reveal({ name: 'api-call', reason: 'authenticating' });
```

## Features

- **Automatic Redaction**: `toString()`, `toJSON()`, `util.inspect()` all return redacted values
- **True Private Fields**: Uses ES2022 `#private` for runtime encapsulation
- **Sensitivity Classification**: `generic`, `secret`, `token`, `pii_email`, `pii_generic`
- **Constant-Time Comparison**: Timing-safe equality for secrets and tokens
- **Audit Context**: AsyncLocalStorage-based context propagation
- **Path-Based Wrapping**: Wrap sensitive fields in complex objects by path
- **Zero External Dependencies**: Only uses Node.js built-ins

## Handling Webhooks and API Payloads

When receiving data from external services (payment gateways, identity providers, etc.), use `wrapSensitiveByPath` to protect sensitive fields:

```typescript
import { 
  wrapSensitiveByPath,
  SensitiveFieldConfig,
} from '@anthropic-security/sensitive-core';

// 1. Define which fields are sensitive
const WEBHOOK_SENSITIVE_FIELDS: SensitiveFieldConfig = {
  'notification.metadata.webhookSignature': 'secret',
  'notification.metadata.cardLastFour': 'pii_generic',
  'notification.metadata.customerIpAddress': 'pii_generic',
  'notification.transaction.gatewayReference': 'token',
};

// 2. Create a helper that atomically parses + protects
function parseAndProtectWebhook<T extends object>(
  rawBody: string,
  parser: (body: string) => T,
  sensitiveFields: SensitiveFieldConfig
): T {
  // Parse and wrap in one step - no window for raw data to leak
  return wrapSensitiveByPath(parser(rawBody), sensitiveFields);
}

// 3. Use at your HTTP boundary
app.post('/webhooks/payment', (req, res) => {
  const notification = parseAndProtectWebhook(
    req.body,
    JSON.parse,
    WEBHOOK_SENSITIVE_FIELDS
  );
  
  // Safe to log - SensitiveStrings auto-redact via toJSON()
  logger.info('Received webhook', notification);
});
```

### Important: wrapSensitiveByPath Expects Parsed Objects

The `wrapSensitiveByPath` utility operates on already-parsed JavaScript objects:

```typescript
// ✅ CORRECT: Pass parsed object
const parsed = JSON.parse(rawBody);
const safe = wrapSensitiveByPath(parsed, config);

// ❌ WRONG: Don't pass raw string
const safe = wrapSensitiveByPath(rawBody, config); // Won't work!
```

### Validating Your Configuration

Use `validateSensitiveFieldConfig` in tests to catch path typos:

```typescript
import { validateSensitiveFieldConfig } from '@anthropic-security/sensitive-core';

test('sensitive field config matches payload structure', () => {
  const samplePayload = { /* your sample webhook */ };
  const result = validateSensitiveFieldConfig(samplePayload, WEBHOOK_SENSITIVE_FIELDS);
  
  expect(result.valid).toBe(true);
  expect(result.missingPaths).toEqual([]);
});
```

## API

See the [main README](../../README.md) for full API documentation.

## License

MIT
