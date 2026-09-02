# @platform-sec/sensitive-string-core

Core library for handling sensitive string data with automatic redaction, type-safe classification, and audit-ready reveal patterns.

## Installation

```bash
pnpm add @platform-sec/sensitive-string-core
```

## Requirements

- Node.js 20+
- TypeScript 5.4+ (for best type inference)

## Quick Start

```typescript
import { readFileSync } from 'node:fs';
import {
  SensitiveString,
  safeLog,
  withRevealContext
} from '@platform-sec/sensitive-string-core';

// Read secret from vault-injected file mount (e.g., Kubernetes secrets, HashiCorp Vault)
const apiKey = new SensitiveString(
  readFileSync('/run/secrets/api_key', 'utf-8'),
  'credential',
  'api_key'
);

// Safe for logging - automatically redacted
console.log('Using API key:', apiKey);
// Output: Using API key: SensitiveString<credential:api_key> { [REDACTED:credential] }

// JSON serialization is safe
console.log(JSON.stringify({ key: apiKey }));
// Output: {"key":"[REDACTED:credential]"}

// Explicit reveal when needed
const raw = apiKey.reveal({ name: 'api-call', reason: 'authenticating' });
```

## Features

- **Automatic Redaction**: `toString()`, `toJSON()`, `util.inspect()` all return redacted values
- **True Private Fields**: Uses ES2022 `#private` for runtime encapsulation
- **Sensitivity Classification**: `sensitive` and `credential` (use labels for finer categorization)
- **Constant-Time Comparison**: Timing-safe equality for credentials
- **Audit Context**: AsyncLocalStorage-based context propagation
- **Path-Based Wrapping**: Wrap sensitive fields in complex objects by path
- **Zero External Dependencies**: Only uses Node.js built-ins

## Handling Webhooks and API Payloads

When receiving data from external services (payment gateways, identity providers, etc.), use `wrapSensitiveByPath` to protect sensitive fields:

```typescript
import { 
  wrapSensitiveByPath,
  SensitiveFieldConfig,
} from '@platform-sec/sensitive-string-core';

// 1. Define which fields are sensitive
const WEBHOOK_SENSITIVE_FIELDS: SensitiveFieldConfig = {
  'notification.metadata.webhookSignature': 'credential',
  'notification.metadata.cardLastFour': { klass: 'sensitive', label: 'card_last_four' },
  'notification.metadata.customerIpAddress': { klass: 'sensitive', label: 'customer_ip' },
  'notification.transaction.gatewayReference': 'credential',
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
import { validateSensitiveFieldConfig } from '@platform-sec/sensitive-string-core';

test('sensitive field config matches payload structure', () => {
  const samplePayload = { /* your sample webhook */ };
  const result = validateSensitiveFieldConfig(samplePayload, WEBHOOK_SENSITIVE_FIELDS);
  
  expect(result.valid).toBe(true);
  expect(result.missingPaths).toEqual([]);
});
```

Configuration values may use the short class form or `{ klass, label }`. Labels
appear in inspection and audit metadata without exposing the protected value.

## Process-global state

The policy registry and reveal-context storage are shared across duplicate
installed copies of core through `Symbol.for()`. Policy registration is mutable
process-global configuration: it protects against accidental misuse and
misconfiguration, but code already executing in the process can replace a
policy and must be trusted.

## API

See the [main README](../../README.md) for full API documentation.

## License

MIT
