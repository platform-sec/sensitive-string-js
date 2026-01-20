# Webhook Helper Example

This example demonstrates how to create atomic parse-and-protect helpers for handling sensitive webhook payloads from payment service providers.

## The Problem

When receiving webhooks, raw sensitive data can leak if parsing and protection aren't atomic:

```typescript
// ❌ DANGEROUS: Raw data can leak between these lines
const parsed = JSON.parse(req.body);
logger.debug('Received:', parsed);  // LEAK! Logs raw card data
const safe = wrapSensitiveByPath(parsed, config);
```

## The Solution

Create a helper that combines parsing and protection in a single step:

```typescript
// ✅ SAFE: Single atomic operation
const safe = parseAndProtectWebhook(req.body, JSON.parse, config);
logger.debug('Received:', safe);  // Safe - SensitiveStrings auto-redact in JSON/toString
```

## Files

- `webhook-helper.ts` - Generic helper function and example configurations
- `webhook-helper.test.ts` - Tests demonstrating usage patterns

## Usage

```typescript
import { 
  parsePspWebhook,
  PSP_SENSITIVE_FIELDS
} from './webhook-helper';
import type { PspWebhookPayload } from './webhook-helper';

// In your HTTP handler
app.post('/webhooks/payment', (req, res) => {
  // Use the pre-configured handler for the sample PSP shape
  const notification = parsePspWebhook(req.body);
  
  // Safe to log entire payload - SensitiveStrings auto-redact
  logger.info('Webhook received', notification);
});

// Or keep your own parser but keep it typed
const parseFromSdk = (body: string): PspWebhookPayload => yourSdk.parseWebhook(body);
const notification = parseAndProtectWebhook(
  req.body,
  parseFromSdk,
  PSP_SENSITIVE_FIELDS
);
```

## Key Points

1. **`wrapSensitiveByPath` expects parsed objects** - not raw strings
2. **Combine parsing + protection** - no gap for sensitive data to leak
3. **Define sensitivity configs per provider** - easy to audit and maintain
4. **Use typed parsers** - match the parser signature to your payload shape to avoid `any` escaping into tests/handlers
5. **Validate configs in tests** - catch path typos before production
