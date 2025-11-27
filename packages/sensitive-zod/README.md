# @anthropic-security/sensitive-zod

Zod integration for SensitiveString - parse and validate input directly into sensitive types at boundary layers.

## Installation

```bash
pnpm add @anthropic-security/sensitive-zod zod
```

## Requirements

- Node.js 20+
- Zod 3.22+
- @anthropic-security/sensitive-core (peer dependency)

## Quick Start

```typescript
import { z } from 'zod';
import { zSensitive, zSensitiveEmail } from '@anthropic-security/sensitive-zod';

// Define schema with sensitive fields
const WebhookSchema = z.object({
  token: zSensitive('token'),
  email: zSensitiveEmail(),
  note: z.string().optional(),
});

// Parse request body
const webhook = WebhookSchema.parse(req.body);

// Type inference works correctly
// webhook.token is SensitiveString<'token'>
// webhook.email is SensitiveString<'pii_email'>

// Safe to serialize
res.json(webhook); // Sensitive fields automatically redacted
```

## Available Schemas

```typescript
// Generic sensitive string with specified class
zSensitive('token')        // → SensitiveString<'token'>
zSensitive('secret')       // → SensitiveString<'secret'>
zSensitive('pii_email')    // → SensitiveString<'pii_email'>

// Email with format validation
zSensitiveEmail()          // → SensitiveString<'pii_email'>

// Convenience shortcuts
zSensitivePII()            // → SensitiveString<'pii_generic'>
zSensitiveSecret()         // → SensitiveString<'secret'>
zSensitiveToken()          // → SensitiveString<'token'>

// With custom validation
zSensitiveWithValidation('secret', z.string().min(32))

// Optional (returns null for missing)
zSensitiveOptional('secret')

// Parse from envelope format
zSensitiveFromEnvelope('token')
```

## Examples

### User Registration

```typescript
const RegistrationSchema = z.object({
  email: zSensitiveEmail(),
  password: zSensitiveWithValidation(
    'secret',
    z.string()
      .min(8, 'Password must be at least 8 characters')
      .regex(/[A-Z]/, 'Must contain uppercase')
      .regex(/[0-9]/, 'Must contain number')
  ),
  fullName: zSensitivePII(),
  phone: zSensitiveOptional('pii_generic'),
});
```

### API Authentication

```typescript
const AuthHeaderSchema = z.object({
  authorization: zSensitive('token'),
});

const headers = AuthHeaderSchema.parse(req.headers);
```

### Service-to-Service Communication

```typescript
// Receiving service
const PayloadSchema = z.object({
  userId: z.string(),
  token: zSensitiveFromEnvelope('token'),
});

const { token } = PayloadSchema.parse(req.body);
// token is SensitiveString<'token'>, reconstructed from envelope
```

## Re-exports

For convenience, this package re-exports commonly used items from `@anthropic-security/sensitive-core`:

- `SensitiveString`
- `SensitivityClass`
- `SensitiveEnvelope`
- `RevealContext`
- `withRevealContext`
- `getCurrentRevealContext`
- `safeLog`
- `redactInStructure`

## License

MIT
