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
import { zCredential, zSensitiveWithValidation } from '@anthropic-security/sensitive-zod';

// Define schema with sensitive fields
const WebhookSchema = z.object({
  token: zCredential('session_token'),
  email: zSensitiveWithValidation('sensitive', z.string().email(), 'email'),
  note: z.string().optional(),
});

// Parse request body
const webhook = WebhookSchema.parse(req.body);

// Type inference works correctly
// webhook.token is SensitiveString<'credential'>
// webhook.email is SensitiveString<'sensitive'>

// Safe to serialize
res.json(webhook); // Sensitive fields automatically redacted
```

## Available Schemas

```typescript
// Generic sensitive string with specified class + label
zSensitiveString('sensitive', 'email')   // → SensitiveString<'sensitive'>
zSensitiveString('credential', 'token') // → SensitiveString<'credential'>

// Convenience shortcuts
zSensitive('email')        // → SensitiveString<'sensitive'>
zCredential('session_token') // → SensitiveString<'credential'>

// With custom validation
zSensitiveWithValidation('credential', z.string().min(32), 'api_key')

// Optional (returns null for missing)
zSensitiveOptional('sensitive', 'phone')

// Parse from serialized format
zSensitiveDeserialize('credential')
```

## Examples

### User Registration

```typescript
const RegistrationSchema = z.object({
  email: zSensitiveWithValidation('sensitive', z.string().email(), 'email'),
  password: zSensitiveWithValidation(
    'credential',
    z.string()
      .min(8, 'Password must be at least 8 characters')
      .regex(/[A-Z]/, 'Must contain uppercase')
      .regex(/[0-9]/, 'Must contain number'),
    'password'
  ),
  fullName: zSensitive('name'),
  phone: zSensitiveOptional('sensitive', 'phone'),
});
```

### API Authentication

```typescript
const AuthHeaderSchema = z.object({
  authorization: zCredential('auth_header'),
});

const headers = AuthHeaderSchema.parse(req.headers);
```

### Service-to-Service Communication

```typescript
// Receiving service
const PayloadSchema = z.object({
  userId: z.string(),
  token: zSensitiveDeserialize('credential'),
});

const { token } = PayloadSchema.parse(req.body);
// token is SensitiveString<'credential'>, reconstructed from serialized form
```

## Re-exports

For convenience, this package re-exports commonly used items from `@anthropic-security/sensitive-core`:

- `SensitiveString`
- `SensitivityClass`
- `SerializedSensitiveString`
- `RevealContext`
- `withRevealContext`
- `getCurrentRevealContext`
- `safeLog`
- `redactInStructure`

## License

MIT
