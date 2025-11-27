# SensitiveString

[![Node.js 20+](https://img.shields.io/badge/node-20%2B-brightgreen)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.4%2B-blue)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Enterprise-grade library for handling sensitive string data in Node.js with **automatic redaction**, **type-safe classification**, and **audit-ready reveal patterns**.

## Why SensitiveString?

In typical Node.js services, sensitive data (tokens, PII, secrets) spreads as plain `string` values, making it trivial to accidentally:

- Log them to console/files
- Serialize them in JSON responses
- Forward them to third-party services

**SensitiveString** provides a centralized abstraction that:

- **Marks data as sensitive** at the type level
- **Redacts by default** in all human-readable contexts
- **Forces explicit, auditable access** for raw values

```typescript
import { SensitiveString } from '@anthropic-security/sensitive-core';

const apiKey = new SensitiveString(process.env.API_KEY!, 'secret');

console.log(apiKey);                  // SensitiveString<secret> { [REDACTED:secret] }
console.log(JSON.stringify({apiKey})); // {"apiKey":"[REDACTED:secret]"}

// Explicit access when needed
const raw = apiKey.reveal({ name: 'api-call', reason: 'authenticating' });
```

---

## Quick Start

### Installation

```bash
# Using pnpm (recommended)
pnpm add @anthropic-security/sensitive-core

# With Zod integration
pnpm add @anthropic-security/sensitive-core @anthropic-security/sensitive-zod zod
```

### Basic Usage

```typescript
import { SensitiveString, safeLog } from '@anthropic-security/sensitive-core';

// Create sensitive values
const token = new SensitiveString('sk-abc123secret', 'token');
const email = new SensitiveString('user@example.com', 'pii_email');

// Safe for logging - automatically redacted
console.log('User:', safeLog({ token, email }));
// Output: User: { token: '[REDACTED:token]', email: '[REDACTED:pii_email]' }

// Explicit reveal when needed
const rawToken = token.reveal();
await callExternalAPI(rawToken);
```

### With Zod Validation

```typescript
import { z } from 'zod';
import { zSensitive, zSensitiveEmail } from '@anthropic-security/sensitive-zod';

const WebhookSchema = z.object({
  token: zSensitive('token'),
  email: zSensitiveEmail(),
  note: z.string().optional(),
});

// Parse input directly into SensitiveString instances
const webhook = WebhookSchema.parse(req.body);

// Type-safe: webhook.token is SensitiveString<'token'>
// Type-safe: webhook.email is SensitiveString<'pii_email'>

// JSON serialization is safe
res.json(webhook); // Sensitive fields automatically redacted
```

---

## Core Concepts

### Sensitivity Classes

Data is classified by sensitivity level:

| Class | Use Case | Constant-Time Comparison |
|-------|----------|-------------------------|
| `generic` | Basic sensitive data | No |
| `secret` | Passwords, API keys | Yes |
| `token` | Session/auth tokens | Yes |
| `pii_email` | Email addresses | No |
| `pii_generic` | Other PII (names, addresses) | No |

### Automatic Redaction

`SensitiveString` overrides all serialization methods:

```typescript
const secret = new SensitiveString('my-secret', 'secret');

// All of these are safe:
secret.toString()           // "[REDACTED:secret]"
JSON.stringify(secret)      // "\"[REDACTED:secret]\""
util.inspect(secret)        // "SensitiveString<secret> { [REDACTED:secret] }"
console.log(secret)         // SensitiveString<secret> { [REDACTED:secret] }
`Value: ${secret}`          // "Value: [REDACTED:secret]"
```

### Explicit Reveal

Raw values require explicit access:

```typescript
// Basic reveal
const raw = secret.reveal();

// With audit context
const raw = secret.reveal({
  name: 'payment-processing',
  reason: 'sending to payment gateway'
});
```

### Context Propagation (AsyncLocalStorage)

Use `withRevealContext` to propagate audit context through async operations:

```typescript
import { withRevealContext, SensitiveString } from '@anthropic-security/sensitive-core';

app.post('/payment', async (req, res) => {
  await withRevealContext({
    name: 'payment-handler',
    reason: 'processing transaction',
    tags: { requestId: req.id, userId: req.user.id },
    auditReveal: (value) => {
      logger.info('Sensitive value accessed', { class: value.klass });
    }
  }, async () => {
    // All reveal() calls in this scope use this context
    await processPayment(req.body.cardToken);
  });
});
```

---

## API Reference

### SensitiveString Class

```typescript
class SensitiveString<C extends SensitivityClass = 'generic'> {
  constructor(value: string, klass: C);
  
  readonly klass: C;
  readonly length: number;
  
  // Serialization (always redacted)
  toString(): string;
  toJSON(): string;
  
  // Raw access
  reveal(ctx?: RevealContext): string;
  
  // Comparison
  equals(other: string | SensitiveString, ctx?: RevealContext): boolean;
  
  // Manipulation
  concat(other: string | SensitiveString, ctx?: RevealContext): SensitiveString;
  substring(start: number, end?: number, ctx?: RevealContext): SensitiveString<C>;
  map(fn: (value: string) => string, ctx?: RevealContext): SensitiveString<C>;
  
  // Classification
  reclassify<D extends SensitivityClass>(newKlass: D, ctx?: RevealContext): SensitiveString<D>;
  isEmpty(): boolean;
  
  // Service-to-service transmission
  toEnvelope(ctx?: RevealContext): SensitiveEnvelope;
  static fromEnvelope<C>(envelope: SensitiveEnvelope): SensitiveString<C>;
  static fromOptional<C>(value: string | null | undefined, klass: C): SensitiveString<C> | null;
}
```

### Zod Schemas

```typescript
// Basic sensitive string
zSensitive<C extends SensitivityClass>(klass: C)

// Email with validation
zSensitiveEmail()

// Convenience shortcuts
zSensitivePII()     // → SensitiveString<'pii_generic'>
zSensitiveSecret()  // → SensitiveString<'secret'>
zSensitiveToken()   // → SensitiveString<'token'>

// With custom validation
zSensitiveWithValidation(klass, zodStringSchema)

// Optional values (returns null for missing)
zSensitiveOptional(klass)

// Parse from envelope format
zSensitiveFromEnvelope(expectedKlass?)
```

### Utility Functions

```typescript
// Recursively redact SensitiveString in structures
redactInStructure(obj: unknown): unknown;

// Alias for logging context
safeLog(obj: unknown): unknown;

// Safe JSON stringify
safeStringify(obj: unknown, options?: { pretty?: boolean }): string;

// Check for sensitive values
containsSensitive(obj: unknown): boolean;

// Create logger serializer
createSensitiveSerializer(): (value: unknown) => unknown;
```

### Context Management

```typescript
// Execute with reveal context
withRevealContext<T>(ctx: RevealContext, fn: () => T): T;

// Get current context
getCurrentRevealContext(): RevealContext | null;

// Create child context
createChildContext(overrides: Partial<RevealContext> & { name: string }): RevealContext;

// Convenience for auditing
withAuditedReveals<T>(name: string, auditFn: (value) => void, fn: () => T): T;
```

### Policy Management

```typescript
// Register custom policy
registerPolicy(policy: SensitivityPolicy, opts?: { overwrite?: boolean }): void;

// Get policy
getPolicy(name: SensitivityClass): SensitivityPolicy;

// Class combination logic
defaultCombineClasses(a: SensitivityClass, b: SensitivityClass): SensitivityClass;
```

---

## Advanced Usage

### Custom Policies

```typescript
import { registerPolicy } from '@anthropic-security/sensitive-core';

registerPolicy({
  name: 'secret',
  redact: (value) => `***${value.length} chars***`,
  requireConstantTimeEquals: true,
  checkRevealAllowed: (ctx) => {
    if (!ctx) {
      throw new Error('Context required for secret access');
    }
  },
  advisory: {
    allowPersistPlain: false,
    allowPersistEncrypted: true,
    criticality: 'high',
  },
}, { overwrite: true });
```

### Service-to-Service Transmission

When transmitting sensitive values between services, use the envelope pattern:

```typescript
// Sender
const payload = {
  userId: user.id,
  token: authToken.toEnvelope({ 
    name: 'service-call',
    reason: 'forwarding to payment service' 
  }),
};
await httpClient.post('https://payment-service/process', payload);

// Receiver
import { SensitiveString } from '@anthropic-security/sensitive-core';
import { zSensitiveFromEnvelope } from '@anthropic-security/sensitive-zod';

const PayloadSchema = z.object({
  userId: z.string(),
  token: zSensitiveFromEnvelope('token'),
});

const { token } = PayloadSchema.parse(req.body);
// token is SensitiveString<'token'>
```

> ⚠️ **Security Note**: Envelopes contain plaintext. Use mTLS, encrypted message buses, or VPC-internal communication.

### NestJS Integration (Example)

```typescript
// Create a pipe for sensitive DTOs
@Injectable()
export class SensitivePipe implements PipeTransform {
  constructor(private schema: z.ZodSchema) {}
  
  transform(value: unknown) {
    return this.schema.parse(value);
  }
}

// Use in controller
@Post('login')
async login(
  @Body(new SensitivePipe(LoginSchema)) dto: LoginDto
) {
  return withRevealContext({
    name: 'login-handler',
    tags: { ip: req.ip }
  }, () => this.authService.login(dto));
}
```

### Logger Integration (Pino)

```typescript
import pino from 'pino';
import { createSensitiveSerializer } from '@anthropic-security/sensitive-core';

const logger = pino({
  serializers: {
    req: createSensitiveSerializer(),
    payload: createSensitiveSerializer(),
  },
});

// Sensitive values in logged objects are automatically redacted
logger.info({ payload: { token: sensitiveToken } }, 'Processing request');
```

---

## Threat Model

### In Scope (Defended Against)

| Threat | Defense |
|--------|---------|
| Accidental logging | Automatic redaction in `toString()`, `toJSON()`, `inspect()` |
| Casual inspection | Private fields (`#value`) inaccessible via reflection |
| JSON serialization | `toJSON()` returns redacted value |
| Template literals | `toString()` called, returns redacted value |
| Timing attacks | Constant-time comparison for `secret` and `token` classes |

### Out of Scope (Documented Limitations)

| Limitation | Reason | Mitigation |
|------------|--------|------------|
| Memory dumps | JavaScript lacks secure memory primitives | Use `crypto.subtle` for encryption keys |
| Malicious code | Attacker with code execution can extract values | This is defense-in-depth, not a security boundary |
| Worker threads | AsyncLocalStorage doesn't propagate to workers | Explicit context passing required |
| V8 heap persistence | Raw values may persist until GC | Consider WASM-based secure memory for highest sensitivity |

---

## Development

### Building

```bash
# Install dependencies
pnpm install

# Build all packages
pnpm build

# Run tests
pnpm test

# Run tests with coverage
pnpm test:coverage
```

### Project Structure

```
sensitive-string-lib/
├── packages/
│   ├── sensitive-core/     # Core library (no external deps)
│   │   └── src/
│   │       ├── types.ts        # Type definitions
│   │       ├── policy.ts       # Policy registry
│   │       ├── context.ts      # AsyncLocalStorage context
│   │       ├── sensitive-string.ts  # Main class
│   │       ├── redact.ts       # Redaction helpers
│   │       └── index.ts        # Exports
│   └── sensitive-zod/      # Zod integration
│       └── src/
│           └── index.ts        # Zod schemas
├── package.json            # Root workspace config
├── pnpm-workspace.yaml
└── tsconfig.base.json
```

---

## Roadmap

### Near-term
- [ ] NestJS package with pipes, interceptors, and guards
- [ ] Pino/Winston integration with custom serializers
- [ ] Worker thread support for context propagation

### Medium-term
- [ ] Domain-specific policy modules (PCI-DSS, HIPAA)
- [ ] Encrypted envelope for transmission (KMS integration)
- [ ] Prisma integration for database columns

### Long-term
- [ ] ESLint plugin to flag `.reveal()` calls
- [ ] LLM integration helpers (scrub before prompt construction)

---

## License

MIT © Anthropic

---

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting PRs.

Key principles:
- All new code must maintain redaction guarantees
- Tests must include "canary" leak detection
- Security-impacting changes require additional review
