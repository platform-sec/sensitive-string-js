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

const apiKey = new SensitiveString(process.env.API_KEY!, 'credential', 'api_key');

console.log(apiKey);                   // SensitiveString<credential:api_key> { [REDACTED:credential] }
console.log(JSON.stringify({ apiKey })); // {"apiKey":"[REDACTED:credential]"}

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
const token = new SensitiveString('sk-abc123secret', 'credential', 'session_token');
const email = new SensitiveString('user@example.com', 'sensitive', 'email');

// Safe for logging - automatically redacted
console.log('User:', safeLog({ token, email }));
// Output: User: { token: '[REDACTED:credential]', email: '[REDACTED:sensitive]' }

// Explicit reveal when needed
const rawToken = token.reveal();
await callExternalAPI(rawToken);
```

### With Zod Validation

```typescript
import { z } from 'zod';
import { zCredential, zSensitiveWithValidation } from '@anthropic-security/sensitive-zod';

const WebhookSchema = z.object({
  token: zCredential('session_token'),
  email: zSensitiveWithValidation('sensitive', z.string().email(), 'email'),
  note: z.string().optional(),
});

// Parse input directly into SensitiveString instances
const webhook = WebhookSchema.parse(req.body);

// Type-safe: webhook.token is SensitiveString<'credential'>
// Type-safe: webhook.email is SensitiveString<'sensitive'>

// JSON serialization is safe
res.json(webhook); // Sensitive fields automatically redacted
```

---

## ⚠️ Important Security Concepts

Please read this section carefully to ensure secure usage.

### 1. `serialize` Exposes Raw Data
The `serialize()` method is designed for **secure transmission boundaries** (e.g., mTLS between internal services). It returns an object containing the **RAW, UNREDACTED** value.
*   **DO NOT** log the output of `serialize()`.
*   **DO NOT** return the output of `serialize()` to untrusted clients.
*   **ONLY** use this when you explicitly intend to send the secret to another trusted system that will reconstruct it using `SensitiveString.deserialize()`.

### 2. `reveal()` is the Danger Zone
Calling `.reveal()` strips all protection. The returned value is a plain JavaScript string.
*   Once revealed, the value attacks accidental logging protections.
*   Always limit the scope of the revealed variable (e.g., inside a small block).
*   Avoid passing the revealed value to other functions if possible; pass the `SensitiveString` instead.

### 3. Runtime Safety, Not Memory Isolation
This library prevents *accidental* exposure (logs, errors, JSON). It does **not** protect against malicious code running in the same Node.js process. Any code with access to the `SensitiveString` instance can call `.reveal()`.

---

## Core Concepts

### Sensitivity Classes

Data is classified by sensitivity level:

| Class | Use Case | Constant-Time Comparison |
|-------|----------|-------------------------|
| `sensitive` | PII, business data | No |
| `credential` | Passwords, API keys, auth tokens | Yes |

Use the optional `label` to categorize within a class (e.g., `email`, `session_token`).

### Automatic Redaction

`SensitiveString` overrides all serialization methods:

```typescript
const secret = new SensitiveString('my-secret', 'credential', 'api_key');

// All of these are safe:
secret.toString()           // "[REDACTED:credential]"
JSON.stringify(secret)      // "\"[REDACTED:credential]\""
util.inspect(secret)        // "SensitiveString<credential:api_key> { [REDACTED:credential] }"
console.log(secret)         // SensitiveString<credential:api_key> { [REDACTED:credential] }
`Value: ${secret}`          // "Value: [REDACTED:credential]"
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
class SensitiveString<C extends SensitivityClass = 'sensitive'> {
  constructor(value: string, klass: C, label?: string);
  
  readonly klass: C;
  readonly label?: string;
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
  reclassify<D extends SensitivityClass>(
    newKlass: D,
    newLabel?: string,
    ctx?: RevealContext
  ): SensitiveString<D>;
  isEmpty(): boolean;
  
  // Service-to-service transmission
  serialize(ctx?: RevealContext): SerializedSensitiveString;
  static deserialize<C>(serialized: SerializedSensitiveString): SensitiveString<C>;
  static fromOptional<C>(value: string | null | undefined, klass: C): SensitiveString<C> | null;
}
```

### Zod Schemas

```typescript
// Basic sensitive string
zSensitiveString<C extends SensitivityClass>(klass: C, label?: string)

// Sensitive (PII, business data)
zSensitive(label?)

// Credential (passwords, API keys, tokens)
zCredential(label?)

// With custom validation
zSensitiveWithValidation(klass, zodStringSchema, label?)

// Optional values (returns null for missing)
zSensitiveOptional(klass, label?)

// Parse from serialized format
zSensitiveDeserialize(expectedKlass?)
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
  name: 'credential',
  redact: (value) => `***${value.length} chars***`,
  requireConstantTimeEquals: true,
  checkRevealAllowed: (ctx) => {
    if (!ctx) {
      throw new Error('Context required for credential access');
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

When transmitting sensitive values between services, use the serialized pattern:

```typescript
// Sender
const payload = {
  userId: user.id,
  token: authToken.serialize({
    name: 'service-call',
    reason: 'forwarding to payment service' 
  }),
};
await httpClient.post('https://payment-service/process', payload);

// Receiver
import { SensitiveString } from '@anthropic-security/sensitive-core';
import { zSensitiveDeserialize } from '@anthropic-security/sensitive-zod';

const PayloadSchema = z.object({
  userId: z.string(),
  token: zSensitiveDeserialize('credential'),
});

const { token } = PayloadSchema.parse(req.body);
// token is SensitiveString<'credential'>
```

> ⚠️ **Security Note**: Serialized sensitive strings contain the **RAW UNREDACTED STRING**. Never log serialized outputs. Only use this method when transmitting data over secure channels (mTLS, encrypted message buses, or VPC-internal communication) to another trusted service.

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

## Zod Integration Deep Dive

The `@anthropic-security/sensitive-zod` package bridges Zod validation with `SensitiveString`. This section explains how they work together and when to use (or avoid) the integration.

### How It Works Step by Step

**Step 1: Define a schema with Zod helpers**

```typescript
import { z } from 'zod';
import { zCredential, zSensitive } from '@anthropic-security/sensitive-zod';

const LoginSchema = z.object({
  email: zSensitive('email'),
  password: zCredential('password'),
});
```

**Step 2: Each helper creates a Zod transform**

Under the hood, each helper wraps `z.string().transform()`:

```typescript
// zCredential('password') is equivalent to:
z.string().transform((value) => new SensitiveString(value, 'credential', 'password'));
```

**Step 3: Parse user input**

```typescript
const input = { email: 'user@example.com', password: 'hunter2' };
const result = LoginSchema.parse(input);

// result.email is SensitiveString<'sensitive'>
// result.password is SensitiveString<'credential'>
```

**Step 4: Automatic redaction kicks in**

```typescript
console.log(result.email);   // [REDACTED:sensitive]
JSON.stringify(result);      // {"email":"[REDACTED:sensitive]","password":"[REDACTED:credential]"}
```

**Step 5: Explicit reveal when needed**

```typescript
const rawPassword = result.password.reveal({ name: 'auth', reason: 'verifying' });
```

### When Zod Integration is Useful

#### API Request Validation

Parse and protect sensitive fields in one step:

```typescript
const CreateUserSchema = z.object({
  email: zSensitive('email'),
  password: zSensitiveWithValidation('credential', z.string().min(8), 'password'),
  name: z.string(),
});

app.post('/users', (req, res) => {
  const user = CreateUserSchema.parse(req.body);
  // user.password is already protected
  // Logging user won't leak the password
});
```

#### Environment Variable Loading

Validate and protect config at startup:

```typescript
const EnvSchema = z.object({
  DATABASE_URL: zCredential('database_url'),
  API_KEY: zCredential('api_key'),
  SENTRY_DSN: zSensitive('sentry_dsn'),
});

const config = EnvSchema.parse(process.env);
// Logging config won't leak secrets
```

#### Webhook Payload Handling

Protect incoming sensitive data immediately:

```typescript
const WebhookSchema = z.object({
  event: z.string(),
  customer: z.object({
    id: z.string(),
    email: zSensitive('email'),
    paymentToken: zCredential('payment_token'),
  }),
});

app.post('/webhook', (req, res) => {
  const payload = WebhookSchema.parse(req.body);
  console.log('Received:', payload);  // Safe - sensitive fields redact
});
```

#### Form Validation with Error Messages

Validate before protecting to get useful error messages:

```typescript
const RegistrationSchema = z.object({
  password: zSensitiveWithValidation(
    'credential',
    z.string()
      .min(12, 'Password must be at least 12 characters')
      .regex(/[!@#$%^&*]/, 'Must contain a special character'),
    'password'
  ),
});

// Bad input gets helpful errors, not wrapped in SensitiveString
RegistrationSchema.parse({ password: 'short' });
// throws: "Password must be at least 12 characters"
```

### When Zod Integration Gets in the Way

#### You Need to Validate the Raw Value Later

Once wrapped, accessing the value requires `.reveal()`:

```typescript
const { email } = schema.parse({ email: 'test@example.com' });

// This doesn't work - SensitiveString isn't a string
if (email.endsWith('@company.com')) { }  // Error!

// You have to reveal first
if (email.reveal().endsWith('@company.com')) { }
```

**Workaround:** Use `zSensitiveWithValidation` to validate before wrapping:

```typescript
zSensitiveWithValidation(
  'sensitive',
  z.string().email().endsWith('@company.com', 'Must be company email'),
  'email'
)
```

#### Third-Party Libraries Expect Plain Strings

Many libraries won't understand `SensitiveString`:

```typescript
const { password } = schema.parse(input);

// bcrypt expects a string
bcrypt.hash(password, 10);  // Error!

// You must reveal
bcrypt.hash(password.reveal({ name: 'password-hash' }), 10);
```

This is intentional—it forces you to think about where secrets go—but adds friction.

#### No Refinements After Transform

Zod's `.refine()` runs after transforms, so you can't refine on the raw value:

```typescript
// This doesn't work as expected
zCredential('api_key').refine(val => val.startsWith('sk-'))  // val is SensitiveString!
```

**Workaround:** Use `zSensitiveWithValidation`:

```typescript
zSensitiveWithValidation(
  'credential',
  z.string().refine(s => s.startsWith('sk-'), 'Must start with sk-'),
  'api_key'
)
```

#### Optional Fields Return `null`, Not `undefined`

`zSensitiveOptional` returns `null` for missing values:

```typescript
const { apiKey } = schema.parse({});
apiKey === null       // true
apiKey === undefined  // false

// If downstream expects undefined:
const config = { apiKey: result.apiKey ?? undefined };
```

#### Serialized Format is Verbose

The wire format for service-to-service is larger than plain strings:

```typescript
// Plain: "secret-token"
// Serialized: {"__sensitive":true,"klass":"credential","value":"secret-token","label":"token"}
```

For high-throughput scenarios, this overhead may matter.

### Summary Table

| Scenario | Use Zod Integration? |
|----------|---------------------|
| API request validation | **Yes** - protect at boundary |
| Environment config loading | **Yes** - protect early |
| Webhook payload handling | **Yes** - immediate protection |
| Service-to-service with serialization | **Yes** - use serialize/deserialize |
| High-throughput internal pipelines | **Maybe** - consider overhead |
| Complex post-transform validation | **Avoid** - use validation-first pattern |
| Interop with string-expecting libraries | **Use carefully** - reveal at integration points |

---

## Threat Model

### In Scope (Defended Against)

| Threat | Defense |
|--------|---------|
| Accidental logging | Automatic redaction in `toString()`, `toJSON()`, `inspect()` |
| Casual inspection | Private fields (`#value`) inaccessible via reflection |
| JSON serialization | `toJSON()` returns redacted value |
| Template literals | `toString()` called, returns redacted value |
| Timing attacks | Constant-time comparison for `credential` class |

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
- [ ] Encrypted serialized payload for transmission (KMS integration)
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
