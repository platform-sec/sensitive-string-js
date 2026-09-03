# SensitiveString

Enterprise-grade library for handling sensitive string data in Node.js with:
- **Automatic redaction**
- **Type-safe classification**
- **Audit-ready reveal patterns**

## Why SensitiveString?

In typical system, sensitive data (tokens, PII, secrets) spreads as plain `string` values, making it trivial to accidentally:

- Log them to console/files
- Serialize them in JSON responses
- Forward them to third-party services

**SensitiveString** provides a centralized abstraction that:

- **Marks data as sensitive** at the type level
- **Redacts by default** in all human-readable contexts
- **Forces explicit, auditable access** for raw values

```typescript
import { readFileSync } from 'node:fs';
import { SensitiveString } from '@platform-sec/sensitive-string-core';

// Read secret from vault-injected file mount (e.g., Kubernetes secrets, HashiCorp Vault)
const apiKey = new SensitiveString(
  readFileSync('/run/secrets/api_key', 'utf-8'),
  'credential',
  'api_key'
);

console.log(apiKey);            
// SensitiveString<credential:api_key> { [REDACTED:credential] }
console.log(JSON.stringify({ apiKey }));
// {"apiKey":"[REDACTED:credential]"}

// Explicit access when needed
const raw = apiKey.reveal({ name: 'api-call', reason: 'authenticating' });

```

---

## Quick Start

### Installation

```bash
# Using pnpm (recommended)
pnpm add @platform-sec/sensitive-string-core

# With Zod integration
pnpm add @platform-sec/sensitive-string-core @platform-sec/sensitive-string-zod zod

# Stage 3 decorators: declarative field wrapping and reveal context
pnpm add @platform-sec/sensitive-string-core @platform-sec/sensitive-string-decorators

# NestJS: DTO decorators, transform pipe, context and response interceptors
pnpm add @platform-sec/sensitive-string-core @platform-sec/sensitive-string-nestjs

# Express: body wrapping, header extraction, context, response redaction
pnpm add @platform-sec/sensitive-string-core @platform-sec/sensitive-string-express

# Test utilities: canaries, leak assertions, matchers, audit mocks
pnpm add -D @platform-sec/sensitive-string-testing

# Lint rules for the mistakes the type system cannot catch
pnpm add -D @platform-sec/eslint-plugin-sensitive-string
```

### Basic Usage

```typescript
import { SensitiveString, safeLog } from '@platform-sec/sensitive-string-core';

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
import { zCredential, zSensitiveWithValidation } from '@platform-sec/sensitive-string-zod';

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
import { withRevealContext, SensitiveString } from '@platform-sec/sensitive-string-core';

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

## API Reference

### SensitiveString Class

```typescript
class SensitiveString<C extends SensitivityClass = 'sensitive'> {
  constructor(
    value: string,
    klass: C,
    label?: string,
    options?: SensitiveStringOptions
  );
  
  readonly klass: C;
  readonly label?: string;
  readonly length: number;
  
  // Serialization (always redacted)
  toString(): string;
  toJSON(): string;
  
  // Raw access
  reveal(ctx?: RevealContext): string;
  mask(options?: MaskOptions, ctx?: RevealContext): string;
  
  // Comparison
  equals(other: string | SensitiveString, ctx?: RevealContext): boolean;

  // Expiration
  readonly expiresAt?: Date;
  readonly renewalCount: number;
  isExpired(): boolean;
  ttlRemaining(): number | undefined;
  isRenewable(): boolean;
  renew(additionalTtl: number, options?: RenewalOptions, ctx?: RevealContext): void;
  
  // Manipulation
  concat(other: string | SensitiveString, ctx?: RevealContext): SensitiveString;
  substring(start: number, end?: number, ctx?: RevealContext): SensitiveString<C>;
  map(fn: (value: string) => string, ctx?: RevealContext): SensitiveString<C>;
  trim(ctx?: RevealContext): SensitiveString<C>;
  trimStart(ctx?: RevealContext): SensitiveString<C>;
  trimEnd(ctx?: RevealContext): SensitiveString<C>;
  toLowerCase(ctx?: RevealContext): SensitiveString<C>;
  toUpperCase(ctx?: RevealContext): SensitiveString<C>;
  padStart(length: number, pad?: string, ctx?: RevealContext): SensitiveString<C>;
  padEnd(length: number, pad?: string, ctx?: RevealContext): SensitiveString<C>;
  slice(start?: number, end?: number, ctx?: RevealContext): SensitiveString<C>;
  split(separator: string | RegExp, limit?: number, ctx?: RevealContext): SensitiveString<C>[];
  replace(search: string | RegExp, replacement: string, ctx?: RevealContext): SensitiveString<C>;
  replaceAll(search: string | RegExp, replacement: string, ctx?: RevealContext): SensitiveString<C>;
  charAt(index: number, ctx?: RevealContext): SensitiveString<C>;
  at(index: number, ctx?: RevealContext): SensitiveString<C> | undefined;

  // Partial queries (disabled for credential by default)
  startsWith(search: string, position?: number, ctx?: RevealContext): boolean;
  endsWith(search: string, endPosition?: number, ctx?: RevealContext): boolean;
  includes(search: string, position?: number, ctx?: RevealContext): boolean;
  indexOf(search: string, position?: number, ctx?: RevealContext): number;
  lastIndexOf(search: string, position?: number, ctx?: RevealContext): number;
  
  // Regular expressions
  test(pattern: RegExp, ctx?: RevealContext): boolean;
  search(pattern: RegExp, ctx?: RevealContext): number;
  match(pattern: RegExp, ctx?: RevealContext): SensitiveString<C>[] | null;
  matchGroups(
    pattern: RegExp,
    ctx?: RevealContext
  ): Record<string, SensitiveString<C>> | null;
  matchAll(pattern: RegExp, ctx?: RevealContext): IterableIterator<SensitiveString<C>[]>;

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
  static fromOptional<C>(
    value: string | null | undefined,
    klass: C,
    label?: string,
    options?: SensitiveStringOptions
  ): SensitiveString<C> | null;
}
```

String transformations retain the original class and label and are authorized and audited like
other exposing operations. Partial queries reveal facts about a value, so they are audited and
controlled by `SensitivityPolicy.allowPartialQueries`. They are allowed for `sensitive` values and
denied for `credential` values by default. Replacement callbacks are not supported because they
would receive raw matched text.

Regular-expression `test()` and `search()` are partial queries under the same policy. A
caller-controlled regex is a powerful content oracle, so these methods should not be enabled for
credentials without a specific reason. `match()`, `matchGroups()`, and `matchAll()` instead return
protected derivatives and are authorized and audited transformations. Match arrays intentionally
omit native metadata such as `input`, which contains the complete raw value, and omit optional
captures that did not participate. Named groups receive labels such as `email:domain`; an unlabeled
source uses the group name itself. The returned group record has a null prototype, matching native
named-group records and preventing special group names from altering an object prototype.

```typescript
import { patterns, SensitiveString } from '@platform-sec/sensitive-string-core';

const email = new SensitiveString('user@example.com', 'sensitive', 'email');

email.test(patterns.email); // true
email.search(/@/); // 4
email.matchGroups(/^(?<local>[^@]+)@(?<domain>[^@]+)$/);
// { local: SensitiveString<label=email:local>, domain: SensitiveString<label=email:domain> }
```

`patterns.email` is anchored and constructed without ambiguous nested repetition. Caller-supplied
patterns are not checked for catastrophic backtracking. JavaScript regex execution is synchronous,
so it cannot be interrupted safely with a timeout on the current thread; isolating it in a worker
would require an asynchronous API and copying the raw value into another heap. Only use trusted,
bounded-complexity patterns with these methods.

### Partial Masking

```typescript
interface MaskOptions {
  showFirst?: number;
  showLast?: number;
  maskChar?: string;   // exactly one character, default '*'
  minMasked?: number;  // security floor: 4 for 'sensitive', 8 for 'credential'
  strategy?: 'email' | 'phone' | 'card' | 'ssn' | 'uuid' | 'custom';
  customStrategy?: (value: string) => string;
}
```

Full redaction is safe but unhelpful when a support agent needs to confirm which email is on file,
or an engineer needs to know which of three API keys failed. `mask()` returns a partial view as a
plain string, for display.

```typescript
const key = new SensitiveString('sk_live_abc123xyz9', 'sensitive', 'api_key');
key.mask({ showFirst: 2, showLast: 4 }); // 'sk************xyz9'
key.mask();                              // '******************'

new SensitiveString('jane@example.com', 'sensitive', 'email').mask({ strategy: 'email' });
// 'j***@e******.com'
new SensitiveString('+1-555-123-4567', 'sensitive', 'phone').mask({ strategy: 'phone' });
// '+1-***-***-4567'
new SensitiveString('4111111111111111', 'sensitive', 'card').mask({ strategy: 'card' });
// '411111******1111'
new SensitiveString('123-45-6789', 'sensitive', 'ssn').mask({ strategy: 'ssn' });
// '***-**-6789'
new SensitiveString('550e8400-e29b-41d4-a716-446655440000', 'sensitive', 'id').mask({
  strategy: 'uuid',
});
// '550e8400-****-****-****-************'
```

Masking is a partial reveal, not a redaction. It runs `checkRevealAllowed` and `auditReveal`
exactly as `reveal()` does, and the audit record says which it was:

```typescript
await withRevealContext({
  name: 'support-console',
  auditReveal: (value, details) => {
    logger.info('accessed', { label: value.label, operation: details.operation });
    // operation: 'reveal' for a full read, 'mask' for a partial one, with the
    // strategy and options that produced it. The custom formatter is never
    // included.
  },
}, async () => { /* ... */ });
```

Two policy controls apply. `SensitivityPolicy.allowMask` decides whether a class may be masked at
all; it is `true` for `sensitive` and `false` for `credential`, so masking an API key requires a
policy that opts in. `minMasked` is the floor on how many characters the result must hide: 4 for
`sensitive` and 8 for `credential`. A caller may raise the floor but not lower it, positional
masking clamps what it shows to satisfy it, and a rendering that cannot reach it falls back to the
class's full redaction.

```typescript
new SensitiveString('abcdef', 'sensitive').mask({ showLast: 6 }); // '****ef', clamped
new SensitiveString('abc', 'sensitive').mask({ showFirst: 1 });   // '[REDACTED:sensitive]'
new SensitiveString('4111111111111', 'sensitive').mask({ strategy: 'card' });
// '[REDACTED:sensitive]': ten of thirteen digits shown would hide only three

new SensitiveString('secret', 'sensitive').mask({ minMasked: 1 });
// RangeError: minMasked 1 is below the floor of 4 for sensitivity class 'sensitive'
```

A format strategy applied to a value that is not of that format redacts rather than degrading to a
positional view. The strategy exists to show the parts of a known shape that are safe to show;
against a different shape it has no idea which parts those are, and showing a fixed prefix of
whatever the value actually is would be worse than showing nothing.

```typescript
const token = new SensitiveString('a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6', 'sensitive', 'token');

token.mask({ strategy: 'uuid' });  // '[REDACTED:sensitive]', not a canonical UUID
token.mask({ strategy: 'card' });  // '[REDACTED:sensitive]', sixteen digits but not a card
token.mask({ strategy: 'email' }); // '[REDACTED:sensitive]', no '@'
```

The `phone` and `ssn` strategies have no shape to fail: they hide every character that is not one
of the last four digits or a separator they keep, so an unrecognized character is masked rather
than shown.

The `card` strategy shows the six-digit BIN and the last four digits, which is the PCI-DSS maximum.
It is the only definition of card masking in this repository; a package that needs to mask a PAN
calls it rather than writing its own. The `email` strategy masks the domain as well as the local
part, because a full domain leaks the employer or provider, and it hides a one-character local part
completely rather than disclosing the whole address.

Counts are code points, so an astral character is never split and an emoji may be used as the mask
character. The rendering discloses the length of the value by construction. It is a plain string
with no protection of its own: display it, do not process it.

`customStrategy` receives the raw value. It is a reveal in all but name, and the library cannot
measure what it returns against the floor, so it runs only when the caller names it explicitly:

```typescript
pan.mask({
  strategy: 'custom',
  customStrategy: (value) => value.slice(0, 3) + '...' + value.slice(-3),
});

pan.mask({ strategy: 'card', customStrategy: (value) => value });
// Error: customStrategy requires strategy: 'custom'
```

### Template Literals

```typescript
sensitiveTemplate(
  strings: TemplateStringsArray,
  ...values: TemplateValue[]
): SensitiveString<SensitivityClass>;

sensitiveTemplate<K extends SensitivityClass>(
  options: SensitiveTemplateOptions<K>
): SensitiveTemplateTag<K>;

const st = sensitiveTemplate;

type TemplateValue = string | number | boolean | SensitiveString<SensitivityClass>;

interface SensitiveTemplateOptions<K extends SensitivityClass = SensitivityClass> {
  ctx?: RevealContext;
  label?: string;
  klass?: K;
}
```

Building a URL or a connection string from several protected values otherwise takes a `reveal()`
call per value and a hand-picked class. The `st` tag does both: every interpolated
`SensitiveString` is read through `reveal()`, so policy checks and audit hooks run once per value,
and the result inherits the most restrictive interpolated class through the same combination rule
`concat()` uses.

```typescript
import { SensitiveString, st } from '@platform-sec/sensitive-string-core';

const apiKey = new SensitiveString('sk_live_abc123', 'credential', 'api_key');
const userId = new SensitiveString('user_456', 'sensitive', 'user_id');

const url = st`https://api.example.com/users/${userId}?key=${apiKey}`;
url.klass; // 'credential', inherited from apiKey
String(url); // '[REDACTED:credential]'
```

The configured form adds an audit context, a label, and a class. The class may only be tightened:
a `klass` less restrictive than the interpolated values is rejected before anything is revealed.
Lowering a class remains the job of `reclassify()`, which audits the downgrade.

```typescript
const url = sensitiveTemplate({
  ctx: { name: 'build-api-url', reason: 'constructing external API request' },
  label: 'gateway_url',
  klass: 'credential',
})`https://gateway.example.com/charge?user=${userId}`;

sensitiveTemplate({ klass: 'sensitive' })`key=${apiKey}`;
// Error: klass 'sensitive' is less restrictive than interpolated class 'credential'
```

Only strings, numbers, booleans, and `SensitiveString` values may be interpolated. Everything else
throws a `TypeError` naming the index and the runtime type, never the value, and the check runs
before any value is revealed. Coercing an arbitrary object would embed `[object Object]` in a
credential or hand the template an attacker-controlled `toString()`; the same rule rejects an
instance from a duplicate copy of the package, which `instanceof` cannot recognize.

The whole result is one protected value, plain parts included, so it redacts as a unit. That makes
it the wrong tool for a log line:

```typescript
logger.info(String(st`User ${userId} logged in`)); // '[REDACTED:sensitive]'
logger.info(`User ${userId} logged in`); // 'User [REDACTED:sensitive] logged in'
logger.info('User logged in', safeLog({ userId })); // structured field, redacted
```

Values are never interpolated into SQL, sensitive or not. Use a parameterized query and reveal the
parameter at the driver boundary.

### Expiration (TTL)

```typescript
interface SensitiveStringOptions {
  ttl?: number;           // milliseconds from construction
  expiresAt?: Date;       // absolute deadline; mutually exclusive with ttl
  allowRenewal?: boolean; // default: false for 'credential', true for 'sensitive'
  maxRenewals?: number;
  onExpire?: () => void;
}

interface RenewalOptions {
  maxExtension?: Date;
}
```

A one-time code, a reset token, or a short-lived credential should stop working at a deadline even
if a long-running process still holds a reference to it. Tracking that by hand needs a check at
every call site, and the one that is forgotten is the one that matters.

```typescript
const otp = new SensitiveString(code, 'credential', 'otp', { ttl: 5 * 60_000 });

otp.reveal();       // works
otp.ttlRemaining(); // 299_987
otp.isExpired();    // false

// ...five minutes later
otp.isExpired();    // true
otp.ttlRemaining(); // -1
otp.reveal();       // throws ExpiredSensitiveValueError
```

The check lives in the single gate every path to the raw value goes through, so `equals()`,
`mask()`, `serialize()`, and every string, regex, and template operation refuse an expired value
alongside `reveal()`. Redaction and documented metadata do not: `toString()`, `toJSON()`,
`length`, `klass`, and `label` keep working, because a value that can no longer be used still has
to be safe to log.

`ttl: 0` means "already expired", not "no TTL", and a value is not usable at its own deadline: the
comparison is `now >= expiresAt`. `ttl` and `expiresAt` are mutually exclusive, and the `Date` is
read once at construction, so mutating it afterwards moves nothing.

Derived values carry the deadlines of everything they were built from, and expire with the first
of them:

```typescript
const token = new SensitiveString(raw, 'credential', 'token', { ttl: 60_000 });

token.substring(0, 8).isExpired();      // follows token
st`Bearer ${token}`.isExpired();        // follows token
shortLived.concat(longLived).expiresAt; // the earlier of the two
```

`renew()` extends a deadline when the class allows it. It is not a read, so it works on an expired
value and extends from now rather than from the lapsed deadline, which is what a sliding session
that missed a heartbeat needs. Reviving a value that way is also why `allowRenewal` defaults to
`false` for `credential`. The extension is audited before it takes effect, so an audit sink that
throws stops it, and a refused renewal leaves no record of one that never happened.

```typescript
const session = new SensitiveString(token, 'sensitive', 'session', { ttl: 15 * 60_000 });

session.isRenewable(); // true
session.renew(15 * 60_000, { maxExtension: absoluteSessionDeadline });
session.renewalCount;  // 1
```

Only the value that owns a deadline may renew it. A derivative shares its sources' state by
reference, so renewing through one would silently extend the value it came from, and every other
derivative of it; `derived.renew()` throws `RenewalNotAllowedError` with `reason: 'derived'`.

A policy can set expiration for a whole class:

```typescript
registerPolicy({
  name: 'credential',
  redact: (value) => '[REDACTED:credential]',
  defaultTtl: 60 * 60_000,  // applied when the caller sets neither ttl nor expiresAt
  maxTtl: 8 * 60 * 60_000,  // absolute cap, from construction, on the deadline and every renewal
  requireExpiration: true,  // reject a value of this class that has no deadline
  allowRenewal: false,      // a prohibition the allowRenewal option cannot lift
}, { overwrite: true });
```

`maxTtl` is measured from construction, so it is an absolute lifetime rather than something a
renewal can push forward. A renewal that the cap swallows entirely throws rather than reporting a
success that changed nothing.

The deadline crosses the wire, because a token with five minutes left still has five minutes left
on the other side:

```typescript
const serialized = token.serialize();
// { __sensitive: true, klass: 'credential', value: '...', expiresAt: '2026-01-01T00:05:00.000Z' }
```

The receiver enforces it against its own clock, whether it uses `SensitiveString.deserialize()` or
the Zod `zSensitiveDeserialize()` schema. Clock synchronization is the deployment's problem, not the
library's; a receiver whose clock runs ahead of the sender's rejects the value early, which is the
direction to fail in. Renewal permission and renewal counts deliberately do not travel, so a
payload cannot grant the right to extend a credential's lifetime, and the receiving process's
policy still applies its own `maxTtl` and `requireExpiration`.

A deadline must be a date a `Date` can represent. A finite but absurd `ttl` is rejected rather than
accepted as a deadline that can never be reached, which would be no deadline at all.

Expiration is a usability control on the values this process holds, not a cryptographic one. It
stops code from using a stale secret; it does not erase the secret from memory, and it does not
constrain a holder of the raw string that was already revealed.

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

// Collections, wrapping each element or value on its own
zSensitiveArray(label?)
zCredentialArray(label?)
zSensitiveStringArray(klass, label?)
zSensitiveRecord(label?)
zCredentialRecord(label?)
zSensitiveStringRecord(klass, label?)

// Normalize before wrapping: normalize, validate, then wrap
zSensitivePreprocess(spec, label?, stringSchema?)
zCredentialPreprocess(spec, label?, stringSchema?)
zSensitiveStringPreprocess(klass, spec, label?, stringSchema?)

// A default produced as a raw string and wrapped by the schema
zSensitiveDefault(klass, label, valueOrFactory)

// Sensitivity decided by a sibling field
zConditionalSensitive({ discriminator, valueField, conditions })

// Refine on the raw value; the check reveals and is audited as one
schema.refineSensitive(check, params?)
refineSensitive(schema, check, params?)

// Parse without echoing the input into the error
sensitiveParse(schema, data, params?)
sensitiveSafeParse(schema, data, params?)
sensitiveSafeParseAsync(schema, data, params?)
redactZodError(error)
redactZodIssues(issues)
installSensitiveErrorMap()
```

### Utility Functions

```typescript
// Recursively redact SensitiveString instances and serialize() results in
// structures, for log lines: class instances become plain objects
redactInStructure(obj: unknown): unknown;

// Alias for logging context
safeLog(obj: unknown): unknown;

// Safe JSON stringify. Always returns a string: a BigInt becomes its decimal
// string, and a value JSON cannot represent at all (undefined, a function, a
// symbol) becomes 'null', where JSON.stringify alone would throw or hand back
// an undefined its own type declaration denies. The replacer runs first, and
// receives the holder as `this`, exactly as JSON.stringify's does.
safeStringify(
  obj: unknown,
  options?: {
    pretty?: boolean;
    replacer?: (key: string, value: unknown) => unknown;
  }
): string;

// Copy a structure for a response body: every SensitiveString and every
// serialize() result becomes its redaction, prototypes are kept so entity
// toJSON() methods still run, shared references stay shared, and streams,
// Buffer, Date, Map, Set, RegExp, and URL pass through by reference.
redactCopy(value: unknown): unknown;

// Check for sensitive values, SensitiveString instances and serialize() results alike
containsSensitive(obj: unknown): boolean;

// Collect the sensitivity classes present in a structure
sensitiveClassesIn(obj: unknown): Set<SensitivityClass>;

// Create logger serializer
createSensitiveSerializer(): (value: unknown) => unknown;

// Winston format
sensitiveFormat(options?: {
  dropClasses?: readonly SensitivityClass[];
  redactSplat?: boolean;
  stampClasses?: boolean;
  warnOnLateInstall?: boolean;
  onError?: (error: unknown) => void;
}): WinstonFormat;
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

### Testing Utilities

From `@platform-sec/sensitive-string-testing`, a dev dependency. It depends on no test framework:
the matchers are a plain object you hand to `expect.extend`, and anything that needs a spy takes
`vi.fn` or `jest.fn` as an argument.

```typescript
import {
  createTestSecret,
  expectNotLeaked,
  expectRedacted,
  setupSensitiveMatchers,
  mockRevealContext,
} from '@platform-sec/sensitive-string-testing';

setupSensitiveMatchers(expect);

it('does not leak the key into the response', async () => {
  const apiKey = createTestSecret('credential', 'api_key');

  const response = await handler(apiKey);

  expect(apiKey).toHaveSensitivityClass('credential');
  expectNotLeaked(apiKey, response, logger.entries);
  expectRedacted(logger.lastLine, apiKey);
});
```

```typescript
// Canary values, unique per call and conspicuous in output
createTestSecret(klass?, label?, options?): SensitiveString;
createExpiredSecret(klass?, label?, options?): SensitiveString;
createExpiringSecret(klass, label, ttlMs, options?): SensitiveString;

// Assertions
expectNotLeaked(secret: SensitiveString, ...targets: unknown[]): void;
expectRedacted(output: string | object, secret: SensitiveString, options?): void;

// Matchers, registered with expect.extend or setupSensitiveMatchers
expect(value).toBeSensitiveString();
expect(value).toHaveSensitivityClass('credential');
expect(value).toHaveLabel('api_token');
expect(value).toRevealAs('abc123');
expect(value).toBeExpired();
expect(output).toContainSensitive(secret);

// Audit mocks
mockRevealContext(name: string, options?: { fn?, reason?, tags? }): MockRevealContext;
createMockAuditLog(name?: string): MockAuditLog;
```

`expectNotLeaked` walks each target rather than calling `JSON.stringify` on it. `JSON.stringify`
asks an object what it wants to show, which is the wrong question for a leak check: a `toJSON` that
omits a field hides a raw copy still sitting on the object. The walk reads own properties instead,
including non-enumerable ones and values behind getters, and it decodes `Buffer` contents. A value
still wrapped in a `SensitiveString` is not a leak and is not reported as one.

The walk covers the places a copy hides rather than only the places a serializer looks: an `Error`'s
`message` and `stack`, a `match()` result's `input`, a raw value used as an object key, and bytes
written into a `Buffer`.

`expectRedacted` checks that the raw value is absent and that the rendering the class policy
actually produces is present, read from the instance rather than assumed to be `[REDACTED:class]`.
A custom policy therefore passes without the test knowing its format.

No failure message from this package contains the value it guards. A leak report names the class,
the label, and the path, and quotes the surrounding text with the value replaced by
`[LEAKED VALUE]`, because an assertion message ends up in a CI log.

A leak check never reports "no leak" because it gave up. The walk has no depth limit, and a reveal
refused by a deadline or a policy raises `UnreadableSecretError` saying the check did not run.

See [packages/sensitive-testing/README.md](packages/sensitive-testing/README.md) for the full
guide.

### Decorators

From `@platform-sec/sensitive-string-decorators`. Stage 3 decorators, so TypeScript 5.0+ with
`experimentalDecorators` left off. No framework and no `reflect-metadata`.

```typescript
import { Sensitive, WithRevealContext } from '@platform-sec/sensitive-string-decorators';

class User {
  @Sensitive('sensitive', 'email') accessor email!: SensitiveString<'sensitive'>;
  @Sensitive('credential') accessor passwordHash!: SensitiveString<'credential'>;
}

class PaymentProcessor {
  @WithRevealContext({ name: 'payment-processing', reason: 'charging card' })
  async processPayment(card: SensitiveString<'credential'>) {
    return gateway.charge(card.reveal()); // audited under that context
  }
}
```

`@Sensitive` needs the `accessor` keyword, which is the only field form whose assignments a
decorator can intercept: a plain field decorator sees the initializer and nothing after it. Every
assignment is wrapped, including one that arrives through an untyped path such as
`Object.assign(new User(), row)`. A value that is already a `SensitiveString` of the same or a
stricter class is stored as it is; a looser one is refused, since a field declared `credential`
must not hold a `sensitive` value.

`@WithRevealContext` covers sync methods, async methods, generators, and async generators. It
nests rather than substitutes, so an ambient `auditReveal` keeps receiving records from a method
that only names itself. It names the operation and grants nothing: a policy's `checkRevealAllowed`
still runs.

One consequence of `accessor` to know before switching a field over: an auto-accessor is a
prototype getter and setter pair, so the instance has no own enumerable property and
`JSON.stringify` omits the field rather than redacting it. Declare `toJSON()` where the serialized
shape matters. See
[packages/sensitive-decorators/README.md](packages/sensitive-decorators/README.md).

NestJS cannot run Stage 3 decorators, and gets the same two names from
`@platform-sec/sensitive-string-nestjs` instead.

### Express Middleware

From `@platform-sec/sensitive-string-express`. Five middleware, each closing one leak an Express
application has by default.

```typescript
app.use(express.json());
app.use(stripParseErrorBody());       // body-parser's 400 stops carrying the raw body
app.use(sensitiveContext((req) => ({ name: `${req.method} ${req.path}` })));
app.use(sensitiveHeaders({ fields: { authorization: 'credential' } }));
app.use(sensitiveResponseFilter());   // serialized values and entity instances on the way out
app.use('/api/auth', sensitiveBody({ fields: { password: 'credential', email: 'sensitive' } }));
```

`sensitiveBody` replaces configured strings in `req.body` with `SensitiveString` instances, so
`console.log(req.body)` redacts. It therefore runs after body parsing and after anything that reads
the body as strings: schema validators, passport-local, CSRF middleware. `sensitiveHeaders` does the
opposite and leaves `req.headers` untouched, because Express and every auth middleware read it;
wrapped copies go on `req.sensitive.headers`.

Express 4.21+ and 5 are both supported. See
[packages/sensitive-express/README.md](packages/sensitive-express/README.md) for the full middleware
order table and the header logging limitation.

### Lint Rules

From `@platform-sec/eslint-plugin-sensitive-string`, a dev dependency. A type keeps a secret
wrapped; it cannot stop `console.log(secret.reveal())`, because the reveal produces an ordinary
string and logging a string is ordinary code. Five rules read the shape of the call instead.

```js
// eslint.config.js
import sensitive from '@platform-sec/eslint-plugin-sensitive-string';

export default [sensitive.configs.recommended];
```

| Rule | `recommended` | Catches |
|---|---|---|
| `no-log-reveal` | error | `console.log(x.reveal())`, `logger.info({ k: x.reveal() })` |
| `no-credential-equality` | error | `x.reveal() === y`, `switch (x.reveal())` |
| `no-network-sensitive` | error | `fetch(url, { body: x.reveal() })` |
| `explicit-class` | warn | `new SensitiveString(v)` with no class |
| `require-reveal-context` | warn | `x.reveal()` with no context and no enclosing `withRevealContext` |

The three rules that catch a value escaping are errors. The two that ask for more auditability are
warnings, because each has a shape it provably cannot see without type information: a context
installed in a caller, a class supplied through a spread.

No rule is auto-fixable. `no-credential-equality` and `explicit-class` offer editor suggestions
instead, because every rewrite they would make changes behaviour: `equals()` can throw where
`reveal()` did not, and a sensitivity class cannot be guessed from syntax.

An eslintrc project uses `plugin:@platform-sec/sensitive-string/legacy-recommended`, and a project
that must transmit only the serialized wire format uses the `strict` preset. See
[packages/sensitive-eslint-plugin/README.md](packages/sensitive-eslint-plugin/README.md) for the
options each rule takes and the limits each one has.

---

## Advanced Usage

### Custom Policies

```typescript
import { registerPolicy } from '@platform-sec/sensitive-string-core';

registerPolicy({
  name: 'credential',
  redact: (value) => `***${value.length} chars***`,
  requireConstantTimeEquals: true,
  allowPartialQueries: false,
  allowMask: false,
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

The policy registry is process-global and shared across duplicate installed
copies of core using `Symbol.for()`. This mutable configuration prevents
accidental misuse; it is not a security boundary against code already running
inside the process, which can replace a registered policy.

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
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { zSensitiveDeserialize } from '@platform-sec/sensitive-string-zod';

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

### Logger Integration (Winston)

```typescript
import winston from 'winston';
import { sensitiveFormat } from '@platform-sec/sensitive-string-core';

const logger = winston.createLogger({
  format: winston.format.combine(sensitiveFormat(), winston.format.json()),
  transports: [new winston.transports.Console()],
});

logger.info('Processing request', { token: sensitiveToken });
// {"level":"info","message":"Processing request","token":"[REDACTED:credential]"}
```

Install it at the **front** of `format.combine(...)`. In any later position the
output string has already been built and redaction cannot change what is
written; the format emits a process warning if it detects this.

Winston's own formats already redact `SensitiveString`, because the class
overrides `toString()`, `toJSON()`, and the inspect hook. The format matters for
transports that serialize the record themselves rather than through those hooks,
such as those writing to Elasticsearch, MongoDB, or an HTTP collector, and it
makes the redacted text identical across every transport.

A transport can also refuse records by sensitivity class outright:

```typescript
const logger = winston.createLogger({
  // stampClasses records what was redacted, so the transport check below can
  // still see it. Without it, redaction erases the evidence dropping needs.
  format: winston.format.combine(sensitiveFormat({ stampClasses: true }), winston.format.json()),
  transports: [
    new winston.transports.File({ filename: 'audit.log' }),
    new winston.transports.File({
      filename: 'debug.log',
      level: 'debug',
      format: sensitiveFormat({ dropClasses: ['credential'] }),
    }),
  ],
});
```

### Logger Integration (Pino)

```typescript
import pino from 'pino';
import { createSensitiveSerializer } from '@platform-sec/sensitive-string-core';

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

The `@platform-sec/sensitive-string-zod` package bridges Zod validation with `SensitiveString`. This section explains how they work together and when to use (or avoid) the integration.

### How It Works Step by Step

**Step 1: Define a schema with Zod helpers**

```typescript
import { z } from 'zod';
import { zCredential, zSensitive } from '@platform-sec/sensitive-string-zod';

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

#### You Need to Validate After Wrapping

Sensitive values can use policy-controlled partial queries without revealing the raw string:

```typescript
const { email } = schema.parse({ email: 'test@example.com' });

// Allowed and audited by the default sensitive policy
if (email.endsWith('@company.com')) { }
```

To keep the validation at the schema boundary, use `zSensitiveWithValidation` to validate before
wrapping:

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

This is intentional, since it forces you to think about where secrets go, but it adds friction.

#### Refinements After Transform Are a Reveal

Zod's `.refine()` runs after the transform, so its callback gets a `SensitiveString` rather than a
string, and a credential refuses the partial queries you would reach for:

```typescript
// Throws by default because credential partial queries are disabled
zCredential('api_key').refine(val => val.startsWith('sk-'))
```

Use `refineSensitive`, which reveals the value and is audited for it:

```typescript
zCredential('api_key').refineSensitive(raw => raw.startsWith('sk-'), {
  message: 'Must start with sk-',
})
```

A check that does not need the raw value at all is cheaper as validation before wrapping, where no
reveal happens:

```typescript
zSensitiveWithValidation(
  'credential',
  z.string().startsWith('sk-', 'Must start with sk-'),
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
| Complex post-transform validation | **Yes** - `refineSensitive`, or validate before wrapping |
| Interop with string-expecting libraries | **Use carefully** - reveal at integration points |

---

## Security

### Supply Chain Protection

This project implements comprehensive supply chain security measures:

- **Protected Branches**: Main branch requires signed commits, PR reviews, and status checks
- **Hardened Runners**: GitHub Actions run on hardened, ephemeral environments
- **Dependency Review**: Automated scanning for vulnerable and malicious dependencies
- **CodeQL Analysis**: Automated scanning for code vulnerabilities
- **SBOM Generation**: Software Bill of Materials for transparency
- **SLSA Provenance**: Build attestations at SLSA Level 3
- **Cosign Signatures**: All release artifacts signed and verifiable via Sigstore
- **License Compliance**: Enforced permissive licensing (MIT, Apache-2.0, BSD, ISC)

See [Supply Chain Security Documentation](.github/SUPPLY_CHAIN_SECURITY.md) for details.

### Reporting Security Issues

If you discover a security vulnerability, please file a [GitHub Security Advisory](../../security/advisories/new) rather than opening a public issue.

---

## License

MIT © AppSec Science, LLC
