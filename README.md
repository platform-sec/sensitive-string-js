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

# With Zod integration (Zod 4; v3 schemas cannot compose with v4 ones)
pnpm add @platform-sec/sensitive-string-core @platform-sec/sensitive-string-zod zod

# Stage 3 decorators: declarative field wrapping and reveal context
pnpm add @platform-sec/sensitive-string-core @platform-sec/sensitive-string-decorators

# NestJS: DTO decorators, transform pipe, context and response interceptors
pnpm add @platform-sec/sensitive-string-core @platform-sec/sensitive-string-nestjs

# Express: body wrapping, header extraction, context, response redaction
pnpm add @platform-sec/sensitive-string-core @platform-sec/sensitive-string-express

# Fastify: a schema keyword, field maps, header extraction, context, response redaction
pnpm add @platform-sec/sensitive-string-core @platform-sec/sensitive-string-fastify

# HTTP clients: reveal at the wire, the marker guard, and the two-path scrub
pnpm add @platform-sec/sensitive-string-core @platform-sec/sensitive-string-http \
         @platform-sec/sensitive-string-axios axios
# ...or -got, -ky, -fetch, -undici

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
  email: zSensitiveWithValidation('sensitive', z.email(), 'email'),
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
*   Do not call `reveal()` from a `toJSON()`. A redaction walk (`safeLog`, `safeStringify`, the logger serializers) runs an object's `toJSON()` to learn its JSON form and refuses any reveal made from inside it, redacting the object's own properties instead. Return the `SensitiveString` itself and let the walk redact it.

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

### Objects that refuse to answer

A redaction walk has to ask an arbitrary object a series of questions, and every
one of them runs through a hook the object controls: a `get` trap, a
`Symbol.toStringTag` getter, a `getPrototypeOf` or `has` or `ownKeys` trap, the
`toJSON` method, an enumerable getter, `toString`. **None of them can make a
redaction throw.** A logger calling `safeLog` must not be the thing that takes
down the request.

The likely case is not a Proxy at all: an ordinary object with an enumerable
getter that throws is what an ORM produces for a relation that was not loaded,
and enumerating properties invokes every one of them.

```typescript
// What an ORM defines on an instance for a relation it has not loaded: an own
// enumerable accessor, which enumerating the object invokes.
const order = { id: 7, token: new SensitiveString(rawToken, 'credential') };

Object.defineProperty(order, 'customer', {
  enumerable: true,
  get() {
    throw new Error('relation not loaded');
  },
});

safeLog(order);
// { id: 7, token: '[REDACTED:credential]', customer: undefined }
```

A property that refuses reads as absent while its siblings still read, and a
getter declared on the class rather than on the instance is not enumerated at
all, so it never reaches the output either way. An object that refuses to be
enumerated at all becomes `UNREADABLE`, the string `'[Unreadable]'`, which is
honest where an empty object would claim the value had no fields.

The built-in branches are guarded the same way. A Proxy around a `Map`, a
`Set`, a `Date`, an array or a `SensitiveString` answers `instanceof` through
the prototype it forwards and then throws from the built-in itself:
`Map.prototype.entries` refuses the proxy as its receiver, a Date proxy throws
from every method, the `toJSON()` a serializer calls later included, and the
brand check on the private field refuses the proxy as `toString()`'s receiver.
Each becomes `UNREADABLE` rather than an exception, and an `Error` whose
`message` is a getter that throws keeps its `name` and `stack` with the message
read as absent.

A `toJSON()` that reveals is refused. The walk runs an object's own `toJSON()`
to learn its JSON form, and could not tell a plain string that was always
plain from one that was a `SensitiveString` a moment ago, so `reveal()`,
`mask()`, `serialize()` and every transform throw `RevealDuringRedactionError`
while a walk is running caller code. The throw is absorbed like any other
refusal: the object's own properties are walked instead, the instance is
redacted as an instance, and neither the policy hook nor the audit hook sees
a reveal that never happened. Comparison still answers, since it discloses
nothing.

The two detectors answer opposite ways on purpose. `containsSensitive` returns
`true` for a value it could not read, because reporting it as clean is how a
caller ships a payload believing it was checked. `sensitiveClassesIn` contributes
no class, because there is no class to name for something that was never read.

One boundary is deliberate: `redactCopy` keeps each object's prototype so a
serializer downstream still sees the class, and then assigns onto the copy. A
prototype whose **setter** refuses therefore fails on the way out, which is a
write rather than a read and is not something a read guard can absorb. Use
`redactInStructure` where the output only has to be inert.

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
| Timing attacks | Constant-time comparison whenever either operand is a `credential` |
| Prototype injection through a `__proto__` key | Every copy a walk builds defines it as an own property rather than assigning it |

### Out of Scope (Documented Limitations)

| Limitation | Reason | Mitigation |
|------------|--------|------------|
| Memory dumps | JavaScript lacks secure memory primitives | Use `crypto.subtle` for encryption keys |
| Malicious code | Attacker with code execution can extract values | This is defense-in-depth, not a security boundary |
| Worker threads and child processes | `AsyncLocalStorage` is per isolate, and `structuredClone` strips an instance to `{ klass, label }` | [`toWorkerPayload` / `fromWorkerPayload`](#worker-threads-and-child-processes) carry the values and the context explicitly |
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

  // One-way transformations, audited like a reveal
  hash(
    algorithm: HashAlgorithm,
    options?: HashOptions,
    ctx?: RevealContext
  ): SensitiveString<'credential'>;
  hmac(
    algorithm: HashAlgorithm,
    key: string | Uint8Array | SensitiveString,
    options?: HmacOptions,
    ctx?: RevealContext
  ): SensitiveString<'credential'>;
  
  // Comparison, constant-time when either operand's class requires it
  equals(other: string | SensitiveString, ctx?: RevealContext): boolean;

  // Expiration
  readonly expiresAt?: Date;
  readonly renewalCount: number;
  isExpired(): boolean;
  ttlRemaining(): number | undefined;
  isRenewable(): boolean;
  renew(additionalTtl: number, options?: RenewalOptions, ctx?: RevealContext): void;

  // Reveal limits
  readonly revealCount: number;
  readonly revealsRemaining?: number;
  isExhausted(): boolean;

  // Revocation
  readonly isRevoked: boolean;
  readonly revocationReason?: string;
  readonly revokedAt?: Date;
  revoke(reason: string, ctx?: RevealContext): void;
  
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

### One-Way Hashing

```typescript
type HashAlgorithm = 'sha256' | 'sha384' | 'sha512' | 'sha3-256' | 'sha3-512';

interface HashOptions {
  salt?: string | Uint8Array;
  encoding?: 'hex' | 'base64' | 'base64url';  // default 'hex'
}

hash(
  algorithm: HashAlgorithm,
  options?: HashOptions,
  ctx?: RevealContext
): SensitiveString<'credential'>;

hmac(
  algorithm: HashAlgorithm,
  key: string | Uint8Array | SensitiveString,
  options?: HmacOptions,
  ctx?: RevealContext
): SensitiveString<'credential'>;
```

A lookup key, a deduplication key, or a correlation token: something derived from a value that can
be stored or compared without storing the value. Without it the caller reveals and hands the raw
value to a hashing library, which is a reveal the audit log records as one and a plain string
afterwards.

```typescript
const token = new SensitiveString(raw, 'credential', 'session_token');

const lookupKey = token.hash('sha256');
// SensitiveString<credential:session_token:hash> { [REDACTED:credential] }

await db.sessions.findUnique({ where: { tokenHash: lookupKey.reveal() } });
```

Taking a digest is an exposure. It runs the class policy, fires `auditReveal` with
`operation: 'hash'`, counts against a reveal budget, and refuses on an expired or revoked value.
A policy that sets `advisory.allowHash: false` forbids it outright; the flag has been declared
since the beginning and this is what reads it. Unset allows, unlike `allowSendToExternal`, because
hashing is the operation the library wants used in place of holding a value.

The result is always `credential`, whatever the source was, and it carries the deadline, the reveal
budget and the revocation of the value it came from. Taking the digest and then reading it are two
exposures of the same budget, so a value with `maxReveals: 1` can be hashed or stored, not both.

A digest of a value an attacker can enumerate is that value behind a lookup table: there are ten
billion Social Security numbers and a laptop hashes all of them in under a minute. Inheriting the
constraints is what stops `ssn.hash('sha256')` from being a way to spend one reveal and keep a
recoverable copy forever.

For a value that is guessable, salt is not enough, because the salt sits in the same row as the
digest. Key it:

```typescript
const email = new SensitiveString('jane@example.com', 'sensitive', 'email');
const pseudonym = email.hmac('sha256', process.env.CORRELATION_KEY!);
```

The key must be at least 16 bytes, the same floor `deriveKeyedToken` applies. A `SensitiveString`
key is read through its own gate, so its policy, audit hook, budget and revocation all apply, and
the result carries the constraints of the value and the key both.

MD5 and SHA-1 are refused with a reason rather than omitted from a list. A salt is prepended, never
appended, and an empty one is refused rather than read as no salt at all.

#### Password Storage

⚠️ `hash('sha256')` is not password hashing. It is fast, and speed is the one property a stored
password must not have: a wordlist runs through SHA-256 at billions of guesses a second on rented
hardware. Password hashing lives in a separate package, because Argon2 and bcrypt are native
modules and `core` has no runtime dependencies.

```typescript
import { hashForStorage, verifyHash } from '@platform-sec/sensitive-string-kdf';

const password = new SensitiveString(body.password, 'credential', 'password');
const stored = await hashForStorage(password, { algorithm: 'argon2id' });
// SensitiveString<credential:password:stored>

await verifyHash(stored, body.password); // true
```

`argon2id`, `argon2i`, `argon2d`, `bcrypt` and `scrypt`, with the parameters and the salt inside the
stored string, so verification reads them from the hash rather than from anything configured today.
`scrypt` needs only `node:crypto`, which makes it the answer for an application that cannot install
a native module. Every parameter has a floor as well as a default, and a value below it is refused
rather than quietly raised.

Unlike a digest from `hash()`, a stored hash is a fresh `credential` that does not inherit the
password's deadline or reveal budget. It has to outlive the password and be read on every login,
and a salted, memory-hard hash is not a reversible copy of the value. That is the whole difference
between the two functions.

bcrypt hashes at most 72 bytes and silently ignores the rest, so two passwords sharing a 72-byte
prefix verify against each other's hash. This package refuses the longer password instead, on both
the hashing and the verifying side.

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
`mask()`, `hash()`, `hmac()`, `serialize()`, and every string, regex, and template operation refuse
an expired value
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

### Reveal Limits and Rate Limiting

```typescript
interface SensitiveStringOptions {
  maxReveals?: number;          // over the whole life of the value; 0 means never
  revealWindow?: number;        // sliding window, in milliseconds
  maxRevealsPerWindow?: number; // exposures allowed inside that window
}
```

A bootstrap token or a reset link should be usable once. A secret read thousands of times a second
is usually a loop doing something it should not, and nothing in the process notices.

```typescript
const bootstrap = new SensitiveString(key, 'credential', 'bootstrap', { maxReveals: 1 });

bootstrap.reveal();         // works
bootstrap.revealCount;      // 1
bootstrap.revealsRemaining; // 0
bootstrap.isExhausted();    // true
bootstrap.reveal();         // throws RevealLimitExceededError
```

A window limits the rate rather than the total, and the refusal says how long to wait, so a caller
that means to continue can back off instead of fetching a new secret:

```typescript
const apiKey = new SensitiveString(key, 'credential', 'api_key', {
  revealWindow: 60_000,
  maxRevealsPerWindow: 100,
});

try {
  apiKey.reveal();
} catch (error) {
  if (error instanceof RevealRateLimitError) {
    await delay(error.retryAfter);
  }
}
```

The two compose. `maxReveals` is the one that cannot be waited out, so it is the one reported when
both would refuse. `revealWindow` and `maxRevealsPerWindow` must be given together, because either
alone is no rate limit at all, and `maxReveals: 0` is how a value is made unreadable rather than
`maxRevealsPerWindow: 0`.

An exposure is what an audit hook sees: `reveal()`, `mask()`, `hash()`, `hmac()`, `serialize()`,
`map()`, and every string, regex, and template operation, one per call. An `hmac()` with a
protected key counts once against the value and once against the key. `equals()` is not, and an
exhausted value can still be compared, because a comparison reads the value without disclosing it
and is the operation to reach for in place of a reveal. Redaction and metadata are not either:
`toString()`, `toJSON()`, `length`, `klass`, and `label` keep working on a spent value, which still
has to be safe to log.

`revealCount` is kept for every value, whether or not it limits anything. A read the gate refused,
or one an audit hook stopped by throwing, is not counted, so a broken audit sink cannot quietly
spend a single-use token.

Derived values share the counter rather than copying it, so a limit cannot be laundered by deriving
from the value it constrains:

```typescript
const bootstrap = new SensitiveString(key, 'credential', 'bootstrap', { maxReveals: 1 });

bootstrap.substring(0).reveal(); // throws: the substring spent the budget, and shares it
```

A value built from two constrained values is charged against both, reports the highest count and
the smallest remainder, and is exhausted as soon as either of them is.

Counters do not cross the wire. `serialize()` charges the sender, and the receiver starts a fresh
count with no limits, because two processes cannot share a counter and a payload must not be able
to describe its own budget. A limit that has to survive a service boundary belongs to the receiving
process's construction site.

```typescript
const received = SensitiveString.deserialize(payload);
received.revealCount; // 0
```

Nothing resets a count. There is no reset method, in test builds or otherwise: a control the
process can switch off is not a control, and a test wanting a fresh budget constructs a fresh value.

The sliding window keeps only the charges still inside it, so its memory is bounded by
`maxRevealsPerWindow` rather than by traffic, however long the value lives: the backing array holds
at most twice the limit, and a window that goes quiet for longer than its own length drops
everything on the next check.

Counters are per instance and per process. This finds a runaway loop, a retry storm, or a token
being used twice inside one service. It is not a defense against credential stuffing or against an
attacker who has the value: they hold their own copy of the string and never touch this instance
again.

### Revocation

```typescript
interface SensitiveStringOptions {
  revocationRegistry?: RevocationRegistry; // consulted on every read of this value
}

function revokeByLabel(label: string, reason: string): void;
function revokeByPattern(pattern: RegExp, reason: string): void;
function pruneRevocations(olderThan: Date | number): number;
function revocationCount(): { labels: number; patterns: number };
```

After a rotation the old secret is still in memory, still held by whatever closed over it, and still
works. Expiry does not help: the deadline was set when the value was made, and a compromise is
news that arrives later.

```typescript
apiKey.revoke('Rotated 2026-08-01');

apiKey.isRevoked;        // true
apiKey.revocationReason; // 'Rotated 2026-08-01'
apiKey.revokedAt;        // Date
apiKey.reveal();         // throws RevokedSensitiveValueError
```

For the instances a caller no longer holds a reference to, revoke by the label they were built
with:

```typescript
revokeByLabel('api_key', 'Emergency rotation');
revokeByPattern(/^session:/, 'User logged out');
```

Both lists are process-global and both reach values constructed before or after the revocation. A
`revocationRegistry` passed at construction is a fourth source, consulted on every read, which is
where a list backed by Redis or a control plane belongs. `RevocationList` is the in-process
implementation; anything with a synchronous `isRevoked(label)` satisfies the interface.

```typescript
const registry = new RevocationList();
registry.revoke('api_key:user_123', 'Account suspended');

const key = new SensitiveString(raw, 'credential', 'api_key:user_123', {
  revocationRegistry: registry,
});
```

A registry that throws denies the read, and so does one that answers with anything but a boolean. A
store that cannot be reached cannot confirm a value is usable, and an `async isRevoked` returns a
Promise, which is truthy and is not `true`: reading it either way would silently revoke everything
or nothing.

**There is no way back.** No `unrevoke`, no reset, no options object and no wire payload that lifts
a revocation. `pruneRevocations()` shrinks the global lists, and it cannot resurrect anything that
has already been refused: a value latches its own revocation the first time it observes one. That is
also the rule for when pruning is safe. Drop an entry only once nothing that could match it is still
reachable, after the rotation has drained and the requests that held those values have finished,
because a value that never looked between the revocation and the prune will not know.

The check lives in the same gate expiry and reveal limits do, so `mask()`, `hash()`, `hmac()`,
`serialize()`, `map()`, and every string, regex, and template operation refuse alongside
`reveal()`. So does `equals()`: a
comparison reads the value, and a rotated credential must not still be able to answer whether a
guess matches it. So does `renew()`, which reads nothing but must not keep working on a value
somebody deliberately took away. Redaction and metadata do not: `toString()`, `toJSON()`, `length`,
`klass`, and `label` keep working, because a value that can no longer be used still has to be safe
to log.

Revocation runs along derivation edges in both directions:

```typescript
const token = new SensitiveString(raw, 'credential', 'api_key');
const prefix = token.substring(0, 8);

prefix.revoke('the prefix leaked');
token.reveal(); // throws: the derivative carries the material it was made from
```

This is the opposite of `renew()`, which refuses on a derivative, and the asymmetry is about which
way each fails. Refusing to extend a lifetime fails closed. Refusing to end one does not: an
incident responder holding a substring, a match group, or a template result has no way to know it is
derived, and refusing them would leave the credential alive.

Label and pattern revocation match the label a value was **constructed** with. A derived value is
matched against its sources' labels rather than the one the derivation gave it, so revoking
`api_key` reaches every substring, match group, and template built from that value, while revoking
the combined label `a/b` that `concat()` produced matches nothing, because no value was ever
constructed under it.

Nothing may refuse a revocation. No policy hook is consulted, and the audit record is reported after
the fact with anything the sink throws swallowed, which is the mirror image of `renew()`. Revoking
an already-revoked value changes nothing and reports nothing, keeping the first reason and
timestamp.

`revokeByPattern` rejects a pattern that applies an unbounded quantifier to a group that can match
the same input more than one way. A stored pattern is tested against every label a value carries, on
a thread nothing can interrupt, so `(a+)+` in the list is a process that hangs on the first read
after somebody revokes something. The heuristic is strict and rejects some safe patterns; the
message says what to rewrite. Patterns are copied out of the caller's RegExp with `g` and `y`
dropped, which would otherwise make a stored pattern match every other time it was consulted.

A revoked value is not transmittable: `serialize()` reads the value, so it throws. The wire format
carries a `revoked` flag for the other direction, so a payload assembled elsewhere can tell the
receiver not to use what it is sending, and it can only ever tighten.

```typescript
SensitiveString.deserialize({ __sensitive: true, klass: 'credential', value, revoked: true });
// isRevoked: true. `revoked: false` is rejected rather than read as permission.
```

Revocation is a control over the values this process holds. It stops code from using a secret
somebody took away; it does not erase the secret from memory, it does not reach a raw string that
was already revealed, and it does not defend against code already executing in the process, which
can revoke anything or prune anything.

### Development Mode

```typescript
interface DevModeConfig {
  enabled: boolean;
  captureStackTraces?: boolean;    // stack of each exposure
  captureCreationStack?: boolean;  // stack of each construction
  warnOnRepeatedReveal?: { threshold: number; window: number } | false;
  warnOnMissingContext?: boolean;
  logReveals?: {
    enabled: boolean;
    logger?: (message: string) => void;  // default: console.warn
    showPartialValue?: boolean;          // development only
    partialLength?: number;              // default 4, capped at 8
  } | false;
}
```

A reveal that fails, or one that should never have happened, says very little on its own. The stack
names the caller of `reveal()` and nothing else: not where the value came from, not how many times
it has already been read, not which of the four `SensitiveString`s in scope this one is.
Development mode records that next to the value.

```typescript
if (process.env['NODE_ENV'] === 'development') {
  setDevMode({
    enabled: true,
    captureStackTraces: true,
    captureCreationStack: true,
    warnOnMissingContext: true,
    logReveals: { enabled: true, showPartialValue: true },
  });
}
```

```
[SensitiveString] Reveal of 'api_key' (sk_t...) without context
    at processPayment (src/payment.ts:45:12)
    at handleRequest (src/handler.ts:23:8)
Created at:
    at loadConfig (src/config.ts:12:15)
```

Everything is off until `setDevMode({ enabled: true })` is called. A process that never calls it
pays one property read per construction and one per exposure, which is the guard that keeps the
rest of it out of the way.

What counts as an exposure is exactly what an audit hook sees: the reads taken for the caller's
benefit rather than for redaction. `reveal()`, `mask()`, `hash()`, `hmac()`, `serialize()`, `map()`,
and the string, regex, and template operations all count; `equals()` does not, because a comparison
reads the value without disclosing it, and neither does redaction. A read the gate refused is not
counted either, so a reveal that threw is absent rather than recorded as a reveal that happened.

`warnOnMissingContext` reports the reveals that nothing explains, and does so even when
`logReveals` is off, which is usually the first thing worth seeing. `logReveals.enabled` reports
every exposure, with or without a context.

`showPartialValue` prints the first few characters of the value. It is a real disclosure, off by
default, and bounded twice: by `partialLength`, which is capped at 8, and by the same floor on
hidden characters that `mask()` enforces for the class, which is 4 for `sensitive` and 8 for
`credential`. A value too short to keep that floor shows nothing at all rather than most of itself.
Note that this shows a prefix of a `credential`, which `mask()` refuses outright: the flag exists
to tell two values apart in a debugger, it trades away a little of what the rest of this library
protects, and it belongs nowhere but a development machine.

`warnOnRepeatedReveal` catches the loop that reveals the same value on every iteration:

```
[SensitiveString] Warning: 'session_token' revealed 10 times in 5000ms
    Consider caching the revealed value or reviewing the code path.
    Most recent reveal at:
    at renderLoop (src/ui.ts:123:18)
```

Reveals are counted per value in fixed windows rather than a sliding one, and the warning fires as
the threshold is crossed and then stays quiet for the rest of the window. A loop revealing a
thousand times a second produces one line per window instead of a thousand, and a burst that
straddles a boundary is reported by the window it finishes in.

The recorded history is also readable:

```typescript
const debug = secret.__devInfo;
debug?.createdAt;         // Date
debug?.creationStack;     // string | undefined
debug?.revealCount;       // exact, and never forgotten
debug?.revealTimestamps;  // the most recent 64, oldest first
debug?.lastRevealStack;   // string | undefined
```

`__devInfo` is `undefined` when development mode is off, rather than a missing property, so the
same debugging code compiles and runs in production. It holds no part of the raw value, and it is
not an own property of the instance: `toString()`, `toJSON()`, `util.inspect()`, `serialize()` and
the redaction walkers are unchanged by it. Records live in a `WeakMap` keyed by the instance, so a
value's history is collected with the value.

A record is only kept for a value constructed while development mode was on. Turning it on
afterwards does not recover a history that was never taken, so enable it at startup, before the
values you intend to inspect exist.

Enabling it while `NODE_ENV` is `production` prints a warning, because the combination is a
security risk rather than a configuration mistake:

```
[SensitiveString] Dev mode enabled in production! This is a security risk: it records stacks and,
with showPartialValue, writes part of every revealed value to a log.
```

Development mode never changes what a program does. A logger that throws is swallowed rather than
turning a successful reveal into a failed one, which in development would look exactly like a bug
in the caller.

For tests, `withDevMode()` installs a configuration and restores the previous one afterwards. It is
synchronous: the configuration is process-global, so it cannot follow one asynchronous task without
following every other task interleaved with it.

```typescript
withDevMode({ enabled: true, logReveals: { enabled: true, logger } }, () => {
  secret.reveal();
});
```

### Zod Schemas

```typescript
// Basic sensitive string
zSensitiveString<C extends SensitivityClass>(klass: C, label?: string)

// Sensitive (PII, business data)
zSensitive(label?)

// Credential (passwords, API keys, tokens)
zCredential(label?)

// With custom validation. The schema is any string-to-string schema, so Zod 4's
// format constructors (z.email(), z.uuid(), ...) work as well as z.string().
zSensitiveWithValidation(klass, stringSchema, label?)

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

// A default produced as a raw string and wrapped by the schema. The fallback
// lives in a closure, so z.toJSONSchema() cannot publish it.
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

`issue.path` is the one channel these helpers deliberately leave alone, because redacting it would
collapse a multi-issue error into a list of unattributed complaints. Do not key an object, record,
or map by a sensitive value; put it in the value position, which is what `zSensitiveRecord` does.

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
// toJSON() methods still run, shared references stay shared, Map and Set are
// copied entry by entry, and streams, Buffer, Date, RegExp, and URL pass
// through by reference.
redactCopy(value: unknown): unknown;

// Check for sensitive values, SensitiveString instances and serialize() results alike
containsSensitive(obj: unknown): boolean;

// Collect the sensitivity classes present in a structure
sensitiveClassesIn(obj: unknown): Set<SensitivityClass>;

// The marker a walk substitutes for an object it could not read at all
UNREADABLE: '[Unreadable]';

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

### Worker Handoff

```typescript
// Sender: values in the wire format plus the portable part of the context
toWorkerPayload<T>(values: T, options?: {
  worker?: string | URL;          // audit field, recorded and never verified
  context?: RevealContext;        // defaults to the ambient context
  data?: unknown;                 // non-sensitive passthrough, checked against transport
  transport?: 'clone' | 'json';   // 'json' for child_process IPC
}): WorkerPayload<T>;

// Receiver: rebuild the instances and take the raw values out of the payload
fromWorkerPayload<T>(payload: unknown, options?: {
  auditReveal?: RevealContext['auditReveal'];
  allowUnaudited?: boolean;       // reported by the no-allow-unaudited lint rule
  require?: readonly string[];
  keepPayload?: boolean;
}): { values: T; context: RevealContext; data: unknown };

// Receiver: the above followed by withRevealContext()
withWorkerPayload<T, R = unknown>(payload: unknown, options, fn: (values: T, data: unknown) => R): R;
```

TypeScript has no partial type argument inference, so naming the values type alone on
`withWorkerPayload` fills the return type from its default instead of inferring it. That is harmless
when the result is discarded, which is the usual shape in a worker. Annotate the callback's
parameter, `({ token }: Values, data) => ...`, to have both inferred, or name both.


Every refusal extends `SensitiveStringError` and carries a `code`:
`MalformedWorkerPayloadError`, `ConsumedWorkerPayloadError`, `MissingWorkerValueError`,
`UnregisteredClassError`, `UnauditedWorkerError`, `UnportableDataError` and
`UnshareableConstraintError`. See [Worker Threads and Child Processes](#worker-threads-and-child-processes).

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

### Fastify Plugin

From `@platform-sec/sensitive-string-fastify`. Two independent halves: an Ajv keyword that wraps
during validation, and a plugin for everything a schema cannot express.

```typescript
// The keyword goes into the constructor: Ajv is built with the instance.
const fastify = Fastify({ ajv: { customOptions: { keywords: [sensitiveKeyword] } } });

await fastify.register(sensitivePlugin, {
  context: (request) => ({ name: `${request.method} ${request.routeOptions.url}` }),
  headers: { authorization: 'credential' },
  responseFilter: true,
});

fastify.post('/api/auth/login', {
  schema: {
    body: {
      type: 'object',
      properties: {
        email: { type: 'string', format: 'email', sensitive: { klass: 'sensitive' } },
        password: { type: 'string', minLength: 8, sensitive: { klass: 'credential' } },
      },
    },
  },
}, handleLogin);
```

The keyword wraps a property after that property's own checks ran on the raw string, so `format` and
`minLength` still reject as they did, and it reaches nested objects, array items, `$ref` schemas, the
querystring, and params. Routes without a schema use the plugin's `body` field map instead, scoped by
Fastify's own encapsulation rather than by a pattern option, and gated to JSON and urlencoded bodies
so a multipart `Buffer` is never flattened by the clone. Fastify 5 only. See
[packages/sensitive-fastify/README.md](packages/sensitive-fastify/README.md) for the hook order table,
the three schema positions the keyword must stay out of, and the custom validator compiler
limitation.

### Error Tracking (Sentry, Bugsnag, Rollbar)

From `@platform-sec/sensitive-string-sentry`, `-bugsnag` and `-rollbar`, over the shared
`@platform-sec/sensitive-string-scrub`. An error tracker is the one dependency whose entire purpose
is to collect application state and send it elsewhere. Every other integration leaks when the
application makes a mistake; this one leaks when the application does nothing at all.

Measured on `@sentry/node` 10.73.0, stock defaults, no `sendDefaultPii`, one inbound request:

```
request.headers.authorization  "Bearer LEAKED_SECRET_abc123xyz"
request.headers.cookie         "session=LEAKED_SECRET_abc123xyz"
request.url                    "http://127.0.0.1:8080/pay?token=LEAKED_SECRET_abc123xyz"
```

Nothing there was ever wrapped, so there is no `SensitiveString` in that event and nothing for the
library to redact. The leak is the raw strings nobody wrapped, which is what the denylist is for.

```typescript
import * as Sentry from '@sentry/node';
import { withSensitiveScrubbing } from '@platform-sec/sensitive-string-sentry';

Sentry.init(
  withSensitiveScrubbing(
    { dsn: process.env.SENTRY_DSN, beforeSend: (event) => event }, // composed, not replaced
    { denyKeys: ['x-internal-signature'] }
  )
);
```

The three lines above close with no configuration. `withSensitiveScrubbing` composes all six of the
SDK's `before*` hooks and appends an integration whose `setup()` registers a scope event processor,
which is the only seam that both holds live `SensitiveString` instances and runs after every other
integration. Structural redaction goes through `redactCopy` rather than `redactInStructure`, because
an event legitimately holds the same object at two paths and the log-line walk turns the second one
into `'[Circular]'`.

No hook throws, and none returns something the SDK will mishandle. On an internal failure an event
becomes a stub carrying the exception type and a `sensitive.scrub_failed` tag, because a `beforeSend`
that throws makes Sentry drop the real error and send one about the scrubber instead; a transaction,
log or metric is dropped instead, because a malformed payload of those shapes is worse than an absent
one. A span is neither: returning `null` from `beforeSendSpan` is disallowed and makes the SDK emit
the original unscrubbed span, so that seam always answers with a span it has scrubbed.

Spans are also where the URLs live. One `http.get` puts a query token into `url.full`, `http.url`,
`http.target`, `http.query` and `url.query`, and all five are covered, with a test that drives a real
outbound request rather than a hand-built fixture. A seventh `before*` hook in a future SDK release
fails `pnpm typecheck` rather than opening quietly. See
[packages/sensitive-sentry/README.md](packages/sensitive-sentry/README.md) for the hook map, the
`recommendedDataCollection` object, and the gap around processors registered after `init`, and
[packages/sensitive-scrub/README.md](packages/sensitive-scrub/README.md) for the denylist and the
inverted marker rule.

The other two vendors share that denylist and differ in what they need on top of it, which is the
argument for a shared layer rather than three of them.

```typescript
Bugsnag.start(withSensitiveScrubbing({ apiKey: process.env.BUGSNAG_KEY! }, policy));
const rollbar = new Rollbar(withSensitiveScrubbing({ accessToken }, policy));
```

Bugsnag needs the most. Its `redactedKeys` default is the single key `password`, and measured, it
applies only under `metaData`, breadcrumb metadata, `request` and `response`, so `context`, `user`,
`featureFlags` and the exception itself are the callbacks' work alone. The package composes all three
callbacks *and* feeds the resolved denylist into `redactedKeys`, because neither half covers what the
other does.

Rollbar needs the least, and its README says so. It ships 25 `scrubFields`, 10 `scrubHeaders` and a
query-parameter pass over URLs, all applied before the one seam a user can install. What the package
adds is the names those lists omit, the wire format no key list describes, the paths Rollbar
documents but does not apply, and two things specific to this vendor. It is the only SDK measured
that does not honour `toJSON()`: a wrapped value arrives at every seam as `{ klass, label }`, so the
value is safe and the **label is not**, and putting the marker back is what keeps labels off by
default here. And a `transform` that throws makes Rollbar disable it for the life of the process and
send the original item, so a caller's own transform is called inside the guard rather than beside it.

Both suites assert on the bytes that actually left the process, against the real SDK driven to a
server on loopback, with a companion case requiring each position to leak once the scrubbing is
removed. That is not a flourish: on both vendors a scrubbing pass runs inside the SDK's own encoder,
so an assertion on the payload object cannot see half of what protects it. The Sentry suite asserts
on the envelope the transport receives, and has one case that goes all the way to the bytes. See
[packages/sensitive-bugsnag/README.md](packages/sensitive-bugsnag/README.md) and
[packages/sensitive-rollbar/README.md](packages/sensitive-rollbar/README.md).

### HTTP Clients

From `@platform-sec/sensitive-string-axios`, `-got`, `-ky`, `-fetch` and `-undici`, over the shared
`@platform-sec/sensitive-string-http`. This is the one integration category where the library's
default is actively wrong for the caller's intent. Everywhere else redaction fails closed and a log
line merely loses information; at the wire the intent is to transmit the value:

```typescript
await axios.post('/charges', { amount }, { headers: { Authorization: `Bearer ${token}` } });
```

`Authorization: Bearer [REDACTED:credential]` goes out. axios does not throw, the server answers 401,
and the first person to debug it pastes the raw token back in.

So the integration has to reveal, and that is where the real problem starts. Measured on axios 1.20.0,
got 16.0.0 and ky 2.1.0, a revealed value survives the call: on the rejection in
`error.config.headers`, `error.options.headers` and `error.request`, in `error.toJSON()` for axios,
and on the **resolution** for axios and got, so `console.log(res)` after a successful call prints the
credential and no error ever existed for an error handler to catch. The error tracking integration
does not help, because by then the value is a plain `string` and `containsSensitive` returns `false`.

```typescript
import axios from 'axios';
import { bearer, createSensitiveAxios } from '@platform-sec/sensitive-string-axios';

const api = createSensitiveAxios(axios.create({ baseURL: 'https://api.example.com' }), {
  reason: 'charge authorization',
  allowedHosts: ['api.example.com'],
  responseFields: { 'customer.email': 'sensitive' },
});

const res = await api.post('/charges', { amount, card: { number: cardNumber } }, {
  headers: { Authorization: bearer(token) },
});

res.data.customer.email; // SensitiveString<'sensitive'>
```

`bearer(token)` rather than `` `Bearer ${token}` `` is the whole trick: the helper takes the instance,
so the reveal and the base64 or prefix encoding both happen inside the wrapper, where a marker guard
can read the result. The guard scans three encodings, because a query string carries
`%5BREDACTED%3Acredential%5D` and axios's `params` serializer produces a third, partly encoded form
that neither literal scan catches.

`allowedHosts` is not optional thinking. A 302 to another origin strips `Authorization`, `Cookie` and
`Proxy-Authorization` on all five wrapped clients, because the Fetch specification names those three
and nothing else, and forwards `x-api-key` verbatim. Most providers authenticate with a name outside
that set, so a credential sent to a host the caller trusts is delivered to a host they never named, on
that host's say-so. That exemption is recorded per client, from a measurement of each one, rather than
assumed from the specification: clients that ignore it exist, so a client this package has not
measured is exempt from nothing and defaults to refusing redirects. When the hosts genuinely cannot be
named in advance, which is the ordinary case for a provider that redirects a download to object
storage, `allowedHosts: 'strip'` follows the hop with every credential-bearing header removed at the
origin boundary. Which headers those are is derived from what the caller wrapped, not from a list of
names the library had to guess.

The wrapper owns the call rather than installing a hook: axios's request interceptor sees stringified
headers and a structured body, got's `beforeRequest` sees the exact mirror image, and `fetch` and
undici have no hook at all. See
[packages/sensitive-http/README.md](packages/sensitive-http/README.md) for the full measurement
tables, the guard's three encodings, and the two places a request object is dropped rather than
rewritten.

### Lint Rules

From `@platform-sec/eslint-plugin-sensitive-string`, a dev dependency. A type keeps a secret
wrapped; it cannot stop `console.log(secret.reveal())`, because the reveal produces an ordinary
string and logging a string is ordinary code. Eight rules read the call instead: six from its
shape alone, two from the types of its arguments.

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
| `no-password-fast-hash` | warn | `password.hash('sha256')`, a fast digest where a KDF belongs |
| `no-allow-unaudited` | error | `fromWorkerPayload(d, { allowUnaudited: true })`, which drops an audit hook the sender asked for |

The three rules that catch a value escaping are errors. The three that reason about something they
cannot see are warnings: a context installed in a caller, a class supplied through a spread, and a
password recognised by what the variable holding it is called.

`require-reveal-context` also covers `mask()`, `hash()`, `hmac()` and `serialize()`, which the
library audits exactly as it audits a reveal, but only in a file that has a TypeScript program:
`bcrypt` and `node:crypto` have a `hash` method and every ORM has a `serialize`, so the receiver's
type is the only thing that separates `token.hash('sha256')` from `bcrypt.hash(password, 12)`.

`no-password-fast-hash` is the one rule here that reads a name rather than a shape, because no type
separates a password from an API key: both are `SensitiveString<'credential'>`. It reports
`password.hash('sha256')` and points at `hashForStorage()` from the `kdf` package.

Two more rules answer a question no syntax answers, "does this value carry a sensitive one inside
it", so they need a TypeScript program and live only in the `-type-checked` presets:

| Rule | `recommended-type-checked` | Catches |
|---|---|---|
| `no-stringify-sensitive` | error | `JSON.stringify(payload)` where `payload` holds a `SensitiveString`, whose value it silently replaces with the redaction, or a `serialize()` result, which it writes in the clear |
| `prefer-safe-log` | warn | `console.log(user)` where `user` holds one, so what is written is whichever serializer the transport reached for |

```js
export default [
  { files: ['**/*.ts'], languageOptions: { parser: tseslint.parser, parserOptions: { projectService: true } } },
  sensitive.configs['recommended-type-checked'],
  { files: ['**/*.js'], ...sensitive.configs['disable-type-checked'] },
];
```

Applied to a file with no program, both report that fact once rather than falling silent, because a
rule that reports nothing looks exactly like a rule that found nothing.

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

`checkRevealAllowed` must be synchronous and return nothing. It denies by
throwing, and the gate reads the value in the same call, so an `async` hook
could only ever throw into a Promise after the raw value had been returned.
Its declared return type is `undefined` rather than `void`, which makes an
`async` function a compile error, and the gate refuses at runtime any hook
that returns a value, a Promise included.

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

### Secret References

A serialized payload puts the raw value on the wire and relies on the transport. Where the value
came from a secrets store and the receiver can reach that store too, send a pointer instead: the
value never leaves the process that fetched it.

```typescript
// Sender: mint from the record the read returned, not from the value.
import { toReference } from '@platform-sec/sensitive-string-secrets';

const record = await vault.get('kv/payments/stripe');
await queue.send({ job: 'charge', key: toReference(record, { store: 'vault-prod' }) });

// Receiver: resolve against an allowlist, never against a bare path from the payload.
import { createReferenceResolver } from '@platform-sec/sensitive-string-secrets';

const resolver = createReferenceResolver({
  store: 'vault-prod',
  source: vault,
  allow: [{ path: 'kv/payments/*', klass: 'credential' }],
});

const key = await resolver.resolve(job.key, { context: { name: 'charge-worker' } });
```

`resolve()` runs in the receiver, with the receiver's credentials, against a path the sender chose,
which is a confused deputy unless it is constrained. So the resolver is constructed with an
allowlist and refuses everything else: the store identity must match exactly, a path carrying a
traversal or an empty segment is refused rather than normalized, a version outside
`[A-Za-z0-9._:-]{1,128}` is refused, and the class comes from the allowlist. A class on the wire may
tighten the receiver's rule and may never loosen it, because a receiver that took `klass` from a
payload would let a sender turn off constant-time comparison for a credential.

There is no `token.toReference()`. A derived instance inherits its sources' state, so a substring
would mint a pointer to the whole credential, and the label rule deliberately strips the account, so
an instance knows a path and not which store it is in. Minting takes the record.

A reference carries no secret material, so every redaction walk emits it as it is and
`containsSensitive()` answers false for one: being able to see which secret a job refers to is the
point of passing references at all. `@platform-sec/sensitive-string-core` owns the format and the
`isSensitiveValueReference()` guard; minting and resolving live in
`@platform-sec/sensitive-string-secrets`, which is the layer that knows the store, the version and
the credentials. Full documentation is in [that package's
README](packages/sensitive-secrets/README.md#references-send-a-pointer-not-a-value).

### Worker Threads and Child Processes

A `SensitiveString` handed to a worker arrives broken, and nothing says so. `structuredClone`
keeps the public fields and drops the private one, so `workerData: { token }` delivers a plain
`{ klass, label }` that answers `klass` correctly and fails at the first method call, in another
thread. The usual fix, `workerData: { token: token.reveal() }`, works and leaves the plaintext in a
plain string for the life of the thread. `AsyncLocalStorage` is per isolate too, so a reveal in the
worker has no context.

`toWorkerPayload()` builds a payload out of the wire format and `withWorkerPayload()` rebuilds the
instances on the far side, with the context's `name`, `reason` and `tags` carried across:

```typescript
// main thread
import { Worker } from 'node:worker_threads';
import { toWorkerPayload } from '@platform-sec/sensitive-string-core';

const worker = new Worker(workerFile, {
  workerData: toWorkerPayload({ token }, { worker: workerFile, data: { batchSize: 100 } }),
});
```

```typescript
// worker
import { workerData } from 'node:worker_threads';
import { withWorkerPayload } from '@platform-sec/sensitive-string-core';

await withWorkerPayload<{ token: SensitiveString<'credential'> }>(
  workerData,
  { auditReveal: (value, details) => logger.info('reveal', { klass: value.klass, ...details }) },
  async ({ token }, data) => {
    await callApi(token.reveal(), data);
  },
);
```

What crosses is what `serialize()` puts on the wire: the value, its class, its label and its
deadline. Building the payload is a reveal of each value through the ordinary gate, so an expired,
revoked or policy-denied value refuses on the sending side, and each value produces one audit record
with `operation: 'worker-handoff'`, the payload key, and the `worker` name the caller gave.

Four things the boundary changes, each of which the helpers turn into a refusal rather than a
silent degradation:

- **The audit hook does not cross.** A function does not survive structured clone. A payload built
  under an audited context arrives marked `audited: true`, and `fromWorkerPayload()` throws
  `UnauditedWorkerError` unless this side passes `auditReveal`, runs inside a `withRevealContext()`
  that carries one, or passes `allowUnaudited: true`. The lint rule `no-allow-unaudited` reports the
  last of those, because it means the sender asked for reveals to be recorded and they will not be.
- **Policies are per thread.** A class registered with `registerPolicy()` on the main thread does not
  exist in a worker. `UnregisteredClassError` names the class and says to register it in the
  worker's own bootstrap; nothing in a payload can install, change or weaken a policy.
- **A reveal limit cannot cross.** `maxReveals` and the rate-limit window are counters shared by
  reference, and a thread has no reference to share, so a handoff would give every worker a fresh
  budget. `toWorkerPayload()` refuses such a value with `UnshareableConstraintError` before reading
  anything.
- **The transports disagree.** `workerData`, `postMessage`, `MessagePort` and `BroadcastChannel` use
  structured clone; `child_process` IPC uses JSON, which drops a function silently where the clone
  throws, and turns a `Date` into a string and a `Map` into `{}` where the clone keeps them.
  `transport: 'json'` validates `data` and `tags` for the serializer that will actually run. The one
  mistake the option cannot catch is its omission: a `Date` in `data` under the default check arrives
  at a forked child as a string.

`fromWorkerPayload()` consumes the payload: it deletes the raw values from the object it was handed
and marks it `consumed`. `workerData` is one mutable object shared by every module in the thread, so
after that a `console.log(workerData)`, a crash handler serializing it, or a dependency walking it no
longer reads the values, and a second `fromWorkerPayload()` throws `ConsumedWorkerPayloadError`
rather than rebuilding anything.

That is per copy, not per payload. Every transport clones, so a payload posted to two workers
arrives twice, whole, and each copy is consumable once; the sender's own object is untouched by
either. Consumption shortens how long one thread holds plaintext. It is not a use-once token, and
building one out of it would be a mistake. Before consumption the payload is made of wire objects, so
`safeStringify`, `safeLog`, `redactInStructure`, `redactCopy` and the logger serializers redact it;
`JSON.stringify` and `util.inspect` do not, which is the window consumption closes.

The reverse direction needs no options. A worker sending results back builds a payload under its own
audited context, and a parent `'message'` handler registered inside `withRevealContext()` already has
an ambient hook, so `fromWorkerPayload(message)` satisfies the requirement as it stands.

#### What this does not fix

Three things a reader who ships `toWorkerPayload()` and believes the worker boundary is now closed
would be wrong about, all measured:

- **`process.env` is copied into every worker by default.** A service that reads secrets from the
  environment already has them in every worker it starts. Pass an `env` allowlist to the `Worker`
  constructor; the `sensitive-env` package is the row that covers the environment itself.
- **An error crossing back carries its own properties and its stack.** A worker that throws an
  application error whose `message` holds a raw value delivers that value to the parent's `'error'`
  handler. The library's own errors put a label and a deadline in the message and never a value; the
  exposure is in application errors, and it is the same exposure those errors have in-process.
- **A `revocationRegistry` does not cross.** It is construction state, like the deadline, but unlike
  the deadline it is a function table and the wire format has never carried one, so a value built
  with one is rebuilt in the worker without it and stops consulting that list. Instance revocation
  travels as a flag and the process-global lists are per isolate, so a worker that needs either
  registers its own. This is the wire format's standing behaviour rather than something the handoff
  introduced, and `serialize()` across a service boundary loses it the same way.
- **The plaintext window is shortened, not eliminated.** Deleting a property removes the reference
  reachable through `workerData`; it does not erase the string from the heap. A heap snapshot, an
  attached debugger, or `/proc/<pid>/mem` still sees the value until it is collected, which is the
  same limitation the library has everywhere. `postMessage` after start keeps the window shorter than
  `workerData`, because a message is garbage once its handler returns where `workerData` lives as
  long as the thread.

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

#### One case where the marker is lost: a wildcard `redact.paths`

If your pino config has a wildcard redaction path, a wrapped value logged as a
**direct property of the merging argument** serializes as pino's
`[unable to serialize, circular reference is too complex to analyze]` instead of
its redaction marker.

```typescript
const logger = pino({ redact: { paths: ['*.token'] } });

logger.info({ apiKey: sensitiveToken }, 'x');
// {"apiKey":"[unable to serialize, circular reference is too complex to analyze]"}

logger.info({ payload: { apiKey: sensitiveToken } }, 'x');
// {"payload":{"apiKey":"[REDACTED:credential]"}}   one level down is fine
```

Nothing is disclosed: the value does not appear. What is lost is the marker, so
the line no longer tells you a credential was there. Three things have to hold at
once, and dropping any one of them avoids it: a **wildcard** entry in
`redact.paths` (a literal path list is unaffected at any depth), a class instance
carrying an **ES private field**, and that instance at the **top level** of the
log object. One level down, or inside an array, renders correctly.

This is not something we can fix from inside the library. The same failure
reproduces with any class carrying a `#private` field and no `toJSON` at all, and
does not reproduce with the identical class minus the private field; `Date` and
plain objects with a `toJSON` are unaffected. `#value` is what makes the wrapped
value unreadable by reflection, so it is not something we would trade away.

The remedy is one line, and it leaves pino's own redaction working:

```typescript
const logger = pino({
  redact: { paths: ['*.token'] },
  formatters: { log: (o) => JSON.parse(JSON.stringify(o)) },
});

logger.info({ apiKey: sensitiveToken }, 'x');
// {"apiKey":"[REDACTED:credential]"}
```

It matters more than the top-level condition suggests, because `logger.info(data,
msg)` is the ordinary pino idiom and puts every field of `data` at exactly that
level. Measured against pino 10.3.1.

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
  z.email().endsWith('@company.com', 'Must be company email'),
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

## Versioning and Releases

The workspace packages version independently. A provider- or framework-specific change therefore
does not force unrelated packages to release, while internal dependents are bumped when a changed
range requires it. User-visible pull requests record their intended package and SemVer impact with:

```bash
pnpm changeset
```

The Version Packages pull request commits package manifests, package changelogs, internal ranges,
and the lockfile together. Publishing consumes only those committed versions and publishes the same
tarballs that the release workflow checked and signed. Contributors and maintainers should follow
the complete procedure in [RELEASING.md](RELEASING.md).

---

## Security

### Supply Chain Protection

This project implements comprehensive supply chain security measures:

- **Release Controls**: Publication is restricted to `main` and scoped to the `npm-publish`
  environment, which should require maintainer approval
- **Hardened Runners**: GitHub Actions run on hardened, ephemeral environments
- **Dependency Review**: Automated scanning for vulnerable and malicious dependencies
- **CodeQL Analysis**: Automated scanning for code vulnerabilities
- **SBOM Generation**: Software Bill of Materials for transparency
- **SLSA Provenance**: Build attestations at SLSA Level 3
- **Cosign Signatures**: Exact package tarballs selected for publication are signed and verifiable
  via Sigstore
- **License Compliance**: Enforced permissive licensing (MIT, Apache-2.0, BSD, ISC)

See [Supply Chain Security Documentation](.github/SUPPLY_CHAIN_SECURITY.md) for details.

### Reporting Security Issues

If you discover a security vulnerability, please file a [GitHub Security Advisory](../../security/advisories/new) rather than opening a public issue.

---

## License

MIT © AppSec Science, LLC
