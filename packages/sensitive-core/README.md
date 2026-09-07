# @platform-sec/sensitive-string-core

Core library for handling sensitive string data with automatic redaction, type-safe classification, and audit-ready reveal patterns.

## Installation

```bash
pnpm add @platform-sec/sensitive-string-core
```

## Requirements

- Node.js 22.12+
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
- **Partial Masking**: `mask()` shows a bounded part of a value for support and debugging, under
  the same authorization and audit hooks as `reveal()`
- **Protected Regex Operations**: Query, match, and extract groups without returning plain strings
- **Built-in Patterns**: Anchored `patterns.email` structural validation
- **Template Literals**: `st` builds a protected value from interpolated secrets, inheriting the
  most restrictive class
- **Expiration**: `ttl` and `expiresAt` stop a value from being used past its deadline, and
  derived values expire with the value they came from
- **Reveal Limits**: `maxReveals` makes a token single-use, a sliding window catches a runaway
  loop, and derived values spend the same budget
- **One-Way Hashing**: `hash()` and `hmac()` derive a lookup or correlation token through the same
  gate as a reveal, and return it as a protected `credential` carrying the source's constraints.
  Password storage lives in `@platform-sec/sensitive-string-kdf`, since a fast digest is the wrong
  tool for it
- **Path-Based Wrapping**: Wrap sensitive fields in complex objects by path
- **Development Mode**: `setDevMode()` records where a value came from, how often it has been
  exposed and from where, off by default and behind one guard when it is
- **Deterministic Redaction**: `deterministicRedaction()` registers a policy whose redacted output
  carries a keyed tag, so a log reader can tell whether two redacted lines are the same value. Opt
  in, keyed only, and refused for `credential`
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

The parsed object is the attacker's shape. A body with a `"__proto__"` key parses to an own property
of that name, inert where it sits, and the copy `wrapSensitiveByPath` returns keeps it that way: the
key is copied as an own data property, never assigned, so the wrapped object inherits nothing the
body supplied and `wrapped.isAdmin` reads what the body read. The same rule applies to the copies
`redactInStructure` and `redactCopy` build.

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

The policy registry, the reveal-context storage, the development mode
configuration and the revocation lists are shared across duplicate installed
copies of core through `Symbol.for()`. Policy registration is mutable
process-global configuration: it protects against accidental misuse and
misconfiguration, but code already executing in the process can replace a policy
and must be trusted. The same is true of `setDevMode()`, which is why enabling
it under `NODE_ENV=production` prints a warning, and of `revokeByLabel()`,
`revokeByPattern()` and `pruneRevocations()`, which defend against a stale
secret rather than against a hostile caller.

## Worker threads and child processes

`AsyncLocalStorage` is per isolate and `structuredClone` strips an instance to
`{ klass, label }`, so neither a value nor its context crosses a worker boundary
on its own. `toWorkerPayload()` builds a payload in the wire format with the
context's `name`, `reason` and `tags`, and `withWorkerPayload()` rebuilds the
instances on the far side, installs that side's own audit hook, and deletes the
raw values from the payload object so `workerData` stops holding plaintext. The
[main README](../../README.md#worker-threads-and-child-processes) has the full
account, including the three things the boundary still does not close.

## Deterministic redaction

`deterministicRedaction(klass, { key })` builds a policy whose `redact` renders
`[REDACTED:sensitive:5f2a91c0b74e]` instead of `[REDACTED:sensitive]`, so the log
lines that concern one subject can be found without the subject being disclosed.

It changes what redacted output means: it stops being constant and starts
carrying a keyed fingerprint of the value, which is disclosure by design. The
tag is an HMAC with no unkeyed mode, the key floor is 16 bytes, the tag floor is
12 hex characters, and `credential` is refused. The policy declares a
`markerPattern`, so the guards that refuse to send a redaction onward still
recognize one. The [main README](../../README.md#deterministic-redaction) has
the trade-offs, the collision arithmetic and the measured cost.

## Secret references

`SensitiveValueReference` is the wire shape of a pointer to a value in a
secrets store, and `isSensitiveValueReference()` is the guard for it. Only the
format lives here, because the walks that meet a payload on the way to a log
line are here; minting and resolving live in
[`@platform-sec/sensitive-string-secrets`](../sensitive-secrets/README.md#references-send-a-pointer-not-a-value),
which is the layer that knows the store, the version and the credentials.

Every walk emits a reference as it is, and `containsSensitive()` answers false
for one. It carries no secret material, resolving it needs credentials of the
reader's own, and redacting it would make a reference-passing system
undebuggable for no gain.

## API

See the [main README](../../README.md) for full API documentation.

## License

MIT
