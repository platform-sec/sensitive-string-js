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
- **Environment Restrictions**: `restrictions` says where a value may be read, checked against a
  process-global `setEnvironmentInfo()` declaration on every access, carried by derived values and
  across the wire
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
configuration, the revocation lists and the environment declaration are shared
across duplicate installed copies of core through `Symbol.for()`. Policy
registration is mutable process-global configuration: it protects against
accidental misuse and misconfiguration, but code already executing in the
process can replace a policy and must be trusted. The same is true of
`setDevMode()`, which is why enabling it under `NODE_ENV=production` prints a
warning, and of `revokeByLabel()`, `revokeByPattern()` and
`pruneRevocations()`, which defend against a stale secret rather than against a
hostile caller.

`setEnvironmentInfo()` is the same kind of state and carries the same caveat.
`lockEnvironmentInfo()` freezes it for the rest of the process, which is what
makes an environment restriction worth anything after startup, and
`resetEnvironmentInfo()` clears both the environment and the lock for test
isolation. That reset is the honest statement of what the lock is worth: the
threat is a misconfigured deploy, not code already running in the process. Each
singleton is per isolate, so a worker thread declares its own environment or
reports `unknown` with no region, which refuses every allowlist.

## Worker threads and child processes

`AsyncLocalStorage` is per isolate and `structuredClone` strips an instance to
`{ klass, label }`, so neither a value nor its context crosses a worker boundary
on its own. `toWorkerPayload()` builds a payload in the wire format with the
context's `name`, `reason` and `tags`, and `withWorkerPayload()` rebuilds the
instances on the far side, installs that side's own audit hook, and deletes the
raw values from the payload object so `workerData` stops holding plaintext. The
[main README](../../README.md#worker-threads-and-child-processes) has the full
account, including the four things the boundary still does not close.

The sharpest of those four: a value that crosses leaves the parent's revocation
reach entirely. An instance `revoke()`, `revokeByLabel()` and
`revokeByPattern()` in the parent, and a `revocationRegistry` the value was
built with, all stop at the boundary, and the receiving side cannot bind a
registry to a rebuilt value. A worker that must honour revocation keeps its own
label list.

## Environment restrictions

`restrictions` on the constructor options says where a value may be read: an
environment, a region with an optional trailing `*`, a datacenter, or a
predicate handed the frozen `EnvironmentInfo`. The check lives in the same
raw-value gate expiry, revocation and reveal limits do, so every operation that
reaches the value refuses together, `renew()` with them, and redaction keeps
working. Derived values
carry the restriction, and declarative restrictions cross `serialize()`; a
custom function has no wire form, so a value carrying one refuses to serialize
rather than arriving half enforced. The [main
README](../../README.md#environment-restrictions) has the field table, the rule
for a field the environment does not state, and what the process-global
environment does and does not protect.

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

## The audit hook

`RevealContext.auditReveal` is called with three arguments: the value, what the operation was, and
the context it ran under.

```typescript
await withRevealContext(
  {
    name: 'password-reset',
    tags: { requestId: 'r-42' },
    auditReveal: (value, details, context) => {
      logger.info('accessed', {
        klass: value.klass,
        operation: details.operation,
        ...context.tags,
      });
    },
  },
  async () => { /* ... */ }
);
```

The context is the one passed to the call, or the ambient one when the call passed none, which is
the same context the policy's `checkRevealAllowed` was asked to authorize. It is not always the
context the hook was installed on: an integration that nests a child through `createChildContext()`
to tag a reveal with a table, a column or an argument path is audited under the child, and that is
what arrives here. `getCurrentRevealContext()` inside the hook answers a different question, namely
where the caller stood.

It carries `name`, `reason` and `tags`, and no `auditReveal`: the sink reading it is that hook. It
is the live context object rather than a copy, so comparing it by identity works and an audited
reveal allocates nothing, and a sink copies out what it means to keep rather than writing to `tags`,
which every reveal under the context shares.

A hook written with two parameters stays valid; the third is there to be ignored.

## API

See the [main README](../../README.md) for full API documentation.

## License

MIT
