# @platform-sec/sensitive-string-secrets

The shared layer under the secrets manager integrations: one `SecretSource` interface, one
classification rule, one decode guard, one instance cache, one write guard, so several provider
packages do not grow several label rules that disagree.

You do not normally install this directly. Install the package for your store, which depends on this
one and supplies the client and the one API call.

## What actually goes wrong

A secret enters a Node process from a secrets manager as a plain `string` on a response object, and
stays a plain string for the rest of its life:

```typescript
const res = await client.send(new GetSecretValueCommand({ SecretId: 'prod/db' }));
const { username, password } = JSON.parse(res.SecretString!);
await pool.connect({ user: username, password });
```

Four things have gone wrong by the last line and none of them throws.

`res` holds the raw secret and is an ordinary object, so it reaches an error tracker if the next line
throws while it is in scope, and it reaches a log line the first time somebody debugs this function.
`username` and `password` are plain strings with no class, no label, and no audit trail. If the
secret is not valid JSON, the `SyntaxError` carries part of it in its message. And nothing recorded
that a secret was loaded, from where, or at which version.

### The parse that leaks

`JSON.parse` puts its input into the `SyntaxError` message. Measured on Node 22.15.0:

| Input | Message |
|---|---|
| 20 characters or fewer, not JSON | `Unexpected token 'S', "SSSSSSSSSSSSSSSSSSSS" is not valid JSON` |
| More than 20 characters, not JSON | `Unexpected token 'S', "SSSSSSSSSS"... is not valid JSON` |
| Well-formed prefix, truncated | `Expected ',' or '}' after property value in JSON at position 56` |

An input of 20 characters or fewer is echoed whole. The truncated-JSON case reports only a position
and is safe, which is what makes this easy to miss in review: the failure mode that leaks is the one
where the secret is not JSON at all, which is exactly what happens when somebody calls `getJson` on a
secret holding a bare API key. A 20-character key is a common length, and it goes into a
`SyntaxError` that goes straight to the error tracker.

Every decoder here parses inside a guard that discards the original error and never chains it through
`cause`. Chaining would satisfy the usual advice about preserving errors and would undo the entire
fix, because every error reporter serializes the cause chain.

## Installation

```bash
pnpm add @platform-sec/sensitive-string-secrets
```

## Requirements

- Node.js 22.12+
- `@platform-sec/sensitive-string-core` (peer dependency)

Core is a peer dependency rather than a regular one. `redactInStructure`, `containsSensitive`,
`wrapSensitiveByPath` and `deserialize` all check `instanceof`, and two copies of core in
`node_modules` make every one of those checks miss.

This package has no third-party runtime dependencies.

## The interface

```typescript
interface SecretSource {
  get(ref, options?): Promise<SecretRecord>;             // one value
  getOptional(ref, options?): Promise<SecretRecord | null>;
  getJson(ref, options): Promise<JsonSecretRecord>;      // declared fields, typed result
  getAll(ref, options): Promise<MultiSecretRecord>;      // discovered keys, a pair of maps
  refresh(ref): void;
}
```

Three rules turn that from a type into a guarantee.

**The provider response object never leaves the provider package.** A provider destructures the one
field it needs, wraps it, and returns a record. The response is not stored on the record, not
attached to an error, and not passed to a hook. There is no `raw` escape hatch, because that is the
one property here that cannot be added later without a breaking change.

**`ResolvedSecretRef.version` is the version the provider served**, not the alias that was requested.
Every store here accepts an alias that resolves to something concrete, and an audit trail that
records the alias records nothing.

**`klass` defaults to `credential`**, the more restrictive of the two classes. It is the one option
that can only loosen, so it is explicit at every call site, and the multi-value reads take a class
per field rather than defaulting a whole payload down.

## Multi-value secrets

One fetch yielding many named values is the majority case. `getJson` and `getAll` are the same
decode, classify, wrap pipeline with two surfaces, split on whether the key set is known when the
code is written.

```typescript
const db = await source.getJson('prod/db', {
  fields: { username: 'sensitive', password: 'credential', host: 'plain', port: 'plain' },
});

db.fields.password;   // SensitiveString<credential:prod/db#password>
db.fields.port;       // 5432, untouched
db.extra.fields;      // keys the payload carried that `fields` did not declare
```

Classification is `fields`, then `rules` in order, then `fallback`. Patterns run on key names, never
on values.

`fields` means different things on the two calls, and the difference is deliberate. On `getJson` a
declared field is one the payload must have, because the result is typed and a missing one would
arrive as an `undefined` typed as a `SensitiveString`. On `getAll` it is a classification of the
keys that turn up: a spec written once for a store has to survive the payloads that legitimately
omit part of it. The Kubernetes type specs are the case that proves it, since the
service-account-token spec names a key only some clusters mount and the pull secret spec names both
the expanded and the unexpanded shape, of which exactly one is ever present.

Nested payloads are addressed by dot path (`db.password`), and so is a flat key that happens to
contain a dot (`tls.key`, `.dockerconfigjson`). Wrapping happens at the leaf rather than by parsing
the path, so a Kubernetes-shaped payload is handled without the caller escaping anything. A payload
where both forms address the same name, `{ "a.b": x }` alongside `{ a: { b: y } }`, is refused
rather than silently classifying one of them under the other's rule.

### `getAll` requires an explicit fallback

```typescript
// A Kubernetes Secret or a Vault KV path: everything in it is secret by construction.
await source.getAll('kv/prod/db', { fallback: 'credential' });

// A config store that mixes secrets with ordinary configuration.
await source.getAll('app-config', {
  rules: [{ pattern: /KEY|TOKEN|SECRET|PASSWORD/i, klass: 'credential' }],
  fallback: 'plain',
});
```

There is no default because fail-closed is wrong for half of the stores that need `getAll`, and it
fails in a way that does not look like a security control. Wrapping `LOG_LEVEL` as a credential makes
`config.LOG_LEVEL === 'debug'` permanently false and `if (config.FEATURE_X)` permanently true,
because an instance is an object and objects are truthy. The application misbehaves, the cause looks
like a configuration bug, and nobody suspects the wrapper. Fail-open is equally wrong for a store
where everything is secret. Only the caller knows which kind of store this is.

`getAll` returns two maps rather than one map of a union type, so a caller iterating `fields` cannot
find a raw string in it. A single map typed `SensitiveString | string` would put that check on every
call site, and the call sites that skip it are exactly the ones that log the map.

## Labels

A label is not private. Core's inspect hook renders

```
SensitiveString<credential:prod/db#password> { [REDACTED:credential] }
```

so a label appears in every log line and every error tracker event that touches the value. The rule
is that a label is the logical path within the store, and everything identifying the account,
project, tenancy, subscription, cluster or host is stripped and put on `ResolvedSecretRef.metadata`
instead, which reaches the load hook and never reaches redacted output.

`describeLabelDisclosure(label)` reports which disclosure rules a label trips. It is a test helper
rather than a runtime guard: nothing stops a caller passing `label` explicitly, and nothing can,
since a label is a free string.

## Load events

Loading a secret creates a `SensitiveString`. It does not call `reveal()`, so `auditReveal` does not
fire, which is correct and is also a gap: loading a production database credential is a
security-relevant event.

```typescript
const source = new SomeSecretSource({
  onLoad: (event) => audit.info('secret.load', event),
});
```

Deliberately not `auditReveal`. Routing loads through the reveal hook would have been less code and
would make the audit trail lie: a sink counting reveals to decide whether a credential is over-used
would count every process restart. Errors thrown by `onLoad` propagate rather than being swallowed,
because a load hook that fails silently is an audit gap.

## Caching

The cache holds `SensitiveString` instances, never raw strings, which is what makes a cache in this
library safe to hold and safe to inspect.

- The key includes the requested version, so `latest` and a pinned version are different entries.
- Entry lifetime is the shorter of the configured TTL and the shortest remaining lifetime of what it
  holds. A cache must not outlive what it holds.
- One provider call serves N concurrent callers for one key, and produces one instance.
- Failures are not cached, and a provider's error object is never retained past the throw.
- `staleOnError` is off by default. Defaulting it on would make a provider outage invisible; when it
  fires, the load event says `cached: true`.

Retry and backoff live nowhere in this package. Clients are injected, and an application that has
configured its SDK's retry strategy should not have a second one wrapped around it. The single-flight
above is concurrency control, not retry.

## Writing

```typescript
import { put, putJson } from '@platform-sec/sensitive-string-secrets/write';

await putJson(vault, 'kv/prod/db', { password: newPassword }, {
  context: { name: 'rotate-db-credential', reason: 'scheduled rotation' },
});
```

A write is a transmit, and it is the one place in this category where a redaction marker gets
persisted rather than merely sent. A `SensitiveString` handed to a provider's write call stringifies
to `[REDACTED:credential]` and is stored under that value: the write succeeds, the provider reports
success, and every consumer that reads the secret afterwards receives the literal marker as its
database password. The first sign is an authentication failure in a different service.

So the write path:

1. Reveals an instance under the caller's context, which puts the write in the reveal audit trail.
2. Requires a `RevealContext`. Writing a secret is not something to do under an ambient context that
   happens to be lying around.
3. Scans the outgoing bytes for `[REDACTED:` and refuses if found, before any transport call. This
   catches the case the guard exists for: a payload built with template interpolation, where the
   interpolation already stringified an instance and no reveal was ever attempted.
4. Reads the value back and compares with `equals()`, which is constant-time for a credential. On by
   default: it costs one extra call on an operation that happens on a rotation schedule, and it turns
   a silently corrupted secret into a failed rotation.

The read-back reads the *current* version, not the one the write reported. Pinning would seem more
precise and is weaker: it passes even when a later version immediately supersedes yours, and the
guarantee worth having is that a reader now gets what this process sent. It also works against a
store that overwrites in place and has no version to pin. A concurrent rotation makes it fail, which
is a true report rather than a false alarm.

It lives behind its own entry point, so an application that only reads never loads it and a build
that never imports it can be verified to contain no write call.

## Watching a file

```typescript
const watcher = watchFile(path, read, {
  debounceMs: 100,
  onChange: (next, previous) => pool.reconfigure(next),
});
```

A change produces a new value; instances are immutable and a watcher that mutated one would defeat
the gate every read goes through. Reads are debounced, because an atomic rename and a kubelet's
write-then-swap both produce more than one filesystem event for one logical change. A partially
written file is a decode failure rather than a value, so the previous value stays in service while
the retry backoff runs. `fs.watch` is unreliable on some container filesystems, so polling is
available and is the right choice for a bind mount.

## What this does not protect against

- **The provider's own response copy.** A vendor SDK holds the raw secret on a response object before
  this package sees it, and some SDKs retain response bodies on the client. What this package can
  promise is that the object does not travel any further.
- **The decoded payload copy.** Every decoder materializes the payload as plain strings before
  anything is wrapped, and that copy exists until collection. JavaScript has no primitive that would
  let it do better.
- **Instances already handed out.** `refresh()` evicts the cache; it cannot reach the values a caller
  already holds. After a rotation, an in-flight request holding the old credential continues with it
  until the far side stops accepting it. Vault is the exception, because it has server-side
  revocation.
- **Memory dumps and heap persistence before GC**, which is the library-wide limitation.
- **A caller's own `label`.** The rule is enforced by the provider defaults and by tests, not at
  runtime.

## Writing a provider package

```typescript
class MySecretSource extends BaseSecretSource {
  protected readonly sourceName = 'my-store';

  protected async fetchSecret(ref: SecretRef): Promise<ProviderResult | null> {
    const response = await this.client.get(ref.path);   // never leaves this method

    if (response.status === 404) {
      return null;      // absence. An authorization failure must throw instead.
    }

    return {
      payload: { kind: 'string', value: response.value },
      ref: { path: ref.path, version: response.versionId, metadata: { region: response.region } },
      lifetime: { expiresAt: response.expiresOn },
    };
  }
}
```

Everything else is here. The division is one test: if implementing it requires knowing the provider's
wire shape, it belongs in the provider package.

**Take the vendor SDK as a types-only peer where you can.** Five of the six SDK-backed providers in
this row inject a client and call ordinary methods on it, so nothing imports a value from the SDK:
the built output carries no vendor import, an application pays nothing for the dependency being
installed, and the fixtures are still typed as the vendor's own response types, which is what makes
a field the package reads have to exist on the real response. The exception is AWS, whose v3 client
dispatches through command objects that have to be constructed. A hand-written structural interface
would avoid the dependency too and would let a fixture drift from the API, which is the thing the
types are there to prevent.

Provider suites import the sweep harness from `@platform-sec/sensitive-string-secrets/testing`, which
drives every entry point with a canary and asserts it appears in no message, no stack, no
`JSON.stringify`, and no `cause` chain at any depth.

## License

MIT
