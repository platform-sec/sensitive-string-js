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

## References: send a pointer, not a value

`serialize()` puts the raw value on the wire and asks the transport for confidentiality. That is a
fair deal for mTLS between two services in one trust domain, and a poor one everywhere the payload
comes to rest: a job in SQS, Kafka, a `jobs` table or a webhook retry buffer sits there in plaintext
for as long as the retention allows, and a transport that terminates at a mesh sidecar, an API
gateway or a logging proxy is decrypted somewhere in the middle.

Where both sides can reach the same store, send a pointer instead. It is the only option here under
which the value never leaves the process that fetched it.

```typescript
// Sender
import { toReference } from '@platform-sec/sensitive-string-secrets';

const record = await vault.get('kv/payments/stripe');
await queue.send({ job: 'charge', key: toReference(record, { store: 'vault-prod' }) });

// Receiver
import { createReferenceResolver } from '@platform-sec/sensitive-string-secrets';

const resolver = createReferenceResolver({
  store: 'vault-prod',
  source: vault,
  allow: [
    { path: 'kv/payments/*', klass: 'credential' },
    { path: 'kv/analytics/db', fields: { password: 'credential', username: 'sensitive' } },
  ],
});

const key = await resolver.resolve(job.key, { context: { name: 'charge-worker' } });
```

A reference is `{ __sensitiveRef: true, v, store, path, version?, field?, klass?, label? }`, and it
carries no secret material at any version of the format.

### Minting takes the record, not the value

There is no `token.toReference()`, and that is not an oversight. An instance does not know which
store it came from, because the label rule strips everything identifying the account, project,
tenancy or host: `prod/db` is what survives from an ARN, and the same logical path usually exists in
staging and in production. And a derived instance inherits its sources' state, which is right for
constraints and wrong for provenance in the most direct way available, since
`token.substring(0, 4).toReference()` would mint a pointer to the whole credential and the receiver
would have no way to tell.

So minting takes the `ref` a read returned, which contains no secret material by construction. It
performs no I/O, reads no raw value, and takes no `RevealContext`, because it is not a reveal:
recording it as one would make a sink that counts reveals to decide whether a credential is
over-used count every message that merely mentions it. That is the call the load path already made.

`fieldReference(record, 'password', { store })` points at one field of a multi-value secret, by the
same dot path `getJson` declares.

### Resolving is an authorization decision

`resolve()` runs in the receiver, with the receiver's credentials, against a path a sender chose,
which is the shape of every confused deputy ever written. Unconstrained, it lets anything that can
enqueue a job read any secret the receiver's role can read, using the receiver as the oracle. So a
resolver is constructed with an allowlist, there is no permissive default, and an empty allowlist is
legal and resolves nothing.

The rules, in the order they run, each refusing before the store is touched:

| # | Rule | `reason` |
|---|---|---|
| 1 | A `RevealContext` was supplied | `no-context` |
| 2 | It is a reference, and carries every member the format requires | `shape` |
| 3 | The format version is one this build reads | `format` |
| 4 | `ref.store` equals the resolver's store, compared exactly | `store` |
| 5 | The path has no `.` or `..` segment, no empty segment, no leading slash, no control character, and no `%`, `\`, `?` or `#` | `path` |
| 6 | The version matches `[A-Za-z0-9._:-]{1,128}` | `version` |
| 7 | Some allowlist entry covers the path | `path` |
| 8 | A covering entry resolves this kind of reference, and declares this field | `field` |

The context is checked first because it is the caller's own precondition: a receiver that forgot it
has a mistake of its own, and reporting that as a fault in what arrived would point whoever reads
the log at the wrong party. Rule 2 also refuses a reference naming a sensitivity class this process
has no policy for, since a class it cannot act on is not one to silently ignore, and the field is
there to tighten the receiver's rule.

Then the class: the most restrictive among every entry covering the reference, and then the more
restrictive of that and the reference's own. A class on the wire may tighten what the receiver does
and may never loosen it, because a receiver that took `klass` from the wire would let a sender ask
it to treat a credential as `sensitive`, which turns off constant-time comparison, lifts the refusal
on partial queries, and lets `mask()` disclose a prefix. The label is derived here too, under the
label rule; the one on the wire is advisory and unread.

Only then does the resolver call `get` or `getJson`, which is where caching, the load event,
lifetime binding and the decode guard already live. Resolving a reference is a load, so it emits the
load event a direct `get` for the same ref would emit, and it fires no reveal hook, because nothing
in it reads a raw value.

Six things about that list are worth stating outright.

**A path is refused rather than normalized.** Normalizing would mean this library and the provider
each holding an opinion about what `kv/a/../b` means, and a disagreement between two normalizers is
how a path that fails the allowlist reaches the store anyway.

**A path may not carry a character a URL parser reads as structure**, which is a stronger rule than
"no `..` segment" and the reason is measured rather than theoretical. A provider builds its request
as `new URL(base + path)`, and on Node 22.15.0 the WHATWG parser applies its double-dot rule to the
percent-decoded segment and treats a backslash as a separator:

| Sent | Requested |
|---|---|
| `kv/payments/%2e%2e/%2e%2e/auth/token/lookup-self` | `/v1/auth/token/lookup-self` |
| `kv/payments/..\..\auth/token/lookup-self` | `/v1/auth/token/lookup-self` |
| `kv/payments/stripe?list=true` | `/v1/kv/payments/stripe?list=true` |

The first two are the escape the allowlist exists to prevent, reached from a path that a check over
`/`-split segments calls well formed, and the second one contains no percent sign at all. The third
turns a read of a permitted secret into a different request. No store this layer supports allows one
of these characters in a secret name, and a caller sends the logical path rather than a pre-encoded
one, so nothing legitimate is refused. The suite pins the parser behaviour next to the refusals.

**A version is checked, not escaped.** It is attacker-chosen exactly as a path is, and providers put
it into a URL path or a query string.

**Overlapping entries take the strictest class, not the first.** A subtree rule and a rule for one
path under it are how an operator writes this, and taking the first would make
`[{ path: 'kv/*', klass: 'sensitive' }, { path: 'kv/payments/stripe', klass: 'credential' }]`
resolve the Stripe key as `sensitive`, which is a security control whose answer depends on the order
two lines were written in. An entry may make the class stricter than another covering the same path
and never looser; an operator who wants a narrow exception to be looser narrows the broad rule
instead, where a reviewer can see it.

**Patterns are a trailing `*` on a segment boundary and nothing else.** `kv/payments/*` covers the
subtree below `kv/payments/` and does not match `kv/paymentsx/stripe`. There is no regex, because a
regular expression in a security check against attacker-chosen input is a backtracking bug waiting
to be found. A malformed pattern throws at construction rather than silently matching nothing.

**An allowlist is a scope, not an authorization decision.** It says which secrets this worker will
ever hand out. It does not say whether the particular sender was entitled to this particular secret.
A system where different callers deserve different secrets constructs a resolver per scope, from the
caller's identity.

The allowlist is copied entry by entry and frozen at construction, so a caller that keeps a
reference to the array or to an entry cannot widen a live resolver afterwards. Everything else that
is the receiver's own configuration also fails there rather than at the first reference: a malformed
pattern, an entry with neither or both of `klass` and `fields`, a class with no registered policy,
and a `fields` entry against a source with no `getJson` to resolve it through.

A refusal is a `ReferenceRefusedError` carrying `reason`. The path is on `error.path` and never in
`error.message`: `ref.path` is text a sender chose, a refusal is the case where the sender is least
likely to be one this receiver trusts, and a message that interpolated it would put attacker-chosen
text into the receiver's own logs. What is on `error.path` after a refusal is what the sender asked
for, which may name no secret that exists anywhere, so a handler that logs it is logging a request
rather than an identifier of anything.

### Versions, and what a pin costs

`pinVersion` defaults to true, so a reference resolves to the version the sender read. A reference
stands in for a value, and a value does not change between the send and the receive; without the
pin, a job that sits in a queue across a rotation resolves to a different credential than the one
the sender was holding, and the failure surfaces as an authentication error in whatever the job
talks to, one hop away from the cause.

The cost is the other half of the same fact: a pinned reference outlives the rotation that was meant
to retire the old version. Keeping queue retention shorter than the rotation interval is the honest
fix, and it is a property of the system rather than of this library. `pinVersion: false` is the
other one, for a long-lived credential where "current" is genuinely what the receiver wants.

A provider that reports no version says so with `'unknown'`, which is a sentinel rather than a
version, and is never pinned.

### A reference is not redacted

Every walk in `core` emits a reference as it is, and `containsSensitive()` answers false for one.
That is a decision rather than an omission: it carries no secret material, resolving it needs
credentials a reader of the log would have to hold independently, and redacting it would make a
reference-passing system undebuggable for no gain. Being able to see which secret a job refers to is
the point. The disclosure it makes, that this request touched `kv/payments/stripe`, is the one the
label already makes in every line that logs the value itself.

An error tracker payload is a stricter walk than a log line. `sensitive-scrub` also denies by key
name, so a reference sent under a key called `token` or `secret` is replaced there like anything
else under that name.

### Where this does not reach

It applies to values that came out of a store, which is where credentials, API keys and connection
secrets are, and not to the other half of what this library wraps. A card number arriving in a
webhook, an email address parsed from a request body, or a session token minted in the process has
no path, and giving it one means writing it into a store first, which is a larger decision than
choosing a wire format. A derived value has no reference either, per the rule above, and that is the
case a caller hits by accident: wrap a connection string, split it, and there is no reference to the
part.

Revocation is the real answer to a pinned reference to a retired version, and this does not
approximate it. What the reference pattern does get for free is the other direction: the receiver
fetches at resolve time, so a secret deleted at the store stops resolving everywhere.

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

A sweep that passes proves nothing unless it can fail, so it has been checked against deliberate
leaks rather than assumed to work. Putting the secret onto `ResolvedSecretRef.metadata` was caught in
both halves, the returned record and the load event. Restoring the `cause` chain that the decode
guard removes, which is the regression that guard exists to prevent, was caught through two
different provider packages, and the case that caught it was the 20-character payload that V8 echoes
whole. Do the same when adding a case: make it fail on purpose once, then fix it.

## License

MIT
