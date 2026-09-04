# @platform-sec/sensitive-string-gcp-secrets

GCP Secret Manager as a `SecretSource`: every value arrives as a `SensitiveString`, the project
number stays off the label, and `payload.dataCrc32c` is verified before anything is wrapped.

This is the provider where the rule about resolved versions earns itself. `latest` is an alias the
server resolves, two reads of it a second apart can legitimately return different versions, and an
audit trail that records `latest` for both cannot tell them apart.

## Installation

```bash
pnpm add @platform-sec/sensitive-string-gcp-secrets
```

## Requirements

- Node.js 22.12+
- `@platform-sec/sensitive-string-core` (peer dependency)
- `@platform-sec/sensitive-string-secrets` (peer dependency)
- `@google-cloud/secret-manager` (peer dependency, **types only**)

The SDK is a types-only peer: the client is injected, `accessSecretVersion` is an ordinary method,
and nothing here imports a value from it. That matters more for this provider than for the others,
because gax carries a large dependency tree that an application configuring its own client already
has.

This package has no third-party runtime dependencies, CRC32C included.

## Usage

```typescript
import { SecretManagerServiceClient } from '@google-cloud/secret-manager';
import { GcpSecretSource } from '@platform-sec/sensitive-string-gcp-secrets';

const gcp = new GcpSecretSource({
  client: new SecretManagerServiceClient(),
  project: 'my-project',
  onLoad: (event) => audit.info('secret.load', event),
});

const key = await gcp.get('stripe-api-key');   // resolves 'latest'

key.ref.version;   // '7', never 'latest'
key.value;         // SensitiveString<credential:stripe-api-key>
```

A fully qualified `projects/<project>/secrets/<name>[/versions/<n>]` path works too, and needs no
configured project.

### Integrity

Google ships an integrity check with the secret and a check nobody runs is decoration.
`payload.dataCrc32c` is verified against the bytes **before** anything is wrapped, which is what
keeps the verification from being a reveal: at that point the value is a buffer this package is
decoding rather than a `SensitiveString` somebody would have to reveal to check. A mismatch throws
with the secret name and the version, and never the content.

```typescript
new GcpSecretSource({ client, project, requireChecksum: true });   // default is false
```

A present checksum is always verified. `requireChecksum` decides what an **absent** one means. It
defaults to off because whether the API supplies one on every path is not something this package has
measured, and refusing a load over a field that may legitimately be absent is the wrong way to find
out. A deployment that has checked its own paths can turn it on and get an unconditional guarantee.

The `int64` arrives as a number, a `Long`, or a decimal string depending on how gax decoded it. All
three are handled, because a comparison that only handled one would silently skip verification for
the other two, which is the worst outcome available: the check appears to run and never fails.

### Expiry, and the field that looks like one

```typescript
new GcpSecretSource({ client, project, readExpiry: true });   // default is false
```

`expireTime` on the secret resource is a real deletion time: the secret is gone after it, so a value
derived from it stops working. It maps to `expiresAt`. Reading it costs a `getSecret` call on top of
`accessSecretVersion`, which is why it is opt-in, and a `getSecret` failure loses the metadata rather
than the secret, since `secretmanager.secrets.get` is a separate permission from `versions.access`.

The `rotation` block is not a deadline. It schedules a Pub/Sub notification and neither creates a
version nor invalidates the current one, so a value derived from it would expire while still being
the correct live credential. It is recorded on `metadata` and never bound.

### Labels

The label is the secret's short name. A fully qualified resource name is
`projects/<number>/secrets/<id>/...`, and the project number identifies the organization's billing
account as effectively as an AWS account id does, so it goes on `ResolvedSecretRef.metadata`.

### Absence versus failure

`getOptional` returns null for gRPC status 5, `NOT_FOUND`, and nothing else. `PERMISSION_DENIED`
(7) and `FAILED_PRECONDITION` (9), which is what a `DISABLED` or `DESTROYED` version produces, both
keep throwing, so a broken policy or a destroyed version never arrives as a missing secret.

## Measured behaviour

| Question | Answer | Verified on |
|---|---|---|
| Does CRC32C here match the standard? | Yes. `crc32c("123456789") === 0xE3069283`, the check vector every implementation is tested against | this package's suite |
| Does `accessSecretVersion` return `dataCrc32c` on every path? | **Not verified.** Needs a live project, which is why `requireChecksum` defaults to off | not applicable |

The wire shape is pinned by the SDK's generated proto interfaces: the fixtures are typed as
`IAccessSecretVersionResponse` and `ISecret`, so a field this package reads has to exist on the real
message.

## What this does not protect against

- **The decoded payload copy.** The payload arrives as bytes and decoding to a string produces a
  copy this package cannot clear, the same limitation AWS `SecretBinary` and OCI bundles have.
- **The SDK's own response copy.** The gax response holds the bytes before this package sees them.
  What this package promises is that the object does not travel any further.
- **A gax error's own text.** It propagates unchanged; its `code` is what callers switch on.
- **Memory dumps and heap persistence before GC**, which is the library-wide limitation.

## License

MIT
