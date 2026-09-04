# @platform-sec/sensitive-string-infisical

Infisical as a `SecretSource`: every secret arrives as a `SensitiveString`, the token is itself a
`SensitiveString`, and a key that turns up twice is refused rather than resolved.

## Installation

```bash
pnpm add @platform-sec/sensitive-string-infisical
```

## Requirements

- Node.js 22.12+
- `@platform-sec/sensitive-string-core` (peer dependency)
- `@platform-sec/sensitive-string-secrets` (peer dependency)

There is no vendor SDK. The API surface this package needs is one endpoint over `fetch`, so
`@infisical/sdk` is not a dependency and this package has no third-party runtime dependencies at
all. The transport interface is exported for a caller who wants their own.

## Usage

```typescript
import { InfisicalSecretSource } from '@platform-sec/sensitive-string-infisical';

const infisical = new InfisicalSecretSource({
  token: infisicalToken,      // SensitiveString<'credential'>
  projectId: 'a1b2c3',
  environment: 'prod',
  endpoint: 'https://infisical.internal',   // omit for Infisical Cloud
  onLoad: (event) => audit.info('secret.load', event),
});

const config = await infisical.getAll('/backend', {
  rules: [{ pattern: /KEY|TOKEN|SECRET|PASSWORD|DSN/i, klass: 'credential' }],
  fallback: 'plain',
});

config.fields.get('STRIPE_SECRET_KEY');
config.plain.get('LOG_LEVEL');
```

The ref is what Infisical scopes a read by. With `environment` configured, the ref is the folder
alone; without it, `prod/backend` reads the `/backend` folder of the `prod` environment.

## The store this row argued about

A folder in an Infisical environment mixes secrets with ordinary configuration, the same shape
Doppler has, so the shared layer's required `fallback` applies for the same reason: fail-closed
breaks the application in a way that looks like a configuration bug, and fail-open leaves the API
keys unwrapped. Only the caller knows which keys are which.

## Duplicate keys

```typescript
new InfisicalSecretSource({ token, projectId, environment, includeImports: true });
```

Imports are off by default. An import is a second store's key set arriving under this one's path,
and a classification written for one folder has not seen the other, so turning it on is a decision
rather than a default.

Either way, a key that appears twice in the `secrets` array is **refused** rather than resolved.
Picking one of them would mean an application silently reads a value from a folder its
classification never described, and that is not a thing to do quietly.

## Labels and metadata

The label is `environment/path`. The project id is left off: it identifies the workspace the way an
AWS account id identifies an account, so it goes on `ResolvedSecretRef.metadata`, which reaches the
load hook and never reaches redacted output.

## No version

`ref.version` is `'unknown'`. The raw read reports a version per secret, not for the folder as a
whole, and the rule this row works to is that a provider which reports none says so rather than
inventing one.

## Absence versus failure

`getOptional` returns null for a 404 and nothing else. A 401 or 403 keeps throwing, so a broken
token never arrives as a missing folder.

## The token

It has to be a `SensitiveString<'credential'>`; a plain string is refused at construction. It is
revealed per request under this package's own reveal context, which is a child of whatever is
ambient, so an application's `auditReveal` still sees it.

## Measured behaviour

| Question | Answer | Verified on |
|---|---|---|
| What does the raw read return? | `{ secrets: [{ secretKey, secretValue, ... }], imports: [...] }` | Infisical API documentation |
| Does it report a version for the folder? | No | same |
| What does an absent folder answer? | 404 | same |

**Nothing in this table has been verified against a live Infisical instance.** The rule this row
works to is that a fixture written from a design document tests the document rather than the
provider, and this package's fixtures come from API documentation. That is a weaker footing than the
Vault, Kubernetes and SOPS packages, which each have a second tier running against a real server, and
it is the first thing to fix if this package is used in anger.

## What this does not protect against

- **The decoded payload copy.** The `secrets` array is parsed into plain strings before anything is
  wrapped, and that copy exists until collection.
- **Infisical's own error text.** `InfisicalRequestError` carries the API's `message`, which
  describes the token's scope and the path asked for rather than any value.
  `includeServerErrors: false` turns that off.
- **Secret references.** `expandSecretReferences` is on, so a value that references another secret
  arrives resolved. The referenced secret's own classification is not consulted, because the server
  resolved it before this package saw either.
- **Memory dumps and heap persistence before GC**, which is the library-wide limitation.

## License

MIT
