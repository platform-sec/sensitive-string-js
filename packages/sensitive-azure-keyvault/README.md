# @platform-sec/sensitive-string-azure-keyvault

Azure Key Vault as a `SecretSource`: every value arrives as a `SensitiveString`, the vault URL stays
off the label, and `properties.expiresOn` becomes a deadline bound to the value.

Key Vault is the one source in this row that carries a real deadline an operator set, so it is the
one where a wrapped value enforces something the raw string never could.

## Installation

```bash
pnpm add @platform-sec/sensitive-string-azure-keyvault
```

## Requirements

- Node.js 22.12+
- `@platform-sec/sensitive-string-core` (peer dependency)
- `@platform-sec/sensitive-string-secrets` (peer dependency)
- `@azure/keyvault-secrets` (peer dependency, **types only**)

Core and the shared layer are peers because both are identified by `instanceof`, and two copies in
`node_modules` make every one of those checks miss.

`@azure/keyvault-secrets` is a types-only peer. Nothing here imports a value from it: the client is
injected and `getSecret` is an ordinary method, so the built output contains no vendor import at
all. The SDK's own types are still what the fixtures are typed as, so a field this package reads has
to exist on the real response.

## Usage

```typescript
import { SecretClient } from '@azure/keyvault-secrets';
import { DefaultAzureCredential } from '@azure/identity';
import { AzureSecretSource } from '@platform-sec/sensitive-string-azure-keyvault';

const azure = new AzureSecretSource({
  client: new SecretClient(vaultUrl, new DefaultAzureCredential()),
  onLoad: (event) => audit.info('secret.load', event),
});

const apiKey = await azure.get('payments-api-key');

apiKey.value.ttlRemaining();   // from properties.expiresOn
apiKey.ref.version;            // the concrete version, never an alias
```

Credential construction stays with the application, which is why the client is injected.

### The one place this is stricter than the provider

```typescript
new AzureSecretSource({ client, honorExpiresOn: false });   // default is true
```

`properties.expiresOn` maps directly to the instance's `expiresAt`, which makes Key Vault the
cleanest deadline mapping in this row. It is also the only place in the row where this library
refuses a value the provider might still serve: a secret past its `expiresOn` is wrapped with a
deadline already behind it, so it constructs and refuses to reveal.

The default is on. An operator who set an expiry meant it, and a deadline that nothing enforces is
worth enforcing. Surprising a caller with it is worse than not enforcing it silently, so the opt-out
is one option away and this paragraph is why it exists.

### `notBefore`

```typescript
new AzureSecretSource({ client, honorNotBefore: false });   // default is true
```

Core has no not-yet-valid state, and a value that is inactive now and active later cannot be
expressed. The options were to throw, to report the secret as absent, or to hand back a value that
is not supposed to work yet. This throws `SecretNotYetValidError` naming the date: a future-dated
secret in production is a deployment ordering mistake and should be loud. Adding a real
not-yet-valid state to core is a larger change and not something to smuggle in through a provider.

### `contentType` is surfaced and never acted on

`application/json` on a secret is the convention that says `getJson` is the right read. This package
puts it on `metadata` and does not switch behaviour on it. Behaviour that changes because a
server-side field changed is behaviour that breaks a caller when somebody edits a field in the
portal; the Kubernetes integration makes the same call for Secret `type`, for the same reason.

### Secret identifiers

```typescript
await azure.get('payments-api-key');
await azure.get('https://contoso-prod.vault.azure.net/secrets/payments-api-key');
await azure.get('https://contoso-prod.vault.azure.net/secrets/payments-api-key/abc123');
```

All three work. The vault URL is the tenant's DNS name, so it is stripped from the label and put on
`metadata`; a version on the identifier is honoured rather than dropped, because dropping it would
serve the current secret to a caller who pinned one with nothing saying so. An explicit
`version` on the ref wins over one on the identifier.

### Absence versus failure

`getOptional` returns null for a 404, and for a successful response carrying no `value`. The second
is a real state rather than an impossible one, so it maps to an absence rather than to a non-null
assertion waiting to throw. Everything else keeps throwing: a 403 is an authorization failure and
must not arrive as a missing secret. A disabled secret makes `getSecret` throw, which is the
provider's decision and is passed through unchanged.

## Measured behaviour

| Question | Answer | Verified on |
|---|---|---|
| Does Key Vault refuse to serve a secret past `properties.expiresOn`? | **Not verified.** Needs a live vault | not applicable |
| Does an absent secret answer 404? | Assumed from the REST contract; the check also accepts `code: 'SecretNotFound'` | not applicable |

The design holds either way for the first row: where the service does not enforce the date, this
package does, and `honorExpiresOn: false` is the switch for a deployment that disagrees. A row
without a version is a row nobody has checked, and these two are honestly marked. The wire shape
itself is pinned by the SDK's TypeScript types rather than by prose.

## What this does not protect against

- **The SDK's own response copy.** `KeyVaultSecret` holds the raw secret before this package sees
  it. What this package promises is that the object does not travel any further.
- **The decoded payload copy.** `getJson` and `getAll` materialize the payload as plain strings
  before anything is wrapped.
- **An SDK error's own text.** A `RestError` propagates unchanged. Azure's error text describes the
  request and the policy rather than the value.
- **Tags.** They are operator-chosen strings and reach the load hook as `tag.<name>`. A tag called
  `password` is surfaced exactly as written: it is metadata somebody put on the resource, not part
  of the secret's value.
- **Memory dumps and heap persistence before GC**, which is the library-wide limitation.

## License

MIT
