# @platform-sec/sensitive-string-vault

HashiCorp Vault and OpenBao as a `SecretSource`: every value arrives as a `SensitiveString`, the
provider response object never leaves this package, and a lease becomes a deadline bound to the
credential rather than metadata nothing enforces.

Vault goes first among the secrets managers because it is the only store in the category whose API
supplies everything the lifetime and revocation design needs: `lease_duration`, `renewable`,
server-side revocation, and response wrapping. The other providers are subsets of it.

## Installation

```bash
pnpm add @platform-sec/sensitive-string-vault
```

## Requirements

- Node.js 22.12+
- `@platform-sec/sensitive-string-core` (peer dependency)
- `@platform-sec/sensitive-string-secrets` (peer dependency)

Both are peers rather than regular dependencies. Core is a peer because `redactInStructure`,
`containsSensitive` and `wrapSensitiveByPath` all check `instanceof`, and two copies make every one
of those checks miss. The shared layer is a peer for the same reason: it exports error classes, and
two copies break `instanceof SecretPayloadError`.

There is no vendor SDK. The API surface this package needs is a handful of endpoints over `fetch`,
so the transport is built in and the interface is exported for a caller who wants their own with
retries, mTLS or a proxy already configured.

## Usage

```typescript
import { VaultSecretSource } from '@platform-sec/sensitive-string-vault';

const vault = new VaultSecretSource({
  endpoint: 'https://vault.internal:8200',
  token: vaultToken,                       // SensitiveString<'credential'>
  namespace: 'engineering',                // Vault Enterprise only
  mounts: [{ path: 'kv', kv: 2 }],
  onLoad: (event) => audit.info('secret.load', event),
});

const db = await vault.getJson('kv/prod/db', {
  fields: { username: 'sensitive', password: 'credential' },
});

db.fields.password;   // SensitiveString<credential:kv/prod/db#password>
```

### Dynamic secrets, where the lease is real

```typescript
const lease = await vault.dynamic('database/creds/app-readonly');

lease.fields.get('password');   // ttl taken from lease_duration
lease.leaseId;                  // a string, and not a secret
await lease.renew(1_800_000);   // milliseconds in, milliseconds out
await lease.revoke();
```

### Response wrapping

```typescript
const wrapped = await vault.getWrapped('kv/prod/db', 60);
// hand wrapped.token to the service that should read the secret

const secret = await vault.unwrap(wrapped.token, { fallback: 'credential' });
```

### Writing

```typescript
import { putJson } from '@platform-sec/sensitive-string-secrets/write';

await putJson(vault, 'kv/prod/db', { password: rotated }, {
  context: { name: 'rotate-db-credential', reason: 'scheduled rotation' },
});
```

A Vault KV path holds named fields, so `put` with a single value is refused rather than guessing a
field name. The marker refusal, the required context and the read-back verification are all in the
shared write guard.

## Configuration

| Option | What it does |
|---|---|
| `endpoint` | The API base. Ignored when `transport` is supplied. |
| `transport` | Your own transport, for retries, mTLS or a proxy. |
| `token` | The client token, as a `SensitiveString<'credential'>`. |
| `namespace` | Vault Enterprise namespace. Rejected under `flavor: 'openbao'`. |
| `flavor` | `'vault'` (default) or `'openbao'`. Required rather than detected. |
| `mounts` | Which mounts run KV v1 and which run KV v2. |
| `defaultKv` | The engine version for a mount that is not listed. Defaults to 2. |
| `cache` | `{ ttl, staleOnError }`, from the shared layer. |
| `onLoad` | One event per load. Carries no secret material. |
| `onAuthError` | Called when a token renewal fails. |
| `tokenRenewal` | `{ intervalMs, incrementMs }`. Off unless configured. |

### The KV engine version is configured, not guessed

KV v2 nests the payload at `data.data` with metadata at `data.metadata`, and KV v1 puts it at `data`.
Getting it wrong yields a payload whose fields are `data` and `metadata` rather than the ones you
declared, so the mount version is explicit and a mismatch produces a diagnostic naming the likely
cause instead of a confusing classification result.

A KV read reports `lease_duration: 0`, which means no lease rather than already expired. Nothing is
bound for a KV read; mapping zero to `ttl: 0` would produce a value that is expired on arrival,
because `ttl: 0` in core means exactly the opposite.

### The client token

`token` takes a `SensitiveString<'credential'>` and nothing else. Accepting a plain string as well
would be convenient and would mean the one value that unlocks every other one is the one value not
covered. It is revealed once per request, under a reveal context named by this package that inherits
whatever ambient context is active, so the reveal reaches your audit sink under the name
`vault-request` rather than disappearing.

A token from AppRole or Kubernetes auth has its own lease. `tokenRenewal` renews it on a timer, and a
renewal failure is surfaced through `onAuthError` rather than retried silently until the token dies.

## OpenBao

OpenBao is the Linux Foundation fork of Vault, taken from the codebase before the license change. For
everything this package does it is the same API, so it is a flavor rather than a second package: a
separate package would be a re-export under a different name and would double a test matrix that has
nothing different to test.

```typescript
const bao = new VaultSecretSource({
  flavor: 'openbao',
  endpoint: 'https://openbao.internal:8200',
  token: baoToken,
});
```

`flavor` is required rather than detected. Detection would mean a response from the server decides
how the client behaves, and what is being decided is which compatibility assumptions hold.

### Compatibility

Measured on Vault 1.21.4 Community Edition and OpenBao 2.6.2, both dev-mode containers.

| Area | Vault | OpenBao | What this package does | Verified against |
|---|---|---|---|---|
| Namespaces | Enterprise feature, `X-Vault-Namespace`. Community Edition ignores the header | Not present. The header turns a 200 into a 404 | `namespace` under `flavor: 'openbao'` throws at construction | Vault 1.21.4 CE, OpenBao 2.6.2 |
| Token header | `X-Vault-Token` | `X-Vault-Token`. `X-Bao-Token` is refused with 403 | sends `X-Vault-Token` for both | Vault 1.21.4 CE, OpenBao 2.6.2 |
| KV v2 read shape | `data.data` with `data.metadata.version` | identical | one parser for both | Vault 1.21.4 CE, OpenBao 2.6.2 |
| Response wrapping | `X-Vault-Wrap-TTL`, `wrap_info.token`, `sys/wrapping/unwrap` | identical | one code path for both | Vault 1.21.4 CE, OpenBao 2.6.2 |
| Version reporting | `sys/health` version string, 1.x series | `sys/health` version string, 2.x series | recorded on metadata, never used to switch behaviour | Vault 1.21.4 CE, OpenBao 2.6.2 |
| Enterprise-only backends | Some | None | out of scope either way | not applicable |

A row with no version is a row nobody has checked. A compatibility claim made once is a claim that
rots, so the table is also in code as `FLAVOR_DIVERGENCE`, and CI runs the suite against both servers
in a container matrix.

Two rows moved when they were measured, and both moved in a useful direction.

`X-Bao-Token` is not an accepted alias. OpenBao 2.6.2 answers it with 403, so `X-Vault-Token` is the
compatible header because it is the only header either server accepts.

The namespace row is the one with teeth, and the silent wrong-secret case is not OpenBao's. OpenBao
2.6.2 does not ignore `X-Vault-Namespace`: a read that answers 200 without it answers 404 with it, so
a caller notices. **Vault 1.21.4 Community Edition accepts the header, ignores it, and serves the
root namespace with a 200.** So a deployment that sets `namespace` against a Community Edition
server, believing it to be Enterprise, reads a different secret than it thinks and nothing says so.
This package cannot tell Community from Enterprise without letting a server response decide how the
client behaves, which is the thing the flavor flag exists to avoid, so the OpenBao case throws at
construction and the Vault Community case is this paragraph.

## Labels

A label is the logical path within the store: `kv/prod/db#password`, never
`https://vault.internal:8200/v1/kv/data/prod/db`. The endpoint carries an internal hostname and port,
and a label appears in every log line that touches the value.

A path that is a URL is refused rather than half-normalized, because silently stripping the endpoint
would also leave a request path that does not exist.

## What this does not protect against

- **Instances already handed out.** `refresh()` and a lease revocation evict the cache; they cannot
  reach the values a caller already holds. Vault's `sys/leases/revoke` is stronger than anything
  local, which is why the gap is smaller here than for stores without server-side revocation, but a
  local in-flight request holding the credential continues with it until Vault stops accepting it.
- **Single-use wrapping tokens.** A wrapping token is single-use server-side, and this package models
  it as a normal credential with the wrap TTL. The count is not enforced locally.
- **KV v1 versions.** KV v1 overwrites in place and has no versions, so a write reports
  `'unversioned'` rather than inventing a number that means nothing.
- **A response body reaching a log through your own transport.** This package consumes the response
  and returns only the decoded body plus a status, and no error it throws carries a body. A transport
  you supply is yours to keep quiet.
- **Memory dumps and heap persistence before GC**, which is the library-wide limitation.

A Vault API failure does carry Vault's own `errors` array, which describes policy and paths rather
than values. That is a deliberate exception to the rule that nothing here carries provider output:
without it, an operator debugging a denied read has a status code and nothing else. Pass
`includeServerErrors: false` to `fetchTransport` for a deployment that would rather have less.

## Testing

No test in this package calls a live Vault. The suite runs against a fake transport driven by
recorded response fixtures, and every secret-bearing field in a fixture carries a canary, so a
fixture that leaks through a code path is caught by the same sweep that would catch a real leak.

The container matrix against real Vault and OpenBao servers is a second tier and is not required for
the unit suite to pass locally.

## License

MIT
