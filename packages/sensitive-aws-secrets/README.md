# @platform-sec/sensitive-string-aws-secrets

AWS Secrets Manager as a `SecretSource`: every value arrives as a `SensitiveString`, the response
object never leaves this package, and `ref.version` is the `VersionId` the service served rather
than the staging label that was asked for.

## What actually goes wrong

```typescript
const res = await client.send(new GetSecretValueCommand({ SecretId: 'prod/db' }));
const { username, password } = JSON.parse(res.SecretString!);
await pool.connect({ user: username, password });
```

Four things have gone wrong by the last line and none of them throws.

`res` holds the raw secret and is an ordinary object, so it reaches an error tracker if the next
line fails while it is in scope, and it reaches a log line the first time somebody debugs this
function. `username` and `password` are plain strings with no class, no label and no audit trail.
If the secret turns out to hold a bare API key rather than JSON, the `SyntaxError` carries up to
twenty characters of it into the report. And nothing recorded that a secret was loaded, from where,
or at which version.

## Installation

```bash
pnpm add @platform-sec/sensitive-string-aws-secrets
```

## Requirements

- Node.js 22.12+
- `@platform-sec/sensitive-string-core` (peer dependency)
- `@platform-sec/sensitive-string-secrets` (peer dependency)
- `@aws-sdk/client-secrets-manager` (peer dependency)

Core and the shared layer are peers rather than regular dependencies because both are identified by
`instanceof`: `redactInStructure` and `containsSensitive` check for `SensitiveString`, and callers
check for `SecretPayloadError`. Two copies in `node_modules` make every one of those checks miss.

This is the one package in the secrets manager row with a vendor import at run time. The others
declare their SDK as a types-only peer, because the client is injected and their calls are ordinary
methods. AWS v3 dispatches through command objects, so `GetSecretValueCommand` has to be
constructed; reimplementing its serialization to avoid the import would be a worse trade.

## Usage

```typescript
import { SecretsManagerClient } from '@aws-sdk/client-secrets-manager';
import { AwsSecretSource } from '@platform-sec/sensitive-string-aws-secrets';

const aws = new AwsSecretSource({
  client: new SecretsManagerClient({ region: 'us-east-1' }),
  onLoad: (event) => audit.info('secret.load', event),
});

const db = await aws.getJson('prod/db', {
  fields: { username: 'sensitive', password: 'credential', host: 'plain', port: 'plain' },
});

db.fields.password;   // SensitiveString<credential:prod/db#password>
db.fields.port;       // 5432, untouched
db.ref.version;       // the VersionId, never 'AWSCURRENT'
```

The client is injected, so credential providers, retry strategy and endpoints stay the
application's concern. This package adds no retry policy of its own: an application that has
configured its SDK's should not have a second one wrapped around it.

### Staging labels and version ids

```typescript
await aws.get({ path: 'prod/stripe', version: 'AWSPREVIOUS' });                 // VersionStage
await aws.get({ path: 'prod/stripe', version: 'b9b1f2c4-4a2f-...' });           // VersionId
```

`GetSecretValue` takes one or the other and this library has one `version` slot, so something has
to decide which field a string goes in. A value shaped like a UUID goes to `VersionId` and anything
else to `VersionStage`. Guessing is acceptable only because the failure direction is safe: a
misrouted staging label produces `ResourceNotFoundException`, which arrives as an absence rather
than as a different secret. `versionIs: 'stage' | 'id'` overrides it.

During a rotation both `AWSCURRENT` and `AWSPENDING` are valid. That is a property of the rotation
protocol rather than a problem to solve, so `VersionStages` goes on `metadata` and a caller can see
which one they got.

### Rotation metadata, which is not a deadline

```typescript
const aws = new AwsSecretSource({ client, readRotation: true });
```

Off by default, because it costs a `DescribeSecret` call per load. `NextRotationDate` is the most
tempting field in this API and binding it would be wrong: the current version of a rotated secret
keeps working after its next rotation date, usually until the rotation actually succeeds and often
well past that. A value derived from it would throw while still being the live credential. It is
recorded on `metadata` and never becomes `expiresAt`.

A `DescribeSecret` failure loses the metadata rather than the secret.
`secretsmanager:DescribeSecret` is a separate permission from `GetSecretValue`.

### Labels

A label is not private: it appears in every log line and every error tracker event that touches the
value. So the label is the secret's **name**, never the ARN, which carries the account id. The ARN,
the account and the region go on `ResolvedSecretRef.metadata`, which reaches the load hook and
never reaches redacted output. The resolved `ref.path` is the name too, so an ARN in the request
does not become an account id in an error message.

Passing a full ARN works and keeps AWS's six random characters on the label. Stripping them looks
tidier and is a guess: a partial ARN has no suffix, and a secret genuinely named
`prod/config-backup` would lose its last word to a rule that cannot tell the two cases apart. Pass
the name rather than the ARN and the question does not arise.

## Measured behaviour

| Question | Answer | Verified on |
|---|---|---|
| Does the SDK's own logging redact `SecretString`? | Yes. At `info` level the SDK logs the full output object with `"SecretString":"***SensitiveInformation***"` | `@aws-sdk/client-secrets-manager` 3.1126.0, Node 22.15.0 |
| Does that cover the application's logging? | No. `output.SecretString` is the raw string, and a response object that reaches an error tracker is serialized by the tracker's rules | same |
| Does the SDK log anything else identifying? | Yes. The same line carries the ARN, which holds the account id | same |
| What does an absent secret raise? | `ResourceNotFoundException` | AWS API docs; fixtures match |

The rest of the wire shape is pinned by the SDK's own TypeScript types: this package's fixtures are
typed as `GetSecretValueCommandOutput`, so a field it reads has to exist on the real response.

## What this does not protect against

- **The SDK's own response copy.** `GetSecretValueCommandOutput` holds the raw secret before this
  package sees it. What this package promises is that the object does not travel any further: it is
  destructured in one function, is not stored on a record, is not attached to an error, and is not
  passed to a hook.
- **The decoded `SecretBinary` copy.** Decoding a `Uint8Array` produces a second copy of the secret
  that this package cannot clear. JavaScript has no primitive that would let it do better.
- **The decoded payload copy.** `getJson` and `getAll` materialize the payload as plain strings
  before anything is wrapped, and that copy exists until collection.
- **An SDK error's own text.** A `ServiceException` propagates unchanged, because its `name` is what
  callers catch on. AWS's error text describes policy and identifiers rather than values, and this
  package does not inspect it.
- **`aws-secretsmanager-caching`.** An application using it has a cache holding raw strings upstream
  of anything here. Use one cache or the other; this package's holds instances.
- **Memory dumps and heap persistence before GC**, which is the library-wide limitation.

## License

MIT
