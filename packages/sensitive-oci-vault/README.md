# @platform-sec/sensitive-string-oci-vault

OCI Vault as a `SecretSource`, through the secret retrieval data plane: every value arrives as a
`SensitiveString`, the secret OCID stays off the label, and a bundle whose content type is not the
one this package decodes is refused rather than decoded as base64 anyway.

## The two clients, and the one to use

This is the first thing an implementer gets wrong here, so it goes at the top.

- **`oci-vault`'s `VaultsClient`** manages secrets, their metadata and their versions. It does not
  return secret contents.
- **`oci-secrets`' `SecretsClient`** is the read path, through `getSecretBundle` and
  `getSecretBundleByName`. It is what this package takes.

The package is named for the product and depends on the data plane. The name mismatch is confusing
enough to be worth a paragraph, and the constructor's error message says the same thing.

## Installation

```bash
pnpm add @platform-sec/sensitive-string-oci-vault
```

## Requirements

- Node.js 22.12+
- `@platform-sec/sensitive-string-core` (peer dependency)
- `@platform-sec/sensitive-string-secrets` (peer dependency)
- `oci-secrets` (peer dependency, **types only**)

The SDK is a types-only peer: the client is injected, the two reads are ordinary methods, and
nothing here imports a value from it. That also keeps `oci-common`, which the SDK's request types
extend, out of this package's build.

## Usage

```typescript
import * as secrets from 'oci-secrets';
import { OciSecretSource } from '@platform-sec/sensitive-string-oci-vault';

const oci = new OciSecretSource({
  client: new secrets.SecretsClient({ authenticationDetailsProvider }),
  vaultId: 'ocid1.vault.oc1.iad.abc...',
  onLoad: (event) => audit.info('secret.load', event),
});

const key = await oci.get('prod-stripe-key');

key.ref.version;   // the concrete versionNumber, never 'CURRENT'
```

Reading by name is the ergonomic path and the one `SecretRef.path` maps to, with the vault OCID in
the source configuration.

### Stages, version numbers and version names

```typescript
await oci.get({ path: 'prod-stripe-key', version: 'PREVIOUS' });          // stage
await oci.get({ path: 'prod-stripe-key', version: '2' });                 // versionNumber
await oci.get({ path: 'prod-stripe-key', version: 'release-2026-09' });   // secretVersionName
```

OCI splits across three request fields what this library holds in one `version` slot. All digits is
a number, one of the five known stages is a stage, and anything else is a version name. Misrouting
produces a 404, which arrives as an absence rather than as a different secret.

### Reading by OCID, and why it needs a label

```typescript
await oci.get(secretOcid);                                // throws
await oci.get(secretOcid, { label: 'prod-stripe-key' });  // works
```

A label is not private: it appears in every log line and every error tracker event that touches the
value. A secret OCID encodes the tenancy, the region and the realm, and there is nothing in one that
identifies the secret without also identifying the tenancy. So a read by OCID has no label to derive
and this package refuses rather than inventing one. Pass a name, or pass `label` explicitly.

The OCID is not discarded: it goes on `ResolvedSecretRef.metadata` as `secretId`, which reaches the
load hook and never reaches redacted output. The resolved `ref.path` for an OCID read is a
placeholder for the same reason, so an error message does not carry the tenancy.

### A ref is a name, not a URL

A ref that carries a scheme and authority is refused at the read. The label rule already strips a
host from the label, and this is the half the label rule does not reach: `ResolvedSecretRef.path` is
what every error this package throws quotes, and what every load event carries to the audit sink, so
a host and port in a ref is a host and port in an error tracker. The endpoint belongs on the client.
The Vault package refuses the same shape for the same reason.

### Base64, and the decode that would not fail

The bundle's content is base64 and `Buffer.from(value, 'base64')` is lenient: it skips characters
outside the alphabet rather than failing, so a damaged bundle decodes to plausible-looking garbage,
gets wrapped as a credential, and fails at the far side as an authentication error with nothing
pointing back here. This package validates the alphabet and the round trip first, through the shared
decoder, and the failure names the secret rather than its content.

### Content types

`secretBundleContent` is a discriminated union on `contentType` with one member, `BASE64`. Handling
the one that exists and refusing anything else is the point: a new content type decoded as base64
would produce silent garbage that travels downstream as a credential.

### Lifetime

`timeOfExpiry` is the secret version's own expiry and becomes the instance's `expiresAt`.
`timeOfDeletion` is the scheduled deletion of the secret resource, and a secret pending deletion
still works until it is deleted, so it is recorded on `metadata` and never bound. That is the same
call this row makes for a rotation schedule.

## Measured behaviour

| Question | Answer | Verified on |
|---|---|---|
| Does OCI model any content type other than `BASE64`? | No. `SecretBundle.secretBundleContent` is `Base64SecretBundleContentDetails`, whose `contentType` is the constant `"BASE64"` | `oci-secrets` 2.140.1 |
| Does the service ever send a different one? | **Not verified.** Needs a live tenancy, which is why the guard is a real check rather than dead code | not applicable |
| What does an absent secret answer? | Assumed 404 from the REST contract; the check is on `statusCode` | not applicable |

The wire shape is pinned by the SDK's own model interfaces: the fixtures are typed as
`models.SecretBundle`, so a field this package reads has to exist on the real model.

## What this does not protect against

- **Two copies of the secret.** The base64 string on the response and the decoded string both exist
  and neither can be cleared on demand. This is inherent to a base64 wire format in JavaScript.
- **The SDK's own response copy.** The bundle holds the encoded secret before this package sees it.
  What this package promises is that the object does not travel any further.
- **A caller's own `label`.** Passing one is how an OCID read works at all, and nothing stops a
  caller passing the OCID as the label. `describeLabelDisclosure` reports it; nothing enforces it.
- **Writing.** This package is read-only. The write path for OCI goes through `oci-vault`'s
  control-plane `VaultsClient`, which is a different client with a different trust boundary, and
  adding it here would pull in the SDK this package deliberately does not depend on.
- **Memory dumps and heap persistence before GC**, which is the library-wide limitation.

## License

MIT
