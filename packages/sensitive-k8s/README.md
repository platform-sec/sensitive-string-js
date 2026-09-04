# @platform-sec/sensitive-string-k8s

Kubernetes Secrets as a `SecretSource`: every value arrives as a `SensitiveString`, `tls.crt` stays
an ordinary string because a certificate is public, and the annotation holding a second copy of the
Secret never leaves this package.

## Installation

```bash
pnpm add @platform-sec/sensitive-string-k8s
```

## Requirements

- Node.js 22.12+
- `@platform-sec/sensitive-string-core` (peer dependency)
- `@platform-sec/sensitive-string-secrets` (peer dependency)
- `@kubernetes/client-node` (peer dependency, **types only**, and not needed at all for
  `K8sMountedSource`)

The client library is a types-only peer: the API client is injected and `readNamespacedSecret` is an
ordinary method, so nothing here imports a value from it. That matters here because
`@kubernetes/client-node` carries a large dependency tree, and because the mounted-volume source
needs no cluster client at all.

## Usage

```typescript
import { CoreV1Api, KubeConfig } from '@kubernetes/client-node';
import { K8sSecretSource, k8sSecretTypeSpec } from '@platform-sec/sensitive-string-k8s';

const kc = new KubeConfig();
kc.loadFromDefault();

const k8s = new K8sSecretSource({
  api: kc.makeApiClient(CoreV1Api),
  namespace: 'payments',
  onLoad: (event) => audit.info('secret.load', event),
});

const creds = await k8s.getAll('db-creds', { fallback: 'credential' });
creds.fields.get('password');   // label 'payments/db-creds#password'
```

A `namespace/name` path overrides the configured namespace. The label is `namespace/name`: both are
ordinary Kubernetes identifiers and neither discloses anything about the cluster, which makes this
the one provider in the row whose label keeps the container the secret came from.

`resourceVersion` is what `ref.version` reports. A Secret has no versions, and `resourceVersion` is
the closest thing that is a real, concrete identifier of the state that was served.

### The built-in type specs

```typescript
const tls = await k8s.getAll('ingress-tls', k8sSecretTypeSpec('kubernetes.io/tls'));

tls.plain.get('tls.crt');    // string. A certificate is public.
tls.fields.get('tls.key');   // SensitiveString<'credential'>
```

| Type | Classification |
|---|---|
| `kubernetes.io/tls` | `tls.key` credential; `tls.crt` and `ca.crt` plain |
| `kubernetes.io/basic-auth` | `password` credential, `username` sensitive |
| `kubernetes.io/ssh-auth` | `ssh-privatekey` credential, `ssh-publickey` plain |
| `kubernetes.io/service-account-token` | `token` credential; `ca.crt`, `service-ca.crt` and `namespace` plain |
| `kubernetes.io/dockerconfigjson`, `kubernetes.io/dockercfg` | the file credential; expanded, `auth` / `password` / `identitytoken` credential and `username` / `email` sensitive |
| `Opaque` | no field rules, `fallback: 'credential'` |

`tls.crt` is the case that makes these worth shipping. A certificate is published to every client
that opens a connection, so wrapping it as a credential protects nothing and breaks the code that
parses it, compares its fingerprint, or hands it to a TLS context expecting a string.

The specs are exported and are **not** applied automatically from the Secret's `type` field.
Behaviour that changes because a server-side field changed is behaviour that breaks a caller when
somebody edits a resource; the caller who writes `k8sSecretTypeSpec('kubernetes.io/tls')` can see in
their own code what it does.

A spec may name a key the Secret does not carry. A real `kubernetes.io/tls` Secret has exactly
`tls.crt` and `tls.key`, and the spec also names `ca.crt`, which many clusters do not mount. That is
fine: on `getAll` a spec's `fields` classify the keys that turn up, and only `getJson` treats a
declared key as one the payload must have.

### Pull secrets

```typescript
const k8s = new K8sSecretSource({ api, namespace, expandDockerConfigJson: true });

const record = await k8s.getAll('regcred', k8sSecretTypeSpec('kubernetes.io/dockerconfigjson'));
record.fields.get('auths.index.docker.io.password');
```

Off by default, and deliberately a caller's decision rather than something a payload triggers.
Expansion changes the key set a `getAll` returns, so a caller running it under `fallback: 'plain'`
would turn one credential-classified string into several plain ones.

The rules match on the **leaf key name** rather than the dot path, because a registry hostname
contains dots and a pattern written against the path would have to anticipate
`auths.index.docker.io.auth`. Registry hostnames are container keys and never become leaves, so they
are never classified at all.

The nested JSON goes through the shared decode guard, so a malformed pull secret produces an error
naming the Secret rather than a `SyntaxError` quoting part of it.

Expansion lifts the pull secret's own top-level keys into the Secret's key space, so a Secret that
carries a key of the same name would have one of the two silently replaced. That is refused rather
than resolved, for the reason the Infisical source refuses a duplicated key: whichever one won,
an application would be reading a value from somewhere its classification never described.

### Bound service account tokens

```typescript
const k8s = new K8sSecretSource({ api, namespace, readTokenExpiry: true });
```

A projected service account token is a JWT and its `exp` is a real deadline. With this on, the
payload is base64url-decoded before wrapping and `exp` becomes the instance's `expiresAt`. **Only
`exp` is read**: the rest of the claim set names the namespace, the pod and the service account UID,
and `metadata` reaches the audit sink. The payload goes through the shared JSON guard, because a
malformed token is otherwise a `SyntaxError` holding a slice of the token.

A legacy service account token has no `exp` and binds nothing, which is correct: it does not expire.

Signature verification is not performed and is not this package's job. The token came from the
kubelet through a trusted mount; verifying it would need the cluster's public keys and would be
implementing token validation.

### Mounted volumes

```typescript
import { K8sMountedSource, SERVICE_ACCOUNT_PATH } from '@platform-sec/sensitive-string-k8s';

const mounted = new K8sMountedSource({ basePath: '/etc/secrets' });

const creds = await mounted.getAll('db-creds', { fallback: 'credential' });

const watcher = mounted.watch('db-creds', { fallback: 'credential' }, {
  onChange: (next) => pool.reconfigure(next),
});
```

The usual way a workload reads a Secret is a mounted volume, not an API call, and by the
trust-boundary test that belongs to the configuration loaders row: the files are plaintext on a
tmpfs the container can already read and no key is needed. It ships here anyway, because a user who
thinks of it as "reading a Secret" will look in this package first.

What it does is deliberately thin. It reads the directory, classifies, and wraps. It does **not**
delete the files, does not remap them into `process.env`, and does not claim to remove the original.

Entries beginning with `..` are skipped, which is the whole reason the reader is not a plain
`readdir`: a kubelet mount holds a timestamped data directory and a `..data` symlink beside the
visible keys, and including them would report the same secret twice under two names, one of which
changes on every update. `includeHiddenEntries: true` turns that off for a mount that is not a
kubelet one.

The kubelet rewrites a mounted Secret on a sync period rather than immediately, so a value read at
boot goes stale silently. `watch()` is for that, and the atomic swap the kubelet performs is exactly
the several-events-per-change case the shared watcher debounces. Each change produces new instances;
the ones already handed out stay valid, so an in-flight request finishes with the credential it
started with.

## The annotation that holds a second copy

A Secret created with `kubectl apply` carries
`metadata.annotations['kubectl.kubernetes.io/last-applied-configuration']`, whose value is the JSON
the user applied. Annotations are not treated as secret by most tooling: they are printed by
`kubectl describe`, collected by inventory and policy agents, and copied into audit records.

So this package strips `metadata.annotations` **entirely** rather than removing one known key. The
mechanism that put a copy of the Secret in an annotation is a convention, other tools follow similar
ones, and an allowlist survives conventions this package has not heard of. Only `name`, `namespace`,
`resourceVersion`, `uid`, `type`, `immutable` and `creationTimestamp` are surfaced. `labels` and
`managedFields` are dropped too.

## Measured behaviour

| Question | Answer | Verified on |
|---|---|---|
| What does `kubectl apply` write into `last-applied-configuration`? | The whole manifest. For a manifest written with `stringData`, **the secret is in the annotation unencoded**, where the Secret's own `data` is at least base64 | Kubernetes v1.34.1 (k3s), `kubectl` 1.34 |
| What keys does a real `kubernetes.io/tls` Secret have? | `tls.crt` and `tls.key`. No `ca.crt` | same |
| What does `ref.version` look like? | `resourceVersion`, a decimal string | same |
| Is `stringData` present on a read? | No. It is write-only, so a package that looks there reports an empty Secret | Kubernetes API reference; this package names it in an error |
| What does an absent Secret raise? | A 404, surfaced as `code: 404` by the current client | v1.34.1 through `@kubernetes/client-node` 2.0.0 |

The first row is worse than the design that preceded this package assumed, which said the annotation
holds `data`. Applying with `stringData` is the common way people write a Secret by hand, and that
is the case where the annotation holds plaintext.

`src/__tests__/live.test.ts` runs the suite against a real API server and skips itself unless
`K8S_KUBECONFIG` is set. The unit suite runs against typed fixtures and needs no cluster.

## What this does not protect against

- **The API server's response copy.** `V1Secret` holds the base64 secret, and its annotations may
  hold a plaintext copy, before this package sees it. What this package promises is that the object
  does not travel any further: it is destructured in one function, is not stored on a record, is not
  attached to an error, and is not passed to a hook.
- **The decoded payload copy.** Base64 decoding produces a second copy this package cannot clear.
- **The files a mounted volume put on disk.** `K8sMountedSource` reads them and does not remove
  them. Removing them is the configuration loaders row's problem and comes with its own limits.
- **Anything about RBAC.** A caller who can read a Secret can read it; this package changes what
  happens to the value afterwards.
- **Memory dumps and heap persistence before GC**, which is the library-wide limitation.

## License

MIT
