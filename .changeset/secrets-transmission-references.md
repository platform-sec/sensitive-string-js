---
'@platform-sec/sensitive-string-core': minor
'@platform-sec/sensitive-string-secrets': minor
---

Add transmission references: send a pointer to a secret instead of the secret.

ROADMAP 6.5, release one of two. `serialize()` puts the raw value on the wire and asks the transport
for confidentiality, which is a fair deal for mTLS between two services in one trust domain and a
poor one everywhere the payload comes to rest. A job in SQS, Kafka, a `jobs` table or a webhook
retry buffer sits there in plaintext for as long as the retention allows, and a transport that
terminates at a mesh sidecar, an API gateway or a logging proxy is decrypted somewhere in the
middle. Where the value came from a store both sides can reach, `toReference(record, { store })`
sends where it is and the receiver fetches it with its own credentials, so the value never leaves
the process that read it.

There is no `token.toReference()`, and the reason is not ergonomic. `#derived` unions the state of
every source instance into the derivative, which is right for constraints and inverts what
provenance means: a `toReference()` on the instance would let `token.substring(0, 4)` mint a pointer
to the whole credential, and the receiver would have no way to tell the difference. The label rule
is the second reason, since it strips everything identifying the account, project, tenancy or host,
so an instance knows a path and not which of an organization's stores that path is in, and the same
logical path usually exists in staging and in production. Minting takes the `ref` a read returned,
which contains no secret material by construction, and `store` is required rather than derived from
the source, because inventing one from the endpoint would put an internal hostname into a payload.

Minting is not a reveal. It performs no I/O and never touches `#value`, and recording it as one
would make a sink that counts reveals to decide whether a credential is over-used count every
message that merely mentions the secret. That is the call `SecretLoadEvent` already made for loads,
for the same reason.

Resolving is the half with the security content, and it is not `get()` under another name.
`createReferenceResolver({ store, source, allow }).resolve(ref, { context })` runs in the receiver,
with the receiver's credentials, against a path a sender chose, which is the shape of every confused
deputy: unconstrained, it lets anything that can enqueue a job read any secret the receiver's role
can read, using the receiver as the oracle. So the allowlist is required, there is no permissive
default, and the empty list is legal and resolves nothing. The checks run in order and each precedes
the fetch: the caller's own context, then the shape and the format version, the store identity
compared exactly, a path carrying a traversal, an empty segment, a leading slash or a control
character, a version outside `[A-Za-z0-9._:-]{1,128}`, an entry covering the path, and an entry that
resolves this kind of reference and declares this field. Then the class, as the strictest among the
covering entries and then the more restrictive of that and the reference's: a class on the wire may tighten what the receiver does and may never loosen it, because
a receiver that took `klass` from a payload would let a sender turn off constant-time comparison for
a credential, lift the refusal on partial queries, and let `mask()` disclose a prefix.

A path is refused rather than normalized. Normalizing would mean this library and the provider each
holding an opinion about what `kv/a/../b` means, and a disagreement between two normalizers is how a
path that fails the allowlist reaches the store anyway. It is also refused for carrying `%`, `\`,
`?` or `#`, which is a stronger rule than "no `..` segment" and a measured one rather than a
cautious one: a provider builds its request as `new URL(base + path)`, which is what
`sensitive-vault` does, and on Node 22.15.0 the WHATWG parser applies its double-dot rule to the
percent-decoded segment and reads a backslash as a separator, so both
`kv/payments/%2e%2e/%2e%2e/auth/token/lookup-self` and `kv/payments/..\..\auth/token/lookup-self`
leave an allowlisted subtree while passing a check over `/`-split segments, and the second carries
no percent sign at all. A `?` turns a read of a permitted secret into a different request against
the same store. The suite pins that parser behaviour next to the refusals, so the rule keeps its
reason attached. A version is checked against a charset rather than escaped, for the same reason.
Patterns are a trailing `*` on a segment boundary and nothing else, with no regex, and a malformed
one throws at construction rather than silently matching nothing.

Where entries overlap, the class is the strictest among them rather than the first one's. A subtree
rule and a rule for one path under it are how an operator writes an allowlist, and taking the first
would make `[{ path: 'kv/*', klass: 'sensitive' }, { path: 'kv/payments/stripe', klass:
'credential' }]` resolve the Stripe key as `sensitive`, which is a security control whose answer
depends on the order two lines were written in. The allowlist is copied entry by entry and frozen at
construction for the same kind of reason, so a caller holding the array or an entry cannot widen a
live resolver afterwards.

A refusal is a `ReferenceRefusedError` carrying `reason`, and the path is on `error.path` and never
in `error.message`: a refusal is the case where the sender is least likely to be one this receiver
trusts, and interpolating what they sent would put attacker-chosen text into the receiver's own
logs. As everywhere in this package, no error sets `cause`.

`core` gains the format and nothing else: `SensitiveValueReference`, `isSensitiveValueReference()`,
`carriesReferenceMarker()` and `referenceFormatVersion()`. It has no minting and no resolving,
because both need the store, the version and the credentials, and it would have had to model stores
and accounts to hold them. What the format is doing in `core` is that the walks which must decide
what to do with a wire object are there, and what they decide for this one is to leave it alone: a
reference carries no secret material, resolving it needs credentials of the reader's own, and
redacting it would make a reference-passing system undebuggable for exactly no gain. Those
assertions are positive in the suite rather than absent from it, so a later change to redact
everything with a `__sensitive`-shaped marker fails a test instead of shipping.

Two smaller decisions worth recording. `resolve()` requires its own `RevealContext`, for the reason
`PutOptions.context` does on the write path, and checks for it before it looks at the reference at
all, because a receiver that forgot its context has a mistake of its own and reporting that as a
fault in what arrived would point whoever reads the log at the wrong party. That context is
installed as a child of the ambient one, so an application's `auditReveal` is inherited rather than
dropped and a provider that reveals its own token to authenticate the request records that reveal
under the caller's name. And `pinVersion`
defaults to true, since a reference stands in for a value and a value does not change between the
send and the receive, with the cost stated where the option is: a pinned reference outlives the
rotation that was meant to retire the old version, and queue retention shorter than the rotation
interval is the honest fix. The `'unknown'` a provider reports when it has no version is a sentinel
rather than a version, and is never pinned.

The encrypted envelope, the other half of 6.5, is a separate release and is not in this one.
