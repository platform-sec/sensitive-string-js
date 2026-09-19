---
'@platform-sec/sensitive-string-core': minor
'@platform-sec/sensitive-string-zod': patch
---

Add destination binding: a value can say which sinks and hosts it may be revealed toward, and the
raw-value gate checks the reveal context against it.

```ts
const registryPassword = new SensitiveString(pw, 'credential', 'registry', {
  destinations: { hosts: ['registry-1.docker.io'] },
});

registryPassword.reveal();                                                    // DestinationRestrictedError
registryPassword.reveal({ name: 'push', tags: { host: 'registry-1.docker.io.attacker.net' } });
                                                                              // DestinationRestrictedError
registryPassword.reveal({ name: 'push', tags: { sink: 'http', host: 'registry-1.docker.io' } });
                                                                              // the password
```

Every other check in the gate answers a question about the value or about the process. None asked
where the plaintext was about to go, so a credential could be wrapped at entry, revealed at exactly
the call site the design says, audited, and still written to the wrong host. The adoption corpus
recorded that seven times, twice as the same substring host comparison from unrelated maintainers.

The destination is the context's `tags.sink` and `tags.host`, which are the tags the integrations
already write on every reveal: the HTTP clients set both from the request URL per attempt, the data
layer sets the sink to its driver, and `sendToExternal` sets it to the sink it was given. So a bound
value works unchanged through `sensitive-axios`, `sensitive-fetch` and the rest, and refuses through
them when the URL the program computed points somewhere else. A context that states no destination
refuses, on the allowlist rule the environment restrictions follow; there is no denylist.

Every operation that hands plaintext out is checked, `hash()`, `mask()`, `map()`, `serialize()` and
`toWorkerPayload()` included, so serializing a bound value is itself a reveal toward wherever the
payload goes. `equals()` is not checked: a comparison sends the value nowhere. Derived values carry
the binding, a value derived from two bound values carries both, and bindings cross the wire and the
worker handoff as data that can only tighten. `zSensitiveDeserialize()` declares the wire field so an
object schema does not strip it.

A host entry is what `new URL(url).host` spells, compared case-insensitively, with the port when it
is not the scheme's default; `*.example.com` matches at least one label below and not the domain
itself, with a port as part of the suffix. A URL, a path, a userinfo, a bare `*`, a misplaced
wildcard, or any spelling the URL parser would change, a Unicode domain or a stated default port,
is refused at construction, because an entry that can never equal a host tag sits in the list
matching nothing. `sensitive-fetch`'s standalone `sensitiveHeaders` helper takes no URL and writes
no host, so a host-bound value refuses through it unless the caller's context names the host.

Three additions on the same mechanism. `principals` is a third literal list, matched against
`tags.principal`, whatever identity the application tags its reveals with, so a credential fetched
for one caller and handed out of a shared cache to another refuses. A `proxy` tag is read the other
way round: absent means the request goes to its host directly, present means a second machine
receives the bytes first and has to match the same `hosts` list; `sensitive-http` tags it when a
client resolves one. And `releasedBy: Promise<boolean>` holds every exposing read with
`UnreleasedSensitiveValueError` (code `unreleased-value`, `status` `'pending'` or `'refused'`) until
the promise resolves `true`, for good when it resolves anything else or rejects: a credential whose
recipient is trusted only after an asynchronous check, an SSH host key against a known-hosts store,
is constructed with the check in flight and cannot be sent until it says so. A plain boolean is
refused at construction, `equals()` is not held, and the promise never crosses the wire because an
unreleased value cannot be serialized and a released one has nothing to carry.

`DestinationRestrictedError` extends `SensitiveStringError` with the code `destination-restricted`
and names the tag that refused, what the context stated, and the allowed list, none of which is any
part of the value. A process that binds nothing pays a length check on an empty frozen array.
