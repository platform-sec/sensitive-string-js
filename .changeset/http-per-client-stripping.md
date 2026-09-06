---
'@platform-sec/sensitive-string-http': minor
---

The cross-origin stripping exemption is per client, and fails closed for a client nobody measured.

`isStrippedAcrossOrigins(name)` answered from one global set of the three header names the Fetch
specification says a client must drop on a cross-origin redirect. That is the specification's claim,
not any given client's behaviour, and the two are not the same thing: a survey of Node HTTP clients
turned up several that forward `Authorization` across origins. The exemption is what flips a request
carrying a credential from refusing redirects to delegating them, so granting it on the
specification's authority means trusting an implementation nobody looked at.

It now takes the client as well: `isStrippedAcrossOrigins(name, client)`. A client in the measured
table gets the exemption it was measured to deserve, and any other name gets nothing, so its requests
default to refusing redirects. `prepareRequest` already carries the client name and passes it
through, and `allowedHosts` still overrides the default in either direction, because naming the hosts
is the caller saying they have thought about it.

The table was measured rather than read off the specification, and the measurement now lives in the
repository as `__tests__/redirect-stripping.test.ts` rather than in a design document: two loopback
servers on different ports, a 302 from the first to the second, and the second recording what
arrived. On axios 1.20.0, got 16.0.0, ky 2.1.0, undici 8.10.1 and Node 22.15's `fetch`, all five drop
`Authorization`, `Cookie` and `Proxy-Authorization`, and all five forward `x-api-key` untouched. The
test asserts the table in both directions against the clients themselves, so a client that changes
behaviour in a future release fails there rather than quietly widening what the table promises.

`Proxy-Authorization` was in the original set on the specification's authority alone and had never
been measured. It is now measured, and it does belong.

No wrapped client changes behaviour: all five were already in the exempt set and all five still are.
What changes is a caller who drives `prepareRequest` directly with a client name of their own, which
used to inherit the full exemption and now inherits none of it.

`measuredClients()` is exported alongside, so a caller can see which names carry the exemption rather
than discovering it from a redirect that did not happen.
