---
'@platform-sec/sensitive-string-http': minor
'@platform-sec/sensitive-string-axios': minor
'@platform-sec/sensitive-string-fetch': minor
'@platform-sec/sensitive-string-got': minor
'@platform-sec/sensitive-string-ky': minor
'@platform-sec/sensitive-string-undici': minor
---

`allowedHosts: 'strip'`: follow a redirect with the credential removed instead of refusing it.

There were two answers to a credential-bearing request that gets redirected, and for one real shape
both are wrong. Refusing breaks a provider that redirects a release asset or a download to object
storage, which is the ordinary way private artifact hosting works. Naming the hosts is impossible for
exactly the same reason: the caller cannot enumerate a bucket endpoint the provider picks at request
time. `'strip'` is the third answer, and it is the one the upstream project behind
[GHSA-p2f4-r6v6-j797](https://github.com/advisories/GHSA-p2f4-r6v6-j797) reached for when it fixed
the same problem: drop the credential at the origin boundary and keep going.

The difference is where the list of headers to drop comes from. That project had to guess which names
carry credentials, shipped nine of them, and added a registration function so publishers could add
their own. Here the list is derived: the scrub plan already records exactly which header names carried
a wrapped value, because the caller decided that when they wrapped it. A header the library has never
heard of is covered on the same terms as `Authorization`, and there is nothing to register.

`'strip'` is never a default and cannot become one. Refusing is the answer that cannot go wrong
quietly: a request that stops is a bug report, while a credential dropped on a hop the caller did not
know was a boundary is a request that succeeds at doing less than it appears to. Same-origin hops keep
everything, since a redirect inside one origin discloses nothing to anyone new.

`isCrossOrigin` decides the boundary by the scheme/host/port rule, normalizing implied ports. It makes
one exception, `http:` to `https:` on the same host where neither side names a non-default port, which
is an upgrade to the same server that every client in the measured set follows without stripping. The
reverse is never allowed, and the allowance does not extend to a non-default port, since a different
port is a different service as often as it is the same one.

All five wrappers implement it and each is tested end to end against a real pair of loopback origins,
asserting both that the canary does not reach the second origin and that the request still completes.
got is the one that differs: it follows hops itself but hands the next request's options over through
`beforeRedirect`, so there it is a deletion rather than a rebuilt request.

What every wrapper accumulates is the set of dropped header *names*, applied where the next request is
built, rather than a narrowed header object carried forward. The two are not equivalent and the
difference is a real leak: axios merges `defaults.headers` underneath the request's own, and the axios
wrapper deliberately supports a wrapped value there, so narrowing only the per-request headers would
strip the call site's credential and forward the instance's. Dropped names are also set to `null` in
the outgoing axios config, because removing a name from what is sent is not enough on its own when the
client refills it from its defaults.

got tracks the previous hop rather than comparing every hop against the request's original URL.
Same-origin is not transitive once the http-to-https upgrade is allowed: A `http://x` to B `https://x`
is an upgrade, B to C `http://x` is a downgrade, and C is same-origin with A, so comparing against A
would forward a credential into plaintext. Distinguishing the two needs TLS and is not covered by a
test; the other four wrappers rebuild each hop and already hold the previous URL.

New exports from the http package: `isCrossOrigin`, `headersWithout`, and the `RedirectPolicy` and
`ResolvedRedirectPolicy` types. `allowedHosts` accepts `'strip'` alongside the array and `false`.
Nothing changes for a caller who does not ask for it.
