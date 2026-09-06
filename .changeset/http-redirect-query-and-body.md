---
'@platform-sec/sensitive-string-http': patch
'@platform-sec/sensitive-string-axios': patch
'@platform-sec/sensitive-string-fetch': patch
'@platform-sec/sensitive-string-got': patch
'@platform-sec/sensitive-string-ky': patch
'@platform-sec/sensitive-string-undici': patch
---

A redirect hop no longer carries the caller's query, and a cross-origin 307 or 308 that would
re-send a body carrying a wrapped value is refused under `allowedHosts: 'strip'`.

Both were found by an independent verification of the corpus study that produced `'strip'`, by
measurement rather than by reading. With a wrapped credential passed as a query parameter and a 302
whose `Location` carried no query, the axios, fetch, ky and undici wrappers sent the second origin a
URL containing the credential: each hop handed the caller's query to `prepareRequest` again, which
appended it to whatever URL it was given. got did not, because it follows hops itself. The corpus
had recorded exactly this gap against GHSA-p2f4-r6v6-j797 and then withdrawn it, on the reasoning
that a redirect target is the URL the server names; that reasoning was correct only for the delegated
mode, where the client follows and nothing is re-merged.

`prepareRequest` now drops the query on any hop after the first, so no wrapper has to remember. A
redirect target is the URL the server named and nothing else, which is what every client in the
measured set does on its own.

A 307 or 308 re-sends the body, and all five wrappers delivered a JSON body carrying a wrapped value
to the cross-origin target under `'strip'`. A header can be dropped at the origin boundary without
changing what the request means; a body cannot, since a body with one field removed is a different
request that succeeds at doing something else. So the hop is refused with
`RedirectWouldResendCredentialError`, before anything is revealed for it, and the message says to
name the destination in `allowedHosts` if it is trusted with the body. A 301, 302 or 303 drops the
body on its own and is followed as before. `PreparedRequest` gains `bodyCarriesCredential`, which
covers a form body as well as a structured one, and `assertBodyMayFollow` is exported for a wrapper
that follows hops itself.

The got package now merges the instance's `defaults.options.headers` under the call's headers, as the
axios package already did for `defaults.headers`. Measured, a wrapped value placed in
`got.extend({ headers })` reached the wire as `[REDACTED:credential]` and an `apiKey()` descriptor as
`[object Object]`, on every hop, because the wrapper never saw either; they are now revealed,
recorded in the plan, scrubbed, and under `'strip'` dropped at the boundary. ky does not expose an
extended instance's defaults, so the ky README says to put a wrapped value in the call instead.
