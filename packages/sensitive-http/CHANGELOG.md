# @platform-sec/sensitive-string-http

## 0.2.0

### Minor Changes

- 59d6a4b: `headers` on the wrapper's options: a typed place for an instance-level credential.

  The got and axios wrappers read their client's own default headers, so a wrapped value or an
  `apiKey()` descriptor placed in `got.extend({ headers })` or on `defaults.headers.common` is
  revealed, recorded and stripped like any other. That is the run-time story. The compile-time one is
  that none of it type-checks: measured on got 16.0.0, axios 1.20.0 and ky 2.1.0, each client types an
  instance's default headers as strings, both a `SensitiveString` and a descriptor are rejected, and
  the types are aliases nothing can widen from outside. A TypeScript caller had a cast as the only way
  in, which is what this repository's own got suite was doing.

  `SensitiveInstanceOptions` extends `SensitiveClientOptions` with `readonly headers?:
SensitiveHeaders`, and the three wrappers built around a client instance take it:
  `SensitiveGotOptions`, `SensitiveAxiosOptions` and `SensitiveKyOptions` are now aliases of it. The
  headers sit over the client's own defaults, where the wrapper can read them, and under each call's
  headers, and go through the same pipeline: revealed once per attempt, in the scrub plan, scrubbed on
  both settlement paths, and under `allowedHosts: 'strip'` dropped at the origin boundary. The merge
  happens before the dropped-name accounting, so a name stripped at one hop is not refilled from the
  option on the next; the axios and ky suites assert that across a bounce through a second origin and
  back. A credential there flips the redirect default to refusing, the same as one in the call, and
  each suite asserts that too.

  For ky this is the only instance-level layer there is. ky does not expose an extended instance's
  defaults, so a wrapped value in `ky.extend({ headers })` was never seen by the wrapper and the README
  said to put it in the call instead; it now says to put it here.

  `fetch` and undici are unchanged. Neither has an instance to wrap, so their per-call bag is the whole
  surface and already takes a wrapped header.

  Nothing changes for a caller who does not set it. The got and axios wrappers still read their
  client's defaults at run time, so a JavaScript caller keeps what they had.

- 612ccbd: The cross-origin stripping exemption is per client, and fails closed for a client nobody measured.

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

- aadfec7: Tag the proxy a request goes through, so a host-bound credential refuses one its binding does not
  name.

  A proxy setting changes the machine that receives the bytes and leaves the URL untouched, so the
  host check alone passed it; the corpus recorded that shape against axios, and noted that the only
  place this row mentioned a proxy was an instruction for turning off the check that incidentally
  covered it. `OutgoingRequest` gains `proxy`, a URL or a `host[:port]`, and the attempt context tags
  it as `tags.proxy`, which core's destination binding reads as a second machine the bytes reach.

  `sensitive-axios` resolves the effective proxy the way axios itself does: `config.proxy`, an agent
  on `httpAgent` or `httpsAgent` that exposes its `proxy` as `https-proxy-agent` does, or the
  `<scheme>_proxy` and `all_proxy` environment under `no_proxy`, with `proxy-from-env` 2.1.0's rules
  restated rather than imported, since that package is axios's dependency and not this one's. An
  opaque agent reads as no proxy and the README says so. got, ky, undici and fetch honour no proxy
  option of their own and pass none.

- 256911b: `allowedHosts: 'strip'`: follow a redirect with the credential removed instead of refusing it.

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

  What every wrapper accumulates is the set of dropped header _names_, applied where the next request is
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

### Patch Changes

- 1c87ee4: `containsRedactionMarker()` and `redactionMatchers()` in core, replacing four separate answers to
  the same question: given a string about to be written to a column, sent in a request body or stored
  in a secret, does it carry the text a `SensitiveString` renders as? `sensitive-http` derived its
  answer from the policy registry, `sensitive-typeorm` and `sensitive-drizzle` each shipped a narrower
  copy of that derivation, and `sensitive-secrets/write` used a hardcoded `[REDACTED:`. Core owns the
  format, so the detector lives there and the four call it.

  Two gaps close, both in the database packages and both security-relevant.

  **`markerPattern` was ignored.** Core declares it on `SensitivityPolicy` for a policy whose redaction
  varies with the value, `deterministicRedaction()` sets it, and core's own documentation for the field
  names the http guard as its consumer. The two copies written for a database did not read it, so a
  deployment using deterministic redaction had a marker check in front of its columns that could not
  recognise its own markers.

  **A marker for an unregistered class went unrecognised.** Both copies enumerated the registry and
  looked for `[REDACTED:${klass}]` per class. For a reader that is the ordinary case rather than an
  edge one: the column was written by an older release, or by a service that registered a class this
  process does not have. The detector matches the `[REDACTED:` prefix, which covers those, and also
  catches a marker that a composed transformer altered without destroying.

  `policyRegistryVersion()` is new and exported. The memo is keyed on it rather than on the set of
  registered class names, because an `overwrite` re-registration replaces a policy's `redact` while
  leaving the names identical, and both copies kept answering from the previous policy until something
  else changed.

  `sensitive-typeorm` and `sensitive-drizzle` no longer export `redactionMarkers` or
  `resetMarkerCache`; they re-export core's `redactionMatchers` and `resetRedactionMarkerCache`
  instead. `redactionMatchers()` returns `(string | RegExp)[]` rather than a `Set<string>`, since a
  `markerPattern` is a pattern.

- 635b4c2: Stop paying for the failure the guards almost never find.

  Both of these guards run on every request and every statement, and both did work whose only consumer
  was a branch that does not fire. Neither change alters what is refused. What changes is what a clean
  request costs to clear.

  `assertNoMarker` percent-decoded every outgoing body before scanning it, which allocates two full
  copies of the body: one from `replace(/\+/g, ' ')` and one from `decodeURIComponent`. A JSON body
  contains neither `%` nor `+`, so `percentDecoded` is the identity on it and the decoded scan searches
  a string identical to the one just searched. The decode is now skipped when the body holds neither
  character, which is not a heuristic: with no `+` the replace has nothing to replace, with no `%` the
  decode has nothing to decode, so `decoded !== wire` was already dead and the branch was unreachable.
  Measured on Node 22.15.0 over a marker-free JSON body, median of seven rounds with each size in its
  own process: 1 KB from 2.6 us to 105 ns, 16 KB from 34.9 us to 613 ns, 128 KB from 366 us to 5.9 us.
  It is the only figure in this release that scales with payload size, so it is worth most to whoever
  sends the largest bodies.

  `+` is checked as well as `%`, and that half is load-bearing rather than defensive. A custom
  `registerPolicy` redaction may contain a space, a form encoder puts that space on the wire as `+`,
  and the resulting body carries the marker with no percent-escape anywhere in it. A check for `%`
  alone would skip that body without looking at it, and a test now fails if the `+` is removed. A
  second test compares the guard against an implementation that decodes unconditionally over a corpus
  of bodies, so the equivalence is asserted rather than argued.

  `findUnsafeParameter` walked the bound parameters through `parameterEntries`, which materialises a
  `[string, unknown][]`, then carried a path string down the recursion and allocated a `WeakSet` per
  container. On a bag with nothing wrong in it, which is every bag in a working application, all three
  are built and discarded. The walk now reads the three bag shapes in place, builds the path only while
  unwinding the branch that found something, and creates the cycle guard on the first descent rather
  than on entry. Measured the same way: 5 scalars from 237 ns to 81 ns, 6 named scalars from 486 ns to
  201 ns, 3 parameters with one nested array from 532 ns to 162 ns, a 4-level nesting from 1017 ns to
  372 ns.

  Whether that second one is worth having depends on the driver, and the doc comment says so rather
  than quoting the ratio alone. Against a networked Postgres, 300 ns is invisible. Against in-process
  `better-sqlite3`, where a small query is single-digit microseconds, it is a few percent of the
  statement.

  `parameterEntries` keeps its shape and its exported signature, but nothing calls it on the hot path
  any more, so two walkers now read the same three bag shapes. They are held together by a test that
  runs both over the same bags rather than by one calling the other, and adding a shape to one without
  the other fails it.

  Mutation testing found two coverage gaps that a green suite did not. Deleting the array segment from
  the path on the unwind passed every test, because no fixture had an offence nested inside a container
  inside an array, only inside an array directly. Removing the array cycle guard also passed, because
  the only cycle in the fixtures was an object cycle. Both are now in the corpus, along with a mutual
  cycle between an array and an object, and all six mutations of the new walk fail.

- e95bf0b: A redirect hop no longer carries the caller's query, and a cross-origin 307 or 308 that would
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

- Updated dependencies [3e054e2]
- Updated dependencies [49ad21c]
- Updated dependencies [200a5c9]
- Updated dependencies [b362710]
- Updated dependencies [aa609af]
- Updated dependencies [14ed60e]
- Updated dependencies [7de6338]
- Updated dependencies [e721fbd]
- Updated dependencies [a90709f]
- Updated dependencies [785c101]
- Updated dependencies [f8377ff]
- Updated dependencies [1eb5030]
- Updated dependencies [dfe8ae4]
- Updated dependencies [342f7e4]
- Updated dependencies [1c87ee4]
- Updated dependencies [7de3033]
- Updated dependencies [98fd326]
- Updated dependencies [f1d6d96]
- Updated dependencies [5950b87]
- Updated dependencies [b92ff33]
- Updated dependencies [dbb643a]
- Updated dependencies [59ace7a]
- Updated dependencies [29c6f87]
  - @platform-sec/sensitive-string-core@0.6.0

## 0.1.0

### Minor Changes

- Establish the initial public package baseline. The root changelog records the development
  history leading to this version.
