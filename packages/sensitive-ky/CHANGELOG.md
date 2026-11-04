# @platform-sec/sensitive-string-ky

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
- Updated dependencies [635b4c2]
- Updated dependencies [59d6a4b]
- Updated dependencies [612ccbd]
- Updated dependencies [aadfec7]
- Updated dependencies [e95bf0b]
- Updated dependencies [256911b]
- Updated dependencies [59ace7a]
- Updated dependencies [29c6f87]
  - @platform-sec/sensitive-string-core@0.6.0
  - @platform-sec/sensitive-string-http@0.2.0

## 0.1.0

### Minor Changes

- Establish the initial public package baseline. The root changelog records the development
  history leading to this version.
