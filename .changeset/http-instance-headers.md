---
'@platform-sec/sensitive-string-http': minor
'@platform-sec/sensitive-string-axios': minor
'@platform-sec/sensitive-string-got': minor
'@platform-sec/sensitive-string-ky': minor
---

`headers` on the wrapper's options: a typed place for an instance-level credential.

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
