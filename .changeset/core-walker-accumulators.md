---
'@platform-sec/sensitive-string-core': minor
---

Take the structure walkers' accumulators out of their public signatures, and hand
`withAuditedReveals` the whole value.

`containsSensitive(obj, seen?)`, `redactInStructure(obj, seen?)` and
`sensitiveClassesIn(obj, found?, seen?)` published their recursion state as optional parameters,
documented as "(internal use)" and enforced by nothing. That is not a style point. Measured on the
built package, passing a `WeakSet` that already holds the root object made `containsSensitive`
answer `false` about a payload holding a credential, `redactInStructure` return `'[Circular]'` for
the whole payload, and a primed `found` set made `sensitiveClassesIn` report a class the payload
does not contain. The first of those is a safety check failing open, and the way a caller reaches it
is the obvious reason the parameter looked useful: share one `seen` across a walk of a related
object graph and any object already visited answers `false`.

Each walk now lives in a private function and the exported one takes the value alone. Three tests
pin the answers a stray argument used to produce, calling through a cast so an untyped caller is
covered too. `sensitiveFormat`'s record scan was the only internal user of an accumulator; it unions
the two sets it collects instead, which it could always have done, since the two walks shared no
`seen`.

`withAuditedReveals`'s callback typed its value as `{ readonly klass: string }`, so a sink written
against the convenience wrapper could not read `label` and so could not say which credential was
read, where the same sink passed to `auditReveal` directly gets the whole `ISensitiveString`. It is
the latter now. Widening a callback parameter is compatible in both directions: existing two- and
three-parameter sinks still compile.
