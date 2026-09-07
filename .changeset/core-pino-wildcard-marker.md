---
'@platform-sec/sensitive-string-core': patch
---

Documents one case where pino loses the redaction marker, and the one-line remedy.

No code changed. This is a behaviour of pino that a user of this library will otherwise meet without
warning, and the README's pino section now describes it where someone configuring pino will read it.

With a wildcard entry in pino's `redact.paths`, a wrapped value logged as a direct property of the
merging argument serializes as `[unable to serialize, circular reference is too complex to analyze]`
rather than as its marker. Three conditions have to hold at once and dropping any one avoids it: a
wildcard in the path list, since a literal list is unaffected at any depth; a class instance carrying
an ES private field; and that instance at the top level of the log object, since one level down or
inside an array renders correctly.

Nothing is disclosed. The value does not appear in either case. What is lost is the marker, so a line
that should say a credential was present instead says the serializer gave up, and the diagnostic this
library exists to preserve is exactly the thing that goes.

It is not fixable from inside the library. The same failure reproduces with any class carrying a
`#private` field and no `toJSON` at all, and does not reproduce with the identical class without the
private field; `Date` and plain objects with a `toJSON` are unaffected. So it is not caused by
`toJSON`, and `#value` is what makes a wrapped value unreadable by reflection, which is not a
property to trade away for this.

The remedy is a `formatters.log` that converts the payload before pino's redaction machinery sees it,
and it leaves pino's own path redaction working alongside the marker.

The top-level condition sounds like it should reduce this to nothing, and does not: `logger.info(data,
msg)` is the ordinary pino idiom and puts every field of `data` at exactly that level. It was found
in two real applications that both reach it that way through their own logging wrappers.

Measured against pino 10.3.1.
