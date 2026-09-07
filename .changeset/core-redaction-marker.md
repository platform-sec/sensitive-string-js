---
'@platform-sec/sensitive-string-core': minor
'@platform-sec/sensitive-string-http': patch
'@platform-sec/sensitive-string-secrets': patch
'@platform-sec/sensitive-string-typeorm': patch
'@platform-sec/sensitive-string-drizzle': patch
---

`containsRedactionMarker()` and `redactionMatchers()` in core, replacing four separate answers to
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
