---
'@platform-sec/sensitive-string-rollbar': minor
---

A Rollbar integration, over the shared `@platform-sec/sensitive-string-scrub` layer. Everything
below was measured on Node 22.15.0 against `rollbar` 3.1.0, driving the real SDK to a server on
loopback and asserting on the bytes that left the process, with a companion case requiring each
position to leak once the scrubbing is removed.

`rollbar` is thin, and its README says so rather than manufacturing value. The vendor already ships
the best defaults measured and applies them before the one seam a user can install. Two findings are
what the package is actually for. Rollbar is the only SDK measured that does not honour `toJSON()`: a
wrapped value arrives at every seam as `{ klass, label }`, so its value is safe because the private
field is unreachable, and its **label was being transmitted** on every payload. The package
recognizes that shape, puts the marker back, and routes the label into the report where
`reportLabels` governs it. And a `transform` that throws makes Rollbar set `options.transform = null`
and send the original untransformed item, so one exception disables scrubbing for the life of the
process; a caller's own `transform` is therefore called inside the guard rather than beside it.

A `transform` you supply runs *before* the scrubber and is called inside the guard, so a bug in
your callback cannot disable this package.

The seam inventory is checked against the shipped `index.d.ts` rather than at the type level,
because `keyof Rollbar.Configuration` widens to `string` in this program and a type-level check
against it would pass vacuously.
