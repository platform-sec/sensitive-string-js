# @platform-sec/sensitive-string-rollbar

## 0.2.0

### Minor Changes

- 38387f6: A Rollbar integration, over the shared `@platform-sec/sensitive-string-scrub` layer. Everything
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

  A `transform` you supply runs _before_ the scrubber and is called inside the guard, so a bug in
  your callback cannot disable this package.

  The seam inventory is checked against the shipped `index.d.ts` rather than at the type level,
  because `keyof Rollbar.Configuration` widens to `string` in this program and a type-level check
  against it would pass vacuously.

### Patch Changes

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
- Updated dependencies [f67efd7]
- Updated dependencies [48f6213]
- Updated dependencies [29c6f87]
  - @platform-sec/sensitive-string-core@0.6.0
  - @platform-sec/sensitive-string-scrub@0.2.0
