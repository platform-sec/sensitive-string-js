# @platform-sec/sensitive-string-sentry

## 0.1.1

### Patch Changes

- 121c824: Stop tagging events with marker sightings this package wrote itself.

  `sensitive.marker_seen` is meant to be evidence that a _different_ integration sent a redaction
  placeholder where a value belonged, which is worth an operator's attention. Every breadcrumb on an
  event has already been through this package's `beforeBreadcrumb`, where structural redaction wrote a
  marker wherever a wrapped value stood, and the scope event processor was counting those: measured,
  two breadcrumbs each holding one wrapped value produced `sensitive.marker_seen: 2` on an event with
  no marker of its own. An operator following the tag would have investigated an incident that did not
  happen.

  The breadcrumbs are now walked separately with marker counting off, and their classes and denied keys
  are folded back into the event's report. The pass itself is kept, because it is what catches a
  breadcrumb an event processor registered before this one added straight to `event.breadcrumbs`.

  Also adds a transport-level case to the suite: one canary sweep driven through the SDK's own HTTP
  transport to a server on loopback, asserting on the serialized envelope bytes rather than on the
  envelope object a capturing transport receives.

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

## 0.1.0

### Minor Changes

- Establish the initial public package baseline. The root changelog records the development
  history leading to this version.
