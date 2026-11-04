# @platform-sec/sensitive-string-bugsnag

## 0.2.0

### Minor Changes

- 38387f6: A Bugsnag integration, over the shared `@platform-sec/sensitive-string-scrub` layer. Everything
  below was measured on Node 22.15.0 against `@bugsnag/js` 8.10.0, driving the real SDK to a server
  on loopback and asserting on the bytes that left the process, with a companion case requiring each
  position to leak once the scrubbing is removed.

  `bugsnag` composes `onError`, `onBreadcrumb` and `onSession`, and separately unions the resolved
  denylist into `redactedKeys`. Both, because neither covers what the other does: `redactedKeys`
  defaults to the single key `password` and applies under exactly four payload paths, so `context`,
  `user`, `featureFlags`, `app` and the exception itself are the callbacks' work alone. Bugsnag's
  callback contract is to mutate the event it hands over and return a boolean, so the package projects
  the event's regions into a snapshot, scrubs that, and writes back through the SDK's own setters.
  Every write is an assignment, never a write through something the caller still holds: measured,
  `event.originalError` is the caller's own error and a `Breadcrumb` stores the metadata object
  `leaveBreadcrumb` was given by reference.

  A callback you supply runs _before_ the scrubber, which is the opposite of the Sentry package.
  Bugsnag has no second seam, so holding the last position it allows is the only way a callback of
  yours cannot add raw data behind the scrubber's back.

  The seam inventory is a type-level exhaustiveness check against the SDK's own config keys, so a
  fourth `on*` option in a future release fails `pnpm typecheck` with its name in the failure rather
  than opening quietly.

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
