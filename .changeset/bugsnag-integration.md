---
'@platform-sec/sensitive-string-bugsnag': minor
---

A Bugsnag integration, over the shared `@platform-sec/sensitive-string-scrub` layer. Everything
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

A callback you supply runs *before* the scrubber, which is the opposite of the Sentry package.
Bugsnag has no second seam, so holding the last position it allows is the only way a callback of
yours cannot add raw data behind the scrubber's back.

The seam inventory is a type-level exhaustiveness check against the SDK's own config keys, so a
fourth `on*` option in a future release fails `pnpm typecheck` with its name in the failure rather
than opening quietly.
