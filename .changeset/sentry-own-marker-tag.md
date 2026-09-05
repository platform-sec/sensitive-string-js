---
'@platform-sec/sensitive-string-sentry': patch
---

Stop tagging events with marker sightings this package wrote itself.

`sensitive.marker_seen` is meant to be evidence that a *different* integration sent a redaction
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
