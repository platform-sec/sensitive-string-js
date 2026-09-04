# @platform-sec/sensitive-string-sentry

Scrubbing for `@sentry/node`, at every seam the SDK offers rather than the one that is famous.

## The leak

Measured on Node 22.15.0 against `@sentry/node` 10.73.0, stock defaults, no `sendDefaultPii`, no
`dataCollection`, one inbound request:

```
request.headers.authorization  "Bearer LEAKED_SECRET_abc123xyz"
request.headers.cookie         "session=LEAKED_SECRET_abc123xyz"
request.cookies.session        "LEAKED_SECRET_abc123xyz"
request.url                    "http://127.0.0.1:8080/pay?token=LEAKED_SECRET_abc123xyz"
request.query_string           "token=LEAKED_SECRET_abc123xyz"
```

The application never wrapped any of it, so there is no `SensitiveString` anywhere in that event and
nothing for the library to redact. The bearer token left the process because an error happened.

An error tracker is the one dependency in a production service whose entire purpose is to collect
application state and send it somewhere else. Every other integration leaks when the application
makes a mistake. This one leaks when the application does nothing at all.

## Installation

```bash
pnpm add @platform-sec/sensitive-string-sentry
```

## Requirements

- Node.js 22.12+
- `@sentry/node` 10 (peer dependency)
- `@platform-sec/sensitive-string-core` (peer dependency)
- `@platform-sec/sensitive-string-scrub` (peer dependency)

Core is a peer dependency rather than a regular one on purpose. Structural redaction is nothing but
`instanceof` checks, and two copies of core in `node_modules` make every one of them miss.

## Quick Start

```typescript
import * as Sentry from '@sentry/node';
import { withSensitiveScrubbing } from '@platform-sec/sensitive-string-sentry';

Sentry.init(
  withSensitiveScrubbing(
    {
      dsn: process.env.SENTRY_DSN,
      beforeSend(event) {
        return event; // composed, not replaced
      },
    },
    {
      denyKeys: ['x-internal-signature'],
      onScrub: (report) => metrics.increment('sentry.scrub', report.deniedKeys.length),
    }
  )
);
```

The headers, cookies and query parameter above close with no configuration. A key name outside the
default list needs one line in `denyKeys`, and making that line the only one is the package's job.

## Why an options wrapper and not an integration

The measurements force it, and two ordering bugs are available on day one to anyone told to "add
this integration".

An integration cannot cover `beforeBreadcrumb`, which is a client option rather than an integration
hook. And an integration's `processEvent` runs in registration order: an integration listed before
`extraErrorDataIntegration()` does not see the `contexts.<ErrorName>` it writes, and one listed after
does. That context is exactly where a custom property on a thrown error lands, raw values included.

A scope event processor runs after every integration's `processEvent`, and an integration can
register one from its own `setup()`. So `withSensitiveScrubbing` composes the six client hooks at
`init` and appends an integration whose `setup()` registers the scope processor, which takes the last
position regardless of where your `integrations` array puts it. The SDK's own source says the same
thing: scope event processors run after client ones.

## The hook map

Measured on `@sentry/node` 10.73.0. "Sees live instances" decides whether structural redaction has
anything to act on there; the denylist runs everywhere either way.

| Seam | Sees live instances |
|---|---|
| Scope event processor, registered from `setup()` | Yes |
| `beforeBreadcrumb` | Yes |
| `beforeSendLog` | Yes |
| `beforeSendMetric` | Yes |
| `beforeSend` | No, normalized already |
| `beforeSendTransaction` | No |
| `beforeSendSpan` | No |

The last two rows in the "yes" column are worth noting: the design for this package recorded
`beforeSendLog` and `beforeSendMetric` as unmeasured and assumed they were normalized. They are not.
Structural redaction runs at every seam anyway, because "already normalized" is a property of one
version rather than a documented contract.

`beforeSend` is the backstop rather than the reporting seam. The scope processor already scrubbed and
reported the event, so `beforeSend` scrubs again without reporting, which keeps one payload to one
report. It is what catches anything an event processor registered after `init` added.

A seventh `before*` hook in a future SDK release fails `pnpm typecheck` with the new hook's name in
the failure, rather than opening quietly.

### Spans

Spans need three notes, all measured.

**Their URLs are not in `request.url`.** One `http.get` to `/pay?token=SECRET&page=2` puts the token
into five span attributes: `url.full`, `http.url`, `http.target`, `http.query` and `url.query`. All
five are scrubbed, and a test drives a real outbound request and asserts the SDK is not using a
sixth.

**A span cannot be dropped.** Returning `null` from `beforeSendSpan` logs "Returning null from
`beforeSendSpan` is disallowed" and then puts the **original, unscrubbed span** into the envelope. So
this package never answers `null` there. If your own `beforeSendSpan` returns `null`, the scrubbed
span is sent rather than the raw one: your intent to drop is not honoured, because the SDK does not
offer it, but it does not become a raw send either. Use `ignoreSpans` to drop spans.

**Span streaming keeps working.** `spanStreamingIntegration` turns `traceLifecycle` back to
`'static'` when it finds a `beforeSendSpan` the SDK did not mark, and this package installs one
unconditionally. Its hook is marked, so installing it does not silently disable streaming. If you
supply your own `beforeSendSpan` without `withStreamedSpan`, the marker is deliberately not applied,
so the SDK's own warning still reaches you.

### What a failed scrub leaves behind

Per payload kind, because the SDK's tolerance for a dropped payload is per kind:

| Hook | On failure |
|---|---|
| `beforeSend` | A stub: the exception type, the grouping fields, and `sensitive.scrub_failed` |
| `beforeBreadcrumb` | A stub, so the timeline keeps its position |
| `beforeSendSpan` | A stub: the ids, timings, op and status; no `data` and no `description` |
| `beforeSendTransaction`, `beforeSendLog`, `beforeSendMetric` | Dropped |

The last three are dropped rather than stubbed because a stub would have to be a valid payload of its
own shape, and a malformed one is worse than an absent one. Losing one is what sampling already does
routinely, and the failure still reaches you through `onScrub` with `failed: true`.

## Composition rules

- A hook you supply is composed, never replaced, and runs **after** the scrubber on the
  already-scrubbed payload, so a hook that adds context cannot add it behind the scrubber's back.
- A hook of yours returning `null` still drops the payload, with one exception: see spans below.
- A hook of yours that throws, or returns a promise that rejects, does not lose the event. The
  scrubbed payload is sent without whatever the hook meant to add.
- `withSensitiveScrubbing` is idempotent. Applying it twice returns the same object rather than
  double-wrapping the hooks or appending the integration twice.
- The options object you pass is not modified.
- `integrations` in function form is preserved, so a caller filtering the defaults still filters.

## Tags

The event carries what was found, and none of what it said:

| Tag | Meaning |
|---|---|
| `sensitive.classes` | The sensitivity classes in scope, comma separated |
| `sensitive.labels` | The labels, only when `reportLabels: true` |
| `sensitive.marker_seen` | Redaction markers found in captured data |
| `sensitive.marker_classes` | The classes those markers named |
| `sensitive.scrub_failed` | Scrubbing threw and the payload is a stub |

A marker sighting is tagged, never thrown on. See the marker rule in the `scrub` README.

One known source of a false sighting: `extraErrorDataIntegration()` normalizes a thrown error's
custom properties before any event processor runs, so a wrapped value there arrives already rendered
as its marker, indistinguishable from a marker that arrived in captured data. That integration is not
a default one, which keeps this narrow. Set `onMarker: 'ignore'` if you use it and do not want the
signal.

## `sendDefaultPii` and data collection

`withSensitiveScrubbing` throws at init if `sendDefaultPii: true` is set. It enables every collection
category, bodies included, and in v10 it is deprecated with a version-dependent interaction with
`dataCollection`. Say what you want explicitly instead.

`@sentry/core` 10.73.0 replaced `sendDefaultPii` with a `dataCollection` object of per-category
switches. Read the defaults against the measurement at the top of this file: `sendDefaultPii` defaults
to `false`, and headers, cookies and query strings were still captured verbatim, because these
category defaults are what governs collection. An operator who has read the `sendDefaultPii`
documentation and concluded that no PII is sent has concluded something the SDK does not do.

This package does not set them. It exports an object to spread:

```typescript
import { recommendedDataCollection } from '@platform-sec/sensitive-string-sentry';

Sentry.init(withSensitiveScrubbing({ dsn, dataCollection: recommendedDataCollection }, policy));
```

It turns off `cookies` (a cookie jar is credentials by construction and no key list describes the
names), `httpBodies` (arbitrary application shape, where a key denylist is weaker than not
collecting), `databaseQueryData` (a query parameter has no name to match on), and `genAI` (prompts
and completions, which this package has no scrubber for). Headers and query parameters stay on and
are scrubbed by name, because they are most of what makes a report actionable.

Silently changing what an error tracker collects is a large behavioural change to make on your behalf
from inside a scrubbing package, and if you find your events emptier than expected you must be able
to find the line that did it in your own code.

## Local variables

`includeLocalVariables` is off by default and this package neither enables nor disables it. Enabling
it opens the Node inspector in the process, which is a deployment decision well outside a scrubbing
library.

If it is on, the denylist runs over `frame.vars` like any other structure, catching `opts.rawToken`
as readily as a top-level `rawToken`. Names are the only handle at any depth, and the SDK's own
documentation notes that minifiers rename locals, so name filtering is unreliable in a bundled build.

Worth knowing either way: with local variable capture on, a wrapped value is reported as
`"<SensitiveString>"` and a raw string beside it is reported in full. Sentry's capture asks the V8
inspector for own properties only, so the ES2022 private field is never requested. That is a property
of the current SDK rather than a guarantee, which is why it is a measurement in a design document and
not a promise here.

## Not covered

- **What an event processor registered after `init` adds.** Scope processors run in registration
  order, so one your application registers after `withSensitiveScrubbing` runs after this package's.
  `beforeSend` is the backstop and still catches a denied key name there; a key name outside the
  denylist added that late is genuinely not covered. There is a test asserting this gap by executing
  it, so this paragraph and the behaviour cannot drift apart.
- **Sessions, client reports, attachments, profiles and replays**, which do not pass through the six
  `before*` options. An attachment is arbitrary bytes that this package will not open.
- **Server-side scrubbing is not a substitute.** Sentry's project-level data scrubbing runs after the
  payload arrives at Sentry, by which point the value has crossed the network and been written to
  somebody else's disk.
- Everything under **Not covered** in the `scrub` README applies here too.

## License

MIT
