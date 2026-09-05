# @platform-sec/sensitive-string-bugsnag

Scrubbing for `@bugsnag/js`, at every callback the SDK offers and inside its own encoder, rather than
at one of the two.

## The leak

Measured on Node 22.15.0 against `@bugsnag/js` 8.10.0, stock settings, driving the real SDK to an
HTTP server on loopback standing in for the notify endpoint:

```
request.headers.authorization   "Bearer LEAKED_SECRET_abc123xyz"
request.headers.cookie          "session=LEAKED_SECRET_abc123xyz"
request.url                     "http://127.0.0.1:8080/pay?token=LEAKED_SECRET_abc123xyz&page=2"
response.headers.set-cookie     "s=LEAKED_SECRET_abc123xyz"
context                         "/pay?token=LEAKED_SECRET_abc123xyz"
metaData.creds.raw_token        "LEAKED_SECRET_abc123xyz"
metaData.creds.wire.value       "LEAKED_SECRET_abc123xyz"
featureFlags[0].variant         "LEAKED_SECRET_abc123xyz"
```

Bugsnag's own `redactedKeys` caught `password`, which is its entire default list.

The application never wrapped any of the rest, so there is no `SensitiveString` anywhere in that
event and nothing for the library to redact. The bearer token left the process because an error
happened.

The `metaData.creds.wire.value` row is the one no key list closes: a `serialize()` result is a plain
object carrying the raw value by design, and that is what structural redaction is for.

## Installation

```bash
pnpm add @platform-sec/sensitive-string-bugsnag
```

## Requirements

- Node.js 22.12+
- `@bugsnag/js` 8 (peer dependency)
- `@platform-sec/sensitive-string-core` (peer dependency)
- `@platform-sec/sensitive-string-scrub` (peer dependency)

Core is a peer dependency rather than a regular one on purpose. Structural redaction is nothing but
`instanceof` checks, and two copies of core in `node_modules` make every one of them miss.

## Quick Start

```typescript
import Bugsnag from '@bugsnag/js';
import { withSensitiveScrubbing } from '@platform-sec/sensitive-string-bugsnag';

Bugsnag.start(
  withSensitiveScrubbing(
    {
      apiKey: process.env.BUGSNAG_KEY!,
      onError(event) {
        return true; // composed, not replaced
      },
    },
    {
      denyKeys: ['x-internal-signature'],
      onScrub: (report) => metrics.increment('bugsnag.scrub', report.deniedKeys.length),
    }
  )
);
```

The headers, the URL, the context and the metadata keys above close with no configuration. A key name
outside the default list needs one line in `denyKeys`, and making that line the only one is the
package's job.

## Two stages, and both are needed

`withSensitiveScrubbing` does two things, and neither replaces the other.

**It composes the three callbacks.** `onError`, `onBreadcrumb` and `onSession`. This is what reaches
live `SensitiveString` instances, the URL query parameters no key list can express, and the regions
Bugsnag's own redaction does not cover.

**It adds the resolved denylist to `redactedKeys`.** This is what reaches inside the encoder, which
runs after every callback and so catches things a callback cannot see.

The division is a measurement, not a preference. `redactedKeys` applies under exactly four payload
paths:

```
events.[].metaData   events.[].breadcrumbs.[].metaData   events.[].request   events.[].response
```

So `context`, `user`, `featureFlags`, `app`, `device` and the exception itself are the callbacks'
work alone. There is a test pinning both halves of that, because both will change.

## Which censor you see

Two different strings mean two different things, and on this vendor you will see both.

| String | Written by |
|---|---|
| `[REDACTED]` | Bugsnag's own encoder, for a `redactedKeys` match |
| `[SCRUBBED]` | This package's walk, in a region the encoder does not reach |
| `[REDACTED:<class>]` | This library, in place of a wrapped value |

A key in both lists comes out as `[REDACTED]`, because the encoder runs last. Both are equally safe.

## Composition rules

- A callback you supply is composed, never replaced, and runs **before** the scrubber. That is the
  opposite of this repository's Sentry package, and it is forced by the same reasoning: measured,
  Bugsnag runs config callbacks in registration order, so the last position the scrubber can reach is
  the end of that array, and holding it is what stops a callback of yours adding raw data behind its
  back.
- A callback of yours returning `false` still drops the event, because the chain stops there.
- A callback of yours that throws does not lose the event. Bugsnag logs it and continues, and the
  scrubber still runs.
- `withSensitiveScrubbing` is idempotent. Applying it twice returns the same object rather than
  appending a second scrubber.
- The config object you pass is not modified.
- `allowKeys` takes a key out of both stages, so a key you took back is really sent.

## The report

The event carries what was found, and none of what it said, in a `sensitive` metadata section:

| Key | Meaning |
|---|---|
| `classes` | The sensitivity classes in scope, comma separated |
| `labels` | The labels, only when `reportLabels: true` |
| `value_shapes` | The opt-in value recognizers that matched, only when `denyValues` is set |
| `marker_seen` | Redaction markers found in captured data |
| `marker_classes` | The classes those markers named |
| `scrub_failed` | Scrubbing threw and the event was stripped |

A marker sighting is recorded, never thrown on. `[REDACTED:credential]` in a captured 401 response
body means an HTTP client sent the placeholder as a bearer token; the same string in a captured SQL
parameter means an ORM persisted it. The error tracker is the one component positioned to notice.

Markers this package's own `onBreadcrumb` wrote are not counted, since they are its output rather
than evidence about anything else.

## What a failed scrub leaves behind

The event is stripped rather than dropped: the exception class and the stack frame positions survive,
so the alert still points at the right code, and everything captured goes. `sensitive.scrub_failed`
says why, and `onScrub` fires with `failed: true`, which is how you find out that the scrubber is
broken on one shape rather than discovering it through slightly smaller events.

Returning `false` from `onError` would tell Bugsnag the event was deliberately discarded, and losing
the error entirely is the outcome this avoids.

## Request and response bodies

Not censored by default. A body is arbitrary application shape and a key denylist over an arbitrary
shape is weaker than not collecting it, but Bugsnag has no collection switch to turn off: the
application or its framework plugin is what puts a body on the event. So the lever is a path denial,
and the honest place for it is your own code:

```typescript
import { BUGSNAG_BODY_PATHS, withSensitiveScrubbing } from '@platform-sec/sensitive-string-bugsnag';

Bugsnag.start(withSensitiveScrubbing(config, { denyPaths: [...BUGSNAG_BODY_PATHS] }));
```

## Not covered

- **What a per-`notify` callback adds.** `Bugsnag.notify(err, onError)` runs its callback after every
  config callback, measured, and there is no public seam after that one. `redactedKeys` still fires
  in the encoder, so a denied key name added there is still censored; a key outside the denylist
  added that late is genuinely not covered. There is a test asserting this gap by executing it, so
  this paragraph and the behaviour cannot drift apart.
- **The value an application revealed and then logged.** By the time a breadcrumb exists it is an
  ordinary string, indistinguishable from data the application meant to record.
- **Anything already in `req.headers`.** The raw header string existed before the SDK read it and
  still does afterwards. Scrubbing the outbound payload does not unwrite it.
- Everything under **Not covered** in the `scrub` README applies here too.

## Sessions

Composed for coverage rather than for a leak. Measured, the Node notifier's session payload is
`{ notifier, device: {}, app: { releaseStage, version, type }, sessionCounts }`: the user never
leaves the process on this platform. The `onSession` seam is composed anyway, because that is a
property of one version, and there is a test pinning it.

## License

MIT
