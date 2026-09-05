# @platform-sec/sensitive-string-rollbar

Scrubbing for `rollbar`, on top of the best vendor defaults of the three this repository measured.

This is a thin package and it should be. The README says so rather than manufacturing value.

## What Rollbar already does

Measured on Node 22.15.0 against `rollbar` 3.1.0, stock settings, driving the real SDK to an HTTP
server on loopback:

```
request.headers.authorization   "********"
request.headers.cookie          "********"
request.url                     "http://127.0.0.1:8080/pay?token=********&page=2"
custom.password                 "********"
custom.access_token             "********"
```

25 `scrubFields`, 10 `scrubHeaders`, and a query-parameter pass over URLs, all applied before the one
seam a user can install. Nothing in this package replaces any of it.

## What it does not

```
request.headers.x-api-key       "LEAKED_SECRET_abc123xyz"
custom.outer.inner.private_key  "LEAKED_SECRET_abc123xyz"
custom.wire.value               "LEAKED_SECRET_abc123xyz"
custom.wrapped                  { klass: "credential", label: "stripe-key" }
```

Four things, and each is a different kind of gap.

**Names its lists do not carry.** `x-api-key` is not one of the ten header names, and `private_key`
is not one of the twenty-five field names, at any depth. The shared denylist in
`@platform-sec/sensitive-string-scrub` is a measured superset of Rollbar's own, with a test asserting
that against the installed package so a name the vendor adds fails a test rather than going
unnoticed.

**The wire format.** A `serialize()` result is a plain object carrying the raw value by design, and
no key list describes it. Structural redaction is what closes it.

**The flattening, which is this vendor's alone.** Rollbar rebuilds the payload from own enumerable
properties and does not honour `toJSON()`, so a `SensitiveString` arrives at every seam as
`{ klass, label }` rather than as the instance or as its marker. The value is safe either way,
because it lives in an ES2022 private field no property walk can reach. The **label is not**: it
rides out with the flattened object on every payload. Labels are off by default across this
repository, for reasons the `scrub` README gives, and this package is what makes that true on this
vendor. It recognizes the flattened shape, puts `[REDACTED:<class>]` back in its place, and routes
the label into the report where `reportLabels` governs it.

**The paths Rollbar ships but does not apply.** `requestScrubFields` is documentation on a stock
client: `scrubPaths` resolves to `undefined`. This package passes them.

## Installation

```bash
pnpm add @platform-sec/sensitive-string-rollbar
```

## Requirements

- Node.js 22.12+
- `rollbar` 3 (peer dependency)
- `@platform-sec/sensitive-string-core` (peer dependency)
- `@platform-sec/sensitive-string-scrub` (peer dependency)

Core is a peer dependency rather than a regular one on purpose. Structural redaction is nothing but
`instanceof` checks, and two copies of core in `node_modules` make every one of them miss.

## Quick Start

```typescript
import Rollbar from 'rollbar';
import { withSensitiveScrubbing } from '@platform-sec/sensitive-string-rollbar';

const rollbar = new Rollbar(
  withSensitiveScrubbing(
    {
      accessToken: process.env.ROLLBAR_TOKEN,
      transform(data) {
        // composed, not replaced
      },
    },
    { denyKeys: ['x-internal-signature'] }
  )
);
```

## The never-throw contract, which matters most here

Measured on `rollbar` 3.1.0: a `transform` that throws makes Rollbar log "Error while calling custom
transform() function. Removing custom transform()", set `options.transform = null`, and send the
**original, untransformed item**. One exception and scrubbing is off, silently, for the life of the
process, with a log line as the only evidence.

So nothing this package installs can throw, and a `transform` you supply is called **inside** the
guard. If yours throws or returns a rejected promise, the failure is swallowed here: your additions
are lost, the scrub is not, and Rollbar never learns it could disable the package. There is a test
that drives the vendor's fail-open behaviour directly so the reasoning cannot go stale.

## Composition rules

- A `transform` you supply is composed, never replaced, and runs **before** the scrubber, so it
  cannot add raw data behind the scrubber's back. With one seam, last is the only position worth
  having.
- An async `transform` is awaited before the scrub, and if it resolves to a payload object, that
  object is what gets scrubbed.
- `withSensitiveScrubbing` is idempotent, and the config object you pass is not modified.

## `scrubFields`, and who owns it

By default this package **adds to** Rollbar's list rather than replacing it. Measured, Rollbar
concatenates a supplied `scrubFields` onto its own 25, so nothing this package gets wrong about the
vendor's defaults can subtract from them.

`allowKeys` is the exception, because concatenation would put the allowed key straight back. Writing
one flips `overwriteScrubFields: true` and this package owns the list:

```typescript
withSensitiveScrubbing(config, {
  allowKeys: [{ key: 'token', reason: 'opaque request id, not a credential' }],
});
```

The reason string is required and is never transmitted. It exists so the line is reviewable in a
configuration diff. Setting `overwriteScrubFields: false` yourself alongside an `allowKeys` throws at
construction, because the two answers to "who owns the list" cannot both be honoured.

`scrubHeaders` and `scrubPaths` are always replaced, because Rollbar merges rather than concatenates
those two. The list this package passes is a superset of the vendor's, asserted by a test.

## The report

A `sensitive` key under `data.custom` carries what was found, and none of what it said:

| Key | Meaning |
|---|---|
| `classes` | The sensitivity classes in scope, comma separated |
| `labels` | The labels, only when `reportLabels: true` |
| `value_shapes` | The opt-in value recognizers that matched, only when `denyValues` is set |
| `marker_seen` | Redaction markers found in captured data |
| `marker_classes` | The classes those markers named |
| `scrub_failed` | Scrubbing threw and the payload was stripped |

Note that Rollbar copies custom data to more than one position in the payload, so `marker_seen`
counts positions rather than distinct strings.

## Not covered

- **What Rollbar adds after the seam.** `addConfiguredOptions` and `addDiagnosticKeys` run at
  transform positions 12 and 13, after `transform` at position 11. They write
  `notifier.configured_options`, which echoes the source text of your own `transform` and
  `checkIgnore`, and `notifier.diagnostic`, which carries the original error's message and stack
  verbatim. Neither carries anything captured that is not already in the body. There is a test
  asserting this gap by executing it.
- **`checkIgnore`.** It runs after every transform, as a queue predicate, so it sees an already
  scrubbed item and its return value decides whether to send rather than what to send. Nothing is
  composed there; if yours adds data to the item it is not scrubbed.
- **The value an application revealed and then logged.** By the time a telemetry entry exists it is
  an ordinary string.
- Everything under **Not covered** in the `scrub` README applies here too.

## License

MIT
