# @platform-sec/sensitive-string-scrub

The shared layer under the error tracking and APM integrations: one payload walk, one denylist, one
never-throw contract, so several vendor packages do not grow several denylists that disagree.

You do not normally install this directly. Install the vendor package for your tracker, which
depends on this one and supplies the paths of its own payload shape.

## What the leak actually is

Not unredacted `SensitiveString` instances. Measured on Node 22.15.0 against `@sentry/node` 10.73.0,
`@bugsnag/js` 8.10.0 and `rollbar` 3.1.0, a wrapped value is already safe on every path tested,
because each vendor's terminal serialization honours `toJSON()`.

The leak is the raw strings nobody wrapped, sitting beside the wrapped ones. From one Bugsnag
payload, through the real encoder with its default `redactedKeys`:

```
metaData.creds.token      "[REDACTED:credential]"     wrapped by the application
metaData.creds.password   "[REDACTED]"                caught by the vendor's one-key default list
metaData.creds.rawToken   "LEAKED_SECRET_abc123xyz"   neither
```

That third line is what this package exists for.

## Installation

```bash
pnpm add @platform-sec/sensitive-string-scrub
```

## Requirements

- Node.js 22.12+
- `@platform-sec/sensitive-string-core` (peer dependency)

Core is a peer dependency rather than a regular one on purpose. Stage 1 is nothing but `instanceof`
checks, and two copies of core in `node_modules` make every one of them miss.

This package has no third-party runtime dependencies.

## The three stages

```
       captured payload
              |
   [1] structural redaction        wrapped values and serialize() results
              |
   [2] key and path denylist       raw strings nobody wrapped
              |
   [3] seam coverage               the payload reached a stage at all
              |
        vendor transport
```

Stage 2 is the one that closes the measured leak. Stage 1 is defence in depth with one case where it
is the only defence. Stage 3 is not a transform: it is the vendor suite's assertion that stages 1 and
2 ran on every payload shape the SDK can emit, plus a type-level check that the vendor has not
quietly grown a seventh hook.

### Stage 1 uses `redactCopy`, never `redactInStructure`

`redactInStructure` is the log-line walk. It rebuilds objects through `Object.entries`, replaces a
repeat visit with `'[Circular]'`, and drops symbol keys. A tracker event legitimately holds the same
object at two paths, so on an event carrying one object referenced twice:

| Helper | Second reference survives as |
|---|---|
| `redactInStructure` | `"[Circular]"` |
| `redactCopy` | the object |

`redactCopy` keeps prototypes, keeps shared references, and replaces a `serialize()` result with the
marker of the class it names. A `serialize()` result is the one shape `toJSON()` cannot save, because
it is a plain object carrying the raw value and `JSON.stringify` emits it faithfully.

### Stage 2, the denylist

`DEFAULT_DENY_KEYS` is the union of `rollbar` 3.1.0's three key-shaped default lists, which are the
best defaults of the three vendors measured, plus credential-bearing names those lists omit
(`proxy-authorization`, `x-api-key`, `refresh_token`, `client_secret`, `private_key` and others). A
test asserts the reproduction is still a superset of what the installed `rollbar` ships, so a vendor
adding a name fails here rather than going unnoticed.

Three rules the matcher follows:

- **Matching is on key names and paths, never on values,** unless you opt in. A scrubber that decides
  by looking at a string is a classifier, it is wrong some of the time, and the thing a user does
  about a tracker that hides values they needed is turn the scrubbing off. `denyValues` is the
  opt-in, and it is empty by default.
- **A denied value is replaced, not deleted.** An absent key and a censored key look the same to a
  reader of the event and mean different things to somebody debugging why a header was not sent.
- **`allowKeys` requires a reason string.** Removing a key from the default denylist is the one
  operation here that makes it leak more, and a config diff reading
  `allowKeys: [{ key: 'token', reason: 'opaque request id, not a credential' }]` is reviewable in a
  way that `allowKeys: ['token']` is not. The reason is not used at runtime and is not sent anywhere.

A value stage 1 already replaced keeps its marker rather than being censored over. `[REDACTED:credential]`
and `[SCRUBBED]` are equally safe and the marker says more.

## Policy

```typescript
import { resolveScrubPolicy } from '@platform-sec/sensitive-string-scrub';

const policy = resolveScrubPolicy({
  denyKeys: ['x-internal-signature'],
  allowKeys: [{ key: 'token', reason: 'opaque request id, not a credential' }],
  denyPaths: ['request.data.card'],
  urlKeys: ['request.url'],
  denyValues: ['jwt', 'bearer'],
  censor: '[SCRUBBED]',
  onMarker: 'tag',
  onMatch: 'censor',
  reportLabels: false,
  onScrub: (report) => metrics.increment('scrub', report.deniedKeys.length),
});
```

Resolution happens once, at install time. It throws there rather than on the error path, so an
unusable policy fails where the stack trace points at your `init` rather than at an event six hours
later, and the walk does no list arithmetic per payload.

`denyPaths` entries match a whole dotted path rather than segment by segment, and a `*` segment
matches exactly one segment, which is how an array element is named.

`urlKeys` names positions holding a URL. Three shapes arrive, and one outbound HTTP request produces
all three:

```
url.full      "http://127.0.0.1:8080/pay?token=SECRET&page=2"   absolute
http.target   "/pay?token=SECRET&page=2"                        a path with a query
http.query    "token=SECRET&page=2"                             a bare query string
```

The denied query parameters are replaced and the route survives, because deleting a URL from an error
event removes most of its value. A password in the userinfo component goes unconditionally: no key
name names it, and a URL carrying one carries a credential by construction.

Nothing is rewritten just to normalize it. A round trip through `URL` changes percent-encoding and
default ports, so a string with nothing denied in it comes back byte-identical.

## Matching on value shape, if you ask

`denyValues` is empty by default and this is the whole of the package's answer to "should the
denylist ever match on value shape". A bearer token forwarded into a field nobody named
`authorization` is invisible to a key list, and the shapes below are recognizable without guessing,
so they ship. They are off unless you name one.

Default-on would be wrong for a reason specific to error tracking rather than a general dislike of
false positives. A false positive censors a value an engineer needed, the tracker becomes less
useful, and the thing a user does about a tracker that is less useful is turn the scrubbing off
entirely. That trades a certain small loss for an uncertain large one.

| Name | Shape |
|---|---|
| `jwt` | Three base64url segments |
| `bearer` | An `Authorization: Bearer` value |
| `basicAuth` | An `Authorization: Basic` value |
| `pemPrivateKey` | A whole PEM private key block, header to footer |
| `awsAccessKeyId` | `AKIA`, `ASIA`, `AIDA` or `AROA` plus 16 characters |
| `githubToken` | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, or `github_pat_` |
| `slackToken` | `xoxb-` and its siblings |
| `openaiKey` | `sk-`, which several vendors have since copied |

Three rules every shipped pattern follows, each with its own test:

- **Anchored at both ends.** A pattern describes the whole value, never something found inside it.
  Censoring a log line to remove a token from the middle of it would destroy the message, and
  matching a substring is where a linear scan becomes a scan per position.
- **Linear time.** No nested quantifier over a shared character class, so a pathological subject
  cannot turn a scrub on the error path into a stall.
- **A prefix that is issued rather than chosen.** `ghp_`, `xoxb-`, `AKIA` and a PEM header are
  namespaces a vendor controls. A pattern that merely describes "looks random" is not here and should
  not be.

You can pass your own `RegExp` instead of a name. It is taken as written and reported by its source,
with `g` and `y` stripped, because those carry `lastIndex` between calls and would make the same
subject match on one payload and not the next.

The report names the shapes that matched, never the values and never where they matched: a path is a
key name your application chose and is safe on its own, but a path paired with a pattern name is a
map of where to look.

## The report

```typescript
interface ScrubReport {
  kind: PayloadKind;            // 'event' | 'breadcrumb' | 'transaction' | 'span' | 'log' | ...
  instances: number;            // wrapped values and serialize() results found
  classes: ReadonlySet<SensitivityClass>;
  labels?: readonly string[];   // only when reportLabels is on
  deniedKeys: readonly string[];
  deniedValues: readonly string[];  // the value recognizers that matched, by name
  markersSeen: number;
  markerClasses: ReadonlySet<string>;
  failed: boolean;
}
```

Classes, key names and counts. No value, masked or hashed, ever reaches a report, a tag, or
`onScrub`.

Labels are off by default. A class name comes from the policy registry, is not a value, and in a
normal application there are two of them. A label is a user-supplied string, it is high cardinality,
and the secrets manager design already forbids a derived label from carrying an account, project or
tenancy identifier. Sending labels to a third party by default would make this package the thing that
punishes a label somebody chose before that rule existed.

## Observing before censoring

```typescript
const policy = resolveScrubPolicy({
  onMatch: 'observe',
  onScrub: (report) => counts.record(report.kind, report.deniedKeys, report.deniedValues),
});
```

`onMatch: 'observe'` is a measurement mode, not an operating mode. A denylist match is left in place
and still reported, so the payload reaches the vendor as it did before this package was installed
and the report says what would have been censored. The report is the same one `'censor'` produces
for the same payload, asserted across every position in the canary sweep, and it still carries no
value.

It exists for the weeks before a denylist is trusted. An operator reads the denied key names and the
matched shapes off the reports, adds the `allowKeys` entries their application needs, and flips the
switch with a number in hand: this many events a week carried a credential-named key, this many a
token-shaped value. That number is also the one that argues for the next stage of adoption, since the
report counts the raw strings nobody wrapped, which is exactly what a wrapped value's own redaction
never sees.

It governs stage 2 only. A `SensitiveString` and a `serialize()` result are replaced under either
setting, because stage 1 touches nothing the application did not classify itself, and a wrapped
value renders its marker under every vendor's serializer regardless. On the failure path the vendor
gets the payload it handed over rather than a stub, since a mode whose promise is to change nothing
cannot replace an event; the report still says `failed`, which is where the operator learns the walk
broke on a shape before `'censor'` would have broken it in the open. A misspelt mode censors.

## The marker rule, inverted

The library's usual rule is that an integration which transmits throws if the outgoing bytes contain
`[REDACTED:`. Applied to an error tracker that is backwards. A tracker is a sink, not a wire: the
marker is the desired output and its absence is the failure.

There is still something to do about a marker, and it is not to throw. A marker in *captured* data is
evidence that a different integration failed. `[REDACTED:credential]` in a captured 401 response body
means an HTTP client sent the placeholder as a bearer token; the same string in a captured SQL
parameter means an ORM persisted it. The tracker is the one component positioned to notice, because
it is looking at the wreckage either way. So `onMarker: 'tag'`, the default, reports the count and
the classes named. Throwing would suppress the report of the very incident the marker is evidence of.

## Failure behaviour

No hook body throws. Measured on `@sentry/node` 10.73.0: a `beforeSend` that throws drops the
original event and sends a replacement describing the scrubber's own exception, and
`captureException` does not throw to the caller. That is fail-closed on content, which is right, and
a bad outcome anyway: the error the user needed to see is gone and the alert that fires names the
wrong thing.

So on an internal failure the payload is replaced by a stub the vendor package builds, carrying the
exception type, the grouping data the vendor already computed, and a tag saying the payload was
dropped because scrubbing failed. `onScrub` is called with `failed: true`, which is how an operator
finds out; a scrubber broken on one payload shape is invisible if the only evidence is a slightly
smaller event.

The stub is not the same as returning null. Null tells the vendor the payload was deliberately
discarded and it is counted as a client-side drop. Losing the error entirely is the outcome this
avoids.

A `StubBuilder` may still return null, and that is how a payload kind opts out. A stub is worth
building where the loss carries information nothing else does, which is an error report and the
position of a breadcrumb in a timeline. A span, a log line or a metric that goes missing is
indistinguishable from one that was sampled away, and a malformed stub of those shapes is worse than
an absent payload. The vendor package decides per kind, because only it knows which of its payloads
the SDK will accept a null for.

A user hook is caught whether it throws or rejects. `beforeSend` may return a promise, so a hook can
fail either way, and a rejection reaches the vendor as a dropped payload just as a throw would.

## Not covered

Stated plainly, because a security package that overstates its coverage is worse than none.

- **The vendor SDK holds its own copies.** The raw header string existed in `req.headers` before the
  SDK read it and still does afterwards. Scrubbing the outbound payload does not unwrite it.
- **A value revealed and then logged** is a plain string in a breadcrumb by the time any hook sees
  it, indistinguishable from data the application meant to record. The `no-log-reveal` rule in
  `@platform-sec/eslint-plugin-sensitive-string` catches it at build time; nothing here can.
- **Objects the walk passes through by reference.** `redactCopy` passes `Date`, `RegExp`, `URL`,
  `Error`, typed arrays and streams through untouched, and the denylist follows it rather than
  mutating anything the caller still holds. An `Error` placed in a payload with its own enumerable
  properties is the case worth knowing about: its properties serialize and are not scrubbed. A
  `Map` or `Set` is copied and redacted entry by entry; the denylist does not look inside one,
  because its entries are not property names.
- **Prototype getters, symbol keys and non-enumerable properties.** The walk visits own enumerable
  string keys, which is what `JSON.stringify` visits. A wrapped value behind any of those still
  redacts through `toJSON()` on the JSON path, but no key name reaches it.
- **Wrapping copies the value.** Everything the roadmap says under that heading applies unchanged.

## License

MIT
