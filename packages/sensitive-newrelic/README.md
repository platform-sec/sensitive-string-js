# @platform-sec/sensitive-string-newrelic

Attribute exclusions for `newrelic`, generated in the agent's own vocabulary and exact enough that
nothing can lift them.

## The leak, and what it is not

Unlike an error tracker, this agent does not leak at stock defaults. Measured on Node 22.15.0 against
`newrelic` 14.3.10, one inbound request carrying `authorization`, `cookie`, `x-api-key`, a `?token=`
query parameter and a JSON body with a `password` field, exactly six headers reached the payload:

```
request.headers.contentType  "application/json"
request.headers.userAgent    "probe"
request.headers.host         "example.test"
request.method               "POST"
request.uri                  "/pay"
http.statusCode              "500"
```

`allow_all_headers` defaults to false, and with it false the agent iterates a hard-coded six-name
list: `accept`, `content-length`, `content-type`, `referer`, `user-agent`, `host`. Query parameters
are written at destination `NONE` and reach nothing. The body is never read.

The leak is one configuration line away, and the line is one a competent operator has a reason to
write. With `allow_all_headers: true`:

```
request.headers.authorization  "Bearer LEAKED_SECRET_abc123xyz"
request.headers.cookie         "session=LEAKED_SECRET_abc123xyz"
request.headers.xApiKey        "LEAKED_SECRET_abc123xyz"
```

Note `xApiKey`. The agent maps 50 known headers to camelCase names and puts everything else through
a fallback that title-cases each segment after the first. So an exclusion written in the spelling the
HTTP request actually used silently does nothing:

| Rule | `request.headers.xApiKey` |
|---|---|
| `attributes.exclude: ['request.headers.x-api-key']` | Still transmitted |
| `attributes.exclude: ['request.headers.xApiKey']` | Dropped |

That is the single most likely way for a hand-written exclusion list to be wrong, and translating
names is this package's main job.

## Installation

```bash
pnpm add @platform-sec/sensitive-string-newrelic
```

## Requirements

- Node.js 22.12+
- `newrelic` 14 (optional peer dependency; nothing here imports it at runtime)
- `@platform-sec/sensitive-string-core` (peer dependency)
- `@platform-sec/sensitive-string-scrub` (peer dependency)

## Quick start

```javascript
// newrelic.js
const { sensitiveAgentConfig } = require('@platform-sec/sensitive-string-newrelic');

exports.config = {
  app_name: ['payments'],
  allow_all_headers: true,
  ...sensitiveAgentConfig({
    denyKeys: ['x-internal-signature'],
    allowKeys: [{ key: 'x-request-id', reason: 'opaque correlation id, not a credential' }],
  }),
};
```

There is nothing to install into. `newrelic` 14's public API has 39 methods and none of them receives
a payload for rewriting; `setErrorGroupCallback`, the closest thing, returns a grouping string and
cannot touch attributes. So `sensitiveAgentConfig` is a pure function returning a configuration
fragment, which is also the only reason a configuration generator is testable at all.

To keep an `attributes` section you already have, pass it as the second argument:

```javascript
const base = {
  app_name: ['payments'],
  attributes: { exclude: ['request.parameters.ssn'], include: ['request.headers.xRequestId'] },
};

exports.config = { ...base, ...sensitiveAgentConfig({}, base) };
```

The generated entries are appended to yours and every other field of your `attributes` section is
carried through, so the result is a superset of both inputs.

## Why the rules are exact

This is the finding that shapes the package, and it is not visible from New Relic's documentation.
Rules are prefix matches with a trailing `*` and nothing else, and the agent resolves include against
exclude by **match strength**: an exact match scores `Infinity` and a wildcard scores its matched
length. Measured against the shipped `AttributeFilter`, with the destinations
`request.headers.authorization` survived to:

| Configuration | Destinations |
|---|---|
| Defaults | all five enabled |
| `exclude: ['request.headers.*']` | none |
| plus `include: ['request.headers.authorization']` | **all five, restored** |
| `exclude: ['request.*']` plus `include: ['request.headers.*']` | **all five, restored** |
| `exclude: ['request.headers.*']` plus `error_collector.attributes.include: [...]` | **ERROR_EVENT only** |
| `exclude: ['request.headers.authorization']` plus the same include | none |
| `attributes.enabled: false` | none |

A wildcard exclusion is a default, not a floor. Any include that matches more specifically lifts it,
whether that include is global or scoped to one destination, and a longer wildcard beats a shorter
one. An **exact** global exclusion is a floor: the agent returns false on it before evaluating any
include at all.

So the generator emits exact entries wherever it can name a position, and one wildcard only if you
ask for it. For each denied key it writes:

```
request.headers.<translated>     and the raw spelling beside it
response.headers.<translated>    and the raw spelling beside it
request.parameters.<key>
<key>
```

Two exact excludes cost nothing, and `camelCase` is not injective over casing: `x-api-key` becomes
`xApiKey` and `X-API-KEY` becomes `xAPIKEY`. The generator emits every spelling it can derive rather
than guessing which one will arrive.

### Casing

The agent's rules are **case-sensitive**: `_importRules` compiles them into a `RegExp` with no `i`
flag, so an exclusion for `accesstoken` does not cover an attribute called `accessToken`. The shared
denylist is resolved lowercased, because every other matcher in this library lowercases the subject
too, so the generator reads the source lists in the casing they were written and emits both. That is
what keeps the ten camelCase defaults working: `accessToken`, `refreshToken`, `sessionId`,
`clientSecret`, `privateKey`, `confirmPassword`, `passwordConfirmation`, `secretKey`, `secretToken`
and `idToken`, each of which is in the list in that casing precisely because that is how it appears
in a JavaScript payload.

Your own `denyKeys` are emitted in the casing you write them, plus lowercased. A custom attribute or
a query parameter whose name differs from both, `ACCESS_TOKEN` say, needs its own
`attributes.exclude` line; the package cannot enumerate casings it was never given.

### The one wildcard

`excludeAllRequestHeaders: true` adds `request.headers.*`, for excluding headers wholesale rather
than by name. It is off by default and it is **beatable**, per the table above: one later `include`
line, added months afterwards for an unrelated reason, silently reopens it. The exact rules stay
alongside it and cannot be reopened that way.

## Recording a wrapped value as an attribute

Measured, `VALID_ATTR_TYPES` is `string`, `number`, `boolean`, and an attribute of any other type is
dropped with a debug log and nothing else:

| Attribute value | Reached the payload |
|---|---|
| Raw string | Yes, verbatim |
| Number | Yes |
| `SensitiveString` | No. Silently dropped |
| `serialize()` result | No. Silently dropped |
| `{ token: secret, rawToken: canary }` | No. Silently dropped, raw member included |

That is safe, and it is also a papercut: you add a wrapped value expecting `[REDACTED:credential]`,
get an attribute that does not exist, find out in production, and the obvious fix a hurried engineer
reaches for is `reveal()`. So:

```typescript
import { sensitiveAttributes } from '@platform-sec/sensitive-string-newrelic';

newrelic.addCustomAttributes(sensitiveAttributes({
  tenant: tenantId,
  token: apiToken,        // a SensitiveString
  session: serializedTok, // a serialize() result
}));
```

It runs the shared walk, then coerces what is left to the agent's three types, so a wrapped value
arrives as its marker rather than as nothing. It never reveals. A structure that is still not a
scalar afterwards is JSON-encoded rather than dropped, because by then both stages have run and there
is nothing left in it to leak; a cycle or a throwing `toJSON` is omitted with its key.
`attributes.value_size_limit` truncates at 256 characters by default, which is data loss and not a
redaction.

This is opt-in. An application that never calls it is exactly as safe, just less informative.

## What it cannot reach

**Log forwarding, which is the one default-on egress in the agent.** Both
`application_logging.enabled` and `application_logging.forwarding.enabled` default to true, so an
application using an instrumented logger ships its log records to New Relic with no opt-in anywhere.
A wrapped value in a log line is the marker by the time it is written and is safe; a revealed one is
an ordinary string and is not. No part of this package can reach it: by the time a log record exists
the value is a string like any other. The controls are the linting and logger-serializer rows of this
library's roadmap, and neither is complete. Set
`application_logging.forwarding.enabled: false` if that is not acceptable.

**Anything the agent captures that is not an attribute.** Metric names, transaction names, SQL
captured by the datastore instrumentation under `record_sql`, and slow query traces are separate
paths with separate configuration: `transaction_tracer.record_sql`,
`slow_sql.enabled`, `transaction_tracer.explain_enabled`.

**The browser agent.** `getBrowserTimingHeader` injects a script that reports from the user's
browser. `browser_monitoring.attributes.enabled` is off by default, and turning it on sends
attributes to a context this library has no presence in at all.

**Distributed tracing headers.** The outbound `newrelic` and `traceparent` headers carry account and
trace identifiers rather than application data, and are out of scope.

**Anything the application revealed.** Wrapping copies the value; a `reveal()` result is an ordinary
string and nothing here can tell it from any other.

## Version coupling

Two things are reproduced from private modules of the agent rather than imported: its
`HEADER_ATTR_NAMES` map and its `_headerToCamelCase` fallback. Importing a private module to compute
a security-critical list makes the package break on a refactor that would otherwise be invisible. The
test suite pins the reproduction against the shipped agent on all 50 mapped names plus a fixture set
of shapes outside the map, so a vendor change fails a test here rather than going unnoticed in a
generated configuration.

The rule engine's strength ranking, which is what makes exact rules a floor, is also internal. The
destination matrix above is a test, driven through the agent's own `AttributeFilter`.

## Testing

No test contacts New Relic. The suite runs the real agent in its serverless mode, one process per
case, and decodes the gzipped payload it would otherwise have posted to the collector, plus direct
calls into the shipped `AttributeFilter` for the destination rows.

The canary sweep runs each position twice, once with the generated configuration and once without,
and the unscrubbed run is required to leak.

## Related

- [`@platform-sec/sensitive-string-datadog`](../sensitive-datadog) is the other half of this row.
- [`@platform-sec/sensitive-string-sentry`](../sensitive-sentry) is the error tracker with the same
  shared denylist under it.
- [`@platform-sec/sensitive-string-scrub`](../sensitive-scrub) owns the denylist, the walk and the
  never-throw contract.
