# @platform-sec/sensitive-string-datadog

Span tag scrubbing for `dd-trace`, at the plugin hooks the agent actually offers, plus the two lists
a hook cannot reach.

## The leak, and what it is not

Unlike an error tracker, this agent does not leak at stock defaults. Measured on Node 22.15.0 against
`dd-trace` 6.14.0, one inbound `POST /pay?token=<canary>&page=2` carrying `authorization`, `cookie`,
`x-api-key` and a JSON body with a `password` field, the whole server span was three tags:

```
http.url          "http://127.0.0.1:38951/pay?<redacted>&page=2"
http.method       "POST"
http.status_code  "500"
```

No header, no body, and the query obfuscated in place so the route and `page=2` survived. If you
install this package expecting it to close a default leak, it has nothing to do.

The leak is one configuration line away, and the line is one a competent operator has a reason to
write. With `headerTags: ['authorization', 'cookie', 'x-api-key']`:

```
web.request   http.request.headers.authorization  "Bearer LEAKED_SECRET_abc123xyz"
web.request   http.request.headers.cookie         "session=LEAKED_SECRET_abc123xyz"
web.request   http.request.headers.x-api-key      "LEAKED_SECRET_abc123xyz"
http.request  http.request.headers.authorization  "Bearer LEAKED_SECRET_abc123xyz"
http.request  http.request.headers.cookie         "session=LEAKED_SECRET_abc123xyz"
http.request  http.request.headers.x-api-key      "LEAKED_SECRET_abc123xyz"
```

Note the second block. `http.request` is the **client** span, so turning header capture on to debug
inbound traffic also starts transmitting the `authorization` header of every outbound call the
service makes. The obfuscator does not help: it is a query-string transform, called on the URL only,
and nothing in the tag path consults it, so `Bearer <token>` arrives verbatim even though `bearer` is
one of its default patterns.

There is a second leak that has nothing to do with headers, and it is the one place in this library
where the structural walk is the only defence rather than defence in depth.
`span.setTag('probe', secret.serialize())`:

```
probe.klass       "credential"
probe.value       "LEAKED_SECRET_abc123xyz"
probe.label       "tok"
probe.__sensitive 1
```

Nothing on that path calls `toJSON()`. `addMixedTag` flattens an object one level with
`Object.entries`, and one level is exactly enough to reach the `value` key of a wire-format object.
The same flattening turns a plain `SensitiveString` into `probe.klass` and `probe.label`, so two
things that hold everywhere else in this library do not hold here: the redaction marker never
appears, and a label you chose is transmitted with no option involved.

## Installation

```bash
pnpm add @platform-sec/sensitive-string-datadog
```

## Requirements

- Node.js 22.12+
- `dd-trace` 6 (peer dependency)
- `@platform-sec/sensitive-string-core` (peer dependency)
- `@platform-sec/sensitive-string-scrub` (peer dependency)

Core is a peer dependency rather than a regular one on purpose. Structural redaction is nothing but
`instanceof` checks, and two copies of core in `node_modules` make every one of them miss.

## Quick start

```typescript
import tracer from 'dd-trace';
import { installSensitiveScrubbing } from '@platform-sec/sensitive-string-datadog';

tracer.init({ service: 'payments' });

installSensitiveScrubbing(tracer, {
  denyKeys: ['x-internal-signature'],
  captureHeaders: ['authorization', 'x-request-id'],
  onScrub: (report) => metrics.increment('sensitive.scrubbed', report.deniedKeys.length),
});
```

There is no options wrapper, because `tracer.init()` takes the agent's options and `tracer.use()`
takes each plugin's, and the header list this package cares about lives in the second.

Passing `authorization` to `captureHeaders`, as the example does, captures the header and then
scrubs its value. That is a real use rather than a compromise: the presence and shape of an auth
header is diagnostic and its content is not.

### Before or after `tracer.init()`

Both work, and the suite pins that they scrub identically. Prefer **before**, because a span created
between `init()` and the install is not scrubbed and there is no reason to leave that window open.

One thing changes with the order. Installing before `init()` means the resolved configuration does
not exist yet, so a `headerTags` set in `init()` cannot be read and folded into the package's list.
Nothing is lost: the package leaves the agent's own list alone rather than replacing it with an
empty one, and the hook scrubs whatever it finds. Pass `captureHeaders` if you want the list in one
place.

## What it does

| | |
|---|---|
| Censors captured request and response header values whose names are on the denylist | Plugin hooks, on the server span and the client span |
| Replaces a `SensitiveString` on a span tag with its marker, so neither the class tag nor the label is transmitted | The same hooks, plus a wrapper on manually created spans |
| Replaces a `serialize()` result before the agent's flattening can reach its `value` key | The same |
| Rewrites the denied query parameters of a URL tag, keeping the route | The same. Composes with the agent's obfuscator, which runs first |
| Widens the agent's query obfuscator with the denied key names it does not already match | Generated configuration |
| Repairs the instrumentation an early `require('http')` silently disabled | See below |

### Covered plugins

`http`, `undici`, `fetch`, `next`, `express`, `fastify`, `koa`, `connect`, `hapi`, `hono`, `restify`
and `microgateway-core`.

The framework plugins are not decoration. `dd-trace`'s `web.js` calls `setFramework`, which replaces
a request's whole plugin config with the framework plugin's, hooks and header list included, after
the span has already started. So an express-served request runs the **express** plugin's hook.
Measured, with a hook on `http` alone:

```
express.request  http.request.headers.authorization  "Bearer LEAKED_SECRET_abc123xyz"
http.request     http.request.headers.authorization  "[SCRUBBED]"
```

The server span, which is the one carrying the inbound request, keeps the raw header.

A seam test reads `dd-trace`'s shipped `index.d.ts`, resolves the interface inheritance, and fails
when a plugin offers a `hooks` option this package has no opinion about. It is weaker than a
compile-time check, because it is a runtime read of a declaration file, and it catches the same
failure: a plugin gaining a hook in a minor release and this package silently not covering it.

### The load-order repair

Requiring `http` before `tracer.init()` and never requiring it again leaves an application with **no
HTTP instrumentation at all**, silently. No warning, no error, and manually created spans in the same
process still export, so the trace payload looks healthy.

The mechanism is not the one the documented requirement implies. The agent patches the `http` module
object in place, and the pre-init reference is not a stale copy: `require('http')` before and after
`init()` returns the identical object. What is missing is not a patched reference, it is the patch.
The agent's hook sits on module loading, so it fires on a require and nothing else.

So the repair is one `require('http')` anywhere after `init()`, which repatches the shared object for
every reference already handed out. `installSensitiveScrubbing` does that for `http`, `https`,
`http2`, `net` and `dns`, each in its own `try`/`catch`.

**This is a `dd-trace` repair, not a redaction feature.** It is here because it costs nothing and
fixes the most common way a `dd-trace` deployment is quietly broken. Do not install this package for
it.

It does not transfer to ESM. There the requirement is `--import dd-trace/initialize.mjs`, the same
silence applies, and an import cannot be re-run for its side effect.

## What it reaches beyond the covered plugins

`scrubManualSpans` is on by default and wraps `startSpan`, and measured, **every** span goes through
it: `dns.lookup` and `tcp.connect` from plugins this package installs no hook on reach
`DatadogTracer.prototype.startSpan` exactly as `web.request` does. So the finish-time walk sees every
span the process creates after installation, not only the twelve plugins with hooks.

What that is worth is narrower than it sounds, and worth being precise about. A `pg` span's
`sql.query` and a `redis` span's `redis.raw_command` are walked, so a `SensitiveString` or a
`serialize()` result sitting on one is replaced, and a nested denied key inside a tag value is
censored. What is not reached is the thing those tags actually carry: a whole SQL statement under a
key called `query` is a payload under a name no denylist describes, and censoring it by name would
mean censoring every query. The controls there are the agent's own `DD_TRACE_<PLUGIN>_ENABLED` and
not putting a credential in a query.

The plugin hooks are still the primary mechanism, because they are the only way to reach the header
capture list and the query obfuscator, and because they are the seam the agent documents. They also
run first: a hook marks the span, so the finish-time walk skips it and one span produces one report.

## What it cannot reach

**The six plugins that offer hooks and are not covered yet**: `apollo`, `aws-sdk`, `elasticsearch`,
`opensearch`, `graphql` and `sharedb`. Their tags are walked at finish like any other span's; what
they do not get is a hook, so their header and variable capture is not configured through this
package. The seam test covers all of them either way, so an uncovered plugin is visible rather than
forgotten.

**Spans finished before `installSensitiveScrubbing` ran**, and every span at all if you pass
`scrubManualSpans: false`.

**Profiling payloads, the continuous profiler, live debugger snapshots, AppSec and IAST.** All off by
default, none routed through the trace payload, none reachable from a plugin hook. Turn them off
explicitly with `DD_PROFILING_ENABLED`, `DD_APPSEC_ENABLED`, `DD_IAST_ENABLED` and
`DD_DYNAMIC_INSTRUMENTATION_ENABLED` if you want them off rather than defaulted off.

**Runtime metrics and the telemetry payload.** Measured, the telemetry payload posted at startup
carried no canary, and it does carry the resolved configuration. A secret in an environment variable
the agent reports as configuration is a different problem from the one this package solves.

**The OpenTelemetry bridge.** Running `dd-trace`'s `TracerProvider` with your own `SpanProcessor`
puts you on a path where the plugin hooks still fire but attribute names come from OpenTelemetry
semantic conventions. This package's URL key list carries the OTel spellings, and the rest of its
path knowledge does not transfer.

**Anything the application revealed.** Wrapping copies the value; a `reveal()` result is an ordinary
string and nothing here can tell it from any other.

## Version coupling

Two behaviours this package depends on are internal to `dd-trace` and part of no public contract:

- `addMixedTag`'s one-level `Object.entries` flattening, which is why a `serialize()` result leaks
  and why the walk has to run before it.
- `span.context().getTags()`, which appears in no shipped type declaration. Writing a tag is public;
  reading one is not.

The second is checked once at install time against a throwaway span. If it stops working, the
package logs through `onDegraded` once and keeps censoring the header tags it knows can exist through
the public `setTag`, which is the leak this package exists for. Degrading rather than throwing is the
right response to losing a defence-in-depth layer while the primary one still stands. In that state
it cannot tell whether a given header was present, so it writes a censored tag either way: a tag
saying a credential header was censored when the request carried none is a false positive in a span,
and the alternative is a real credential in one. Manual-span scrubbing is also off in that state,
since it has nothing to read.

## Failure behaviour

No hook body throws on the ordinary path. If scrubbing a span's tags fails, every candidate tag is
overwritten with `[SCRUB_FAILED]` and the report carries `failed: true`.

The failure output is a censored bag rather than `null`, and that is forced rather than chosen.
Measured, `web.js` calls `context.config.hooks.request(span, req, res)` and then
`context.span.finish()`, discarding the return value, so `null` would mean this package writes
nothing back and the span ships with its original tags. `null` is the one answer that leaks.

`[SCRUB_FAILED]` is deliberately not the ordinary `[SCRUBBED]` censor. A reader of a span has to be
able to tell "this value was on the denylist" from "the scrubber broke and this span was emptied".

If even the censoring loop fails, the hook rethrows. Measured, the agent's response is to drop that
span: the application's request succeeds, the span and its client span are absent, a span from a
plugin with no hooks survives, and nothing leaks. That is a deliberate last resort.

A hook you supplied yourself is composed, never replaced, and runs after the scrubber on the already
scrubbed span. One that throws costs your addition, not the span.

## Testing

No test contacts Datadog. The suite runs the real agent in its own process per case, posts to a local
HTTP server standing in for the trace agent, and decodes the msgpack. Every measurement quoted above
was taken that way.

The canary sweep runs each position twice, once with scrubbing and once without, and the unscrubbed
run is required to leak. A sweep that only asserts absence keeps passing when a fixture stops
exercising anything.

Two positions cannot be asked to leak, for opposite reasons, and both have their own cases: a wrapped
tag, because the agent flattens it into a class tag rather than writing the value, and `?token=` in
`http.url`, because the agent's own obfuscator already covers it. The parameter that proves the
composed obfuscator does something is `?cookie=`, which the agent's default does not match.

## Related

- [`@platform-sec/sensitive-string-newrelic`](../sensitive-newrelic) is the other half of this row.
- [`@platform-sec/sensitive-string-sentry`](../sensitive-sentry) is the error tracker with the same
  shared denylist under it.
- [`@platform-sec/sensitive-string-scrub`](../sensitive-scrub) owns the denylist, the walk and the
  never-throw contract.
