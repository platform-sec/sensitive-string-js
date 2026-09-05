---
'@platform-sec/sensitive-string-datadog': minor
---

A Datadog APM integration, over the shared `@platform-sec/sensitive-string-scrub` layer. Everything
below was measured on Node 22.15.0 against `dd-trace` 6.14.0, driving the real agent in its own
process, posting to a local HTTP server standing in for the trace agent, and decoding the msgpack,
with a companion case requiring each position to leak once the scrubbing is removed.

This row does not close a default leak, and the README says so first. Measured at stock defaults, an
inbound `POST /pay?token=<canary>&page=2` carrying `authorization`, `cookie`, `x-api-key` and a JSON
body with a `password` field produced a server span of exactly three tags: `http.url` with the query
obfuscated in place, `http.method` and `http.status_code`. No header, no body, no canary. What this
package closes is the opt-in: `headerTags` puts `authorization` and `cookie` into the payload
verbatim, and onto the client span as well as the server one, so turning header capture on to debug
inbound traffic starts transmitting the auth header of every outbound call.

`installSensitiveScrubbing` composes `hooks.request` on twelve plugins and generates two lists a hook
cannot reach. The plugin list is the correction the design did not have: `dd-trace`'s `web.js` calls
`setFramework`, which replaces a request's whole plugin config with the framework plugin's, hooks and
header list included, so an express-served request runs the **express** plugin's hook and covering
`http` alone leaves `express.request` carrying the raw header. `express`, `fastify`, `koa`,
`connect`, `hapi`, `hono`, `restify`, `microgateway-core` and `fetch` all inherit the hook at the
type level and all needed covering. A seam test reads the shipped `index.d.ts`, resolves the
interface inheritance, and fails naming any plugin that offers a `hooks` option this package has no
opinion about.

The structural walk is load-bearing here rather than defence in depth, for a reason no other vendor
in this row shares: nothing on the span tag path calls `toJSON()`. `addMixedTag` flattens an object
one level with `Object.entries`, which is exactly enough to reach the `value` key of a `serialize()`
result and put a full credential on a tag. The same flattening turns a plain `SensitiveString` into
`probe.klass` and `probe.label`, so the redaction marker never appears and a label is transmitted
with no option involved. Both are replaced before the agent sees them, on plugin spans and on spans
the application creates itself.

Two behaviours the package composes with rather than replaces. Its query obfuscator is the agent's
own default pattern, reproduced byte for byte and pinned against the shipped configuration data, with
one anchored branch appended per denied key the default does not already match. Its header capture
list keeps a denied header rather than dropping it, so the tag exists and its presence stays
diagnostic while the hook replaces the value.

`scrubManualSpans` is on by default and wraps `startSpan`, which measured is what **every** span goes
through, `dns.lookup` and `tcp.connect` included. So the finish-time walk sees every span the process
creates after installation, and the hooks stay the primary mechanism because they are the only route
to the header capture list and the query obfuscator, and because they mark the span so one span
produces one report. A throw at that seam is contained rather than propagated: a hook body is called
by the agent, which answers a throw by dropping one span, while `finish()` is called by the
application, so the last-resort rethrow is caught there, the span is emptied through `setTag`
instead, and it is finished either way.

The failure output is a censored tag bag, never `null`, and that is forced rather than chosen:
`web.js` discards a hook's return value, so `null` would mean the span ships with its original tags.
It writes `[SCRUB_FAILED]` rather than the ordinary censor, so a reader can tell a denylist hit from
a broken scrubber. If censoring itself fails the hook rethrows, and the agent's answer to that,
measured, is to drop that one span while the request succeeds and a neighbouring plugin's span
survives.

One thing in the package is not a redaction feature and the README says so. Requiring `http` before
`tracer.init()` and never requiring it again leaves an application with no HTTP instrumentation at
all, silently, and the repair is a single `require` after `init()` because the agent patches the
module object in place. `installSensitiveScrubbing` does that for five core modules, which costs
nothing and fixes the most common way a `dd-trace` deployment is quietly broken.
