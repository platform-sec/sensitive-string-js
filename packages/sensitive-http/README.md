# @platform-sec/sensitive-string-http

The shared layer under the HTTP client integrations: one reveal walker and the plan it records, one
marker guard, one set of auth header descriptors, one scrub for both settlement paths, the redirect
and transport checks, and the response decoder.

You do not normally install this directly. Install the package for your client, which depends on this
one:

| Client                       | Package                                 |
| ---------------------------- | --------------------------------------- |
| axios                        | `@platform-sec/sensitive-string-axios`  |
| got                          | `@platform-sec/sensitive-string-got`    |
| ky                           | `@platform-sec/sensitive-string-ky`     |
| Node `fetch`, `undici.fetch` | `@platform-sec/sensitive-string-fetch`  |
| undici dispatcher            | `@platform-sec/sensitive-string-undici` |

## Why this row is different from every other integration

Everywhere else in this library, redaction fails closed. A log line loses information, a snapshot
loses information, and nobody is harmed. At the wire the caller's intent is to transmit the value,
so redaction turns a working request into a broken one with no error:

```typescript
const token = new SensitiveString(process.env.API_TOKEN!, 'credential', 'api_token');
await axios.post(
  'https://api.example.com/charges',
  { amount },
  { headers: { Authorization: `Bearer ${token}` } }
);
```

`Authorization: Bearer [REDACTED:credential]` goes out. axios does not throw, the server answers 401,
and the first person to debug it removes the `SensitiveString` and pastes the raw token back in. The
library has then made the codebase less safe than it was before anyone adopted it.

So the integration has to reveal. That is where the second problem starts.

## The measurements this package is built on

Taken against a local `node:http` server that records the raw request line, headers and body, on Node
22.15.0 with axios 1.20.0, got 16.0.0, ky 2.1.0 and undici 8.x. Every row is reproducible from the
suites in `src/__tests__/` and in each client package.

### A revealed value survives the call

| Client  | Rejection keeps it in                                                                                      | Resolution keeps it in                             |
| ------- | ---------------------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| axios   | `error.config.headers`, `error.toJSON()`, `config.url`                                                     | `response.config.headers`, `response.request`      |
| got     | `error.options.headers`, `error.options._init[n]`, `HTTPError.message` and its stack, `error.response.url` | `response.request.options`, `response.req._header` |
| ky      | `error.request.headers`, the frozen `error.options`                                                        | nothing                                            |
| `fetch` | the failure message, when the credential is in the query                                                   | nothing                                            |

Three consequences.

`console.error(err)` prints the credential, because Node's console uses `util.inspect`. That is the
most common line of error handling in any codebase.

`JSON.stringify(err)` is clean for ky and **not** for axios, whose `toJSON()` is what every
axios-aware logger and error reporter calls, nor for got 16.

The **success** path is worse than the rejection, because a successful call is the one a developer
prints while debugging something else. `console.log(res)` after a 200 through axios or got discloses
the credential, and no error ever existed for an error handler to scrub.

The error tracking integration ranked above this row does not catch any of it. Its `beforeSend` runs
`redactInStructure`, which looks for `SensitiveString` instances; the value in `error.config.headers`
is a `string`, `containsSensitive` returns `false`, and the event ships.

### A custom auth header survives a cross-origin redirect

A 302 from origin A to origin B, with four headers carrying a raw value. Two loopback servers on
different ports, which is a different origin under the scheme/host/port rule, and the second server
recording exactly what arrived:

| Client             | `Authorization` at B | `Cookie` at B | `Proxy-Authorization` at B | `x-api-key` at B       |
| ------------------ | -------------------- | ------------- | -------------------------- | ---------------------- |
| axios 1.20.0       | stripped             | stripped      | stripped                   | **forwarded verbatim** |
| got 16.0.0         | stripped             | stripped      | stripped                   | **forwarded verbatim** |
| ky 2.1.0           | stripped             | stripped      | stripped                   | **forwarded verbatim** |
| undici 8.10.1      | stripped             | stripped      | stripped                   | **forwarded verbatim** |
| Node 22.15 `fetch` | stripped             | stripped      | stripped                   | **forwarded verbatim** |

All five implement the Fetch specification, which names `Authorization`, `Cookie` and
`Proxy-Authorization` and no other header. Every provider that authenticates with a non-standard name
(`x-api-key`, `api-key`, `X-Auth-Token`, `PRIVATE-TOKEN`) is outside that rule. "Reveal at the wire"
is incomplete, because the wire is not a point: it is a sequence of hosts chosen partly by the server.

When the hosts cannot be named in advance, `allowedHosts: 'strip'` is the third answer. The wrapper
follows the redirect and removes every header that carried a wrapped value the moment the hop leaves
the origin, so the request finishes and the credential does not travel. The list of names to drop is
derived from the request rather than enumerated: the caller decided what a credential was when they
wrapped it, so a header the library has never heard of is covered on the same terms as
`Authorization`. It is never a default, because a request that quietly continues without its
credential succeeds at doing less than it appears to.

Two things a header-shaped mode cannot strip are handled on their own terms. The caller's query is
sent on the first hop only, under every policy: a redirect target is the URL the server named, and
re-applying the query to it once carried a wrapped query credential to a second origin that the same
mode had just removed it from the headers of. And a cross-origin 307 or 308 that would re-send a
body carrying a wrapped value is refused with `RedirectWouldResendCredentialError` rather than
followed, because a body with one field removed is a different request; a host that is trusted with
the body can be named in `allowedHosts` instead.

The exemption those three names earn is recorded per client rather than once for every client,
because agreeing with the specification is not a property of the header. It is a property of the
implementation holding the request, and implementations disagree: a survey of Node HTTP clients found
several that forward `Authorization` across origins. `prepareRequest` takes the client as a string,
so a client this package has not measured is exempt from nothing and its requests default to
refusing redirects outright. Naming `allowedHosts` still overrides that, in either direction.

### A response body that is not JSON discloses itself

Server returns a bare API key with `content-type: application/json`:

| Decoder       | 14-character body                                                       |
| ------------- | ----------------------------------------------------------------------- |
| `JSON.parse`  | `Unexpected token 's', "sk_live_abc123" is not valid JSON`              |
| got `.json()` | the same, plus ` in "<full request URL>"`                               |
| ky `.json()`  | the same                                                                |
| axios         | **does not throw**; `response.data` is the raw body as a plain `string` |

axios is not better, only differently wrong: a raw secret becomes an ordinary string in application
code with no class, no label and no audit trail.

## The pipeline

Every client package runs the same eight steps in the same order.

1. Build the reveal context for this attempt.
2. Check the URL scheme and settle the redirect policy, **before** anything is revealed.
3. Log a redacted copy through `redactCopy`, if a `log` sink was given. Also before the reveal.
4. Reveal headers, query and body into a fresh structure, recording a `ScrubPlan` as it goes.
5. Run the marker guard over each outgoing representation.
6. Hand the revealed structure to the client.
7. On rejection, scrub against the plan before rethrowing.
8. On resolution, scrub against the same plan, then wrap the configured response fields.

Steps 2 and 5 are ordered that way deliberately. The scheme and host checks run before the reveal so
that a request to a host the caller never named never reveals anything at all, rather than revealing
and then declining to send.

### Why the package owns the call, rather than installing a hook

The clients disagree about which half of a request a hook can still reach:

| Client          | Hook                   | Header there              | Body there                    | Revealing in the hook fixes |
| --------------- | ---------------------- | ------------------------- | ----------------------------- | --------------------------- |
| axios           | `interceptors.request` | already a `String`        | still structured              | the body only               |
| got             | `hooks.beforeRequest`  | still an instance         | already serialized            | the header only             |
| ky              | `hooks.beforeRequest`  | mutable `Request` headers | needs a replacement `Request` | both, at a cost             |
| `fetch`, undici | none                   | n/a                       | n/a                           | nothing                     |

A hook-based design would need a different correctness argument per client for a guarantee that has
to hold uniformly, and would still leave `fetch` and undici with none. It also would not reach steps
6 to 8, which is where the measured damage is: a hook cannot scrub an error the client has not built
yet, cannot scrub a response the client has already resolved with, and cannot see the individual hops
of a redirect the client follows internally.

The cost is that each wrapper's surface is the six verbs plus a generic `request`, not the client's
full API. Each package exposes the underlying instance as `client` for the rest, and a call made
through it loses the guard.

## The marker guard

```typescript
assertNoMarker(wire, 'request body', { decodeForms: true, base64: false });
```

Three encodings, in the order the measurements put them.

**Literal.** JSON bodies, header values and plain-text bodies carry the marker verbatim.

**Percent-encoded.** Query strings and `application/x-www-form-urlencoded` bodies carry
`%5BREDACTED%3Acredential%5D`, and axios's `params` serializer produces the partly encoded
`%5BREDACTED:credential%5D`, which contains neither the literal marker nor the fully encoded one.
Decoding once covers all three, and this is on by default.

**Base64.** `Basic` auth and any caller-applied `Buffer.from(x).toString('base64')` hide the marker
completely. Base64 has three byte alignments, so the scan uses three needles, derived from the fully
determined groups of the ten-byte prefix `[REDACTED:`:

| Alignment | Determined bytes | Needle         |
| --------- | ---------------- | -------------- |
| 0 mod 3   | `[REDACTED`      | `W1JFREFDVEVE` |
| 1 mod 3   | `EDACTE`         | `RURBQ1RF`     |
| 2 mod 3   | `REDACTED:`      | `UkVEQUNURUQ6` |

Off by default, because it is a heuristic on a heuristic and the auth helpers remove the need for it
on the happy path. Turn it on with `scanBase64: true`.

`markerMatchers()` is built at call time from `getRegisteredClasses()` and each policy's `redact`,
not hardcoded, so it survives a `registerPolicy()` call that changes a format and covers a class this
package has never heard of. A policy whose redaction is **value-dependent** cannot contribute a
literal needle; two probes of different lengths detect that, and such a policy is expected to declare
a `markerPattern` regular expression, which `markerMatchers()` consults duck-typed.

### What the guard cannot see

Any encoding applied after the bytes leave this package: gzip and other content encodings, a protobuf
or MessagePack body, a stream body that is not buffered, an encrypted payload. For those the inputs
are checked before encoding, and that is what is claimed, rather than that the outgoing bytes were
checked.

## Auth headers are descriptors, not strings

```typescript
headers: {
  Authorization: bearer(token),        // SensitiveString<'credential'>
  'x-api-key': apiKey(otherToken),     // the name comes from the key
}
```

The guard can only read what this package built, so this package builds the auth headers. The reveal
and the encoding both happen inside the pipeline, in that order, with the guard run on each component
**before** it is encoded. `basic(user, password)` therefore checks both components as plain text and
the base64 needles never have to fire on the happy path.

This also removes the template-literal footgun. `` `Bearer ${token}` `` is the single most likely way
for a marker to reach a header, and it is unreachable through the helpers.

## The scrub, and what it costs

The plan records a position and the value's own **redacted** form as the walker reveals. It never
holds a raw value, which is what lets the scrub work without searching the settled object for strings
it would have to be keeping alive across the settlement path.

Two deliberate breaks in drop-in behaviour, both conditional on a **non-empty plan**, so a call site
that has not adopted a `SensitiveString` is unaffected:

- axios's `response.request` is `undefined` and `error.request` is deleted. A Node `ClientRequest`
  keeps its own copy of the header block in internal state (`_header`, and a `kOutHeaders` symbol)
  that no supported API rewrites.
- got's `response.request`, `response.req`, and the same on its errors, for the same reason one level
  deeper.

The replacement value is the class marker rather than an empty string, so an operator reading a
scrubbed log sees that a value was there and was removed, which is a different thing from the header
being missing.

`assertHeadersScrubbed` refuses to hand back an object where a planned header still holds something
other than its marker, throwing `SensitiveScrubError`. On the success path that turns a 200 into a
rejection. That is the one place these packages destroy a working call to keep a guarantee, and the
alternative is handing back an object the next `console.log` discloses.

## Redirects and transport

| `allowedHosts`                                         | Behaviour                                                                                                                                         |
| ------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| an array                                               | redirects are followed hop by hop, and one to a host outside the list rejects with `RedirectHostNotAllowedError` before the next request is built |
| `false`                                                | redirects are not followed                                                                                                                        |
| unset, credential in a non-standard header             | `false`                                                                                                                                           |
| unset, every credential in `Authorization` or `Cookie` | the client's own handling, untouched                                                                                                              |

The last row is deliberate: three independent implementations agree on stripping those two headers,
and re-implementing that would be worse than trusting them.

The scheme check is the cheap half of the same idea. A `credential` about to be revealed into a
plaintext `http://` request to a non-loopback host rejects with `InsecureTransportError` **before**
the reveal. `allowInsecureTransport: true` opts out, for a sidecar or a local proxy that terminates
TLS itself, and the option is named to be unpleasant to type. This is the only transport-level check
these packages make: they do not configure TLS, do not verify certificates beyond what the client
already does, and do not inspect the negotiated cipher.

## Failing closed

`undici.request` is the only client in the set that already refuses an unrevealed instance rather
than stringifying it. Generalized, its rule is: refuse to send something that is not what the caller
thinks it is. The wrapper sees the request before the client does, so it holds that rule for all five.

What it refuses, always and in **every environment**:

- A marker in an outgoing representation this package produced.
- A caller-built `Headers`, `URLSearchParams`, `FormData` or `Buffer` whose contents a scan finds a
  marker in. Those containers stringify on construction, so the instance is gone by the time the
  walker runs and the marker is the only evidence left. The packages accept structured `form` options
  and build the containers themselves so a caller never has to.
- A `Map`, `Set` or function value in a JSON body, which axios turns into `{}` and drops.

The rules do not weaken in production. A security guarantee that weakens in the environment where the
secrets are real is not a guarantee, and it would mean the property the suite proves is not the
property that runs.

## API

| Export                                                                                                          | What it does                                                                        |
| --------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| `prepareRequest(request, options)`                                                                              | steps 1 to 5, returning the revealed structure, the plan and the context            |
| `revealOutgoing(value, ctx, recorder)`                                                                          | the one walker; descends into class instances, refuses `Map`/`Set`, resolves cycles |
| `revealHeaders` / `revealQuery` / `revealForm`                                                                  | the header, query and form reveals, guarded                                         |
| `assertNoMarker` / `containsMarker` / `markerMatchers`                                                          | the guard                                                                           |
| `bearer` / `basic` / `apiKey` / `renderAuthHeader`                                                              | the auth descriptors                                                                |
| `PlanBuilder` / `ScrubPlan` / `scrubHeaderBag` / `scrubBody` / `scrubQuery` / `scrubUrlString` / `scrubMessage` | the scrub                                                                           |
| `assertTransport` / `resolveRedirectPolicy` / `assertHopAllowed` / `redirectMethod`                             | redirects and transport                                                             |
| `decodeJson` / `assertDecoded` / `wrapResponseFields` / `safeUrl`                                               | the response half                                                                   |
| `buildAttemptContext`                                                                                           | the per-attempt `RevealContext`                                                     |

`@platform-sec/sensitive-string-http/testing` exports `startRecordingServer` and `findMarker`, the
harness every client suite asserts bytes against.

## Context and audit

Every reveal runs under a child of the ambient context, so a call inside an Express or Fastify handler
inherits the request's context and its audit sink, with the destination added:

```typescript
{
  name: 'POST https://api.example.com/charges',
  reason: options.reason,
  tags: { sink: 'http', host: 'api.example.com', client: 'axios', attempt: 1, hop: 1 },
}
```

The context is built **per attempt**, not per call, so `tags.attempt` is meaningful and a retry storm
is visible in the audit log as what it is. `tags.hop` counts redirect hops separately, because the
two answer different questions: a retry re-sends the same request to the same host, while a hop sends
it to a host the _server_ chose. Both write the value to a socket and both are audited, so without
the second tag an audit log cannot tell one from the other.

`tags.sink: 'http'` and `tags.host` are set on every reveal, and core's destination binding reads
both: a value constructed with `destinations: { hosts: ['api.example.com'] }` is revealed by this
package toward that host and refused toward any other, with nothing configured here. A client that
knows the request will go through a proxy passes it as `proxy` on the outgoing request, a URL or a
`host[:port]`, and it is tagged as `tags.proxy`, which the same binding reads as a second machine
the bytes reach: a host-bound value refuses a proxy its list does not name. `sensitive-axios`
resolves one the way axios does; the other clients honour no proxy option and pass none. The
`allowSendToExternal` flag is **not** enforced here: neither default policy sets it, so enforcing it
would mean choosing between denying every outbound request and allowing every one, and neither
choice carries information.

## Open question: where the guard finally lives

`@platform-sec/sensitive-string-secrets/write` needs the same marker guard and today has its own
one-line copy of it. Putting it in `core` would give every integration one copy and one test suite,
at the cost of `core` growing an API only integrations use. Having `secrets` depend on `http` is
wrong: a Vault client does not want an HTTP client integration in its dependency tree, even though it
speaks HTTP. A third shared package is the honest answer and adds a package to a monorepo that
already has many. It lives here for now, and the two implementations are tested independently.
