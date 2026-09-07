# @platform-sec/sensitive-string-got

got integration for `SensitiveString`. One reveal point at the wire, the marker guard, one audit
record per attempt on a retry, and the scrub that keeps a revealed credential out of `options` on
both settlement paths.

```bash
pnpm add @platform-sec/sensitive-string-core @platform-sec/sensitive-string-http \
         @platform-sec/sensitive-string-got got
```

Peer range `got@^14.0.0 || ^16.0.0`. got 16 is ESM-only, requires Node 22, and dropped the named
`got` export that 14 provided alongside the default, so this package imports the default. Both majors
are covered by the suite through a `got14` dependency alias, the way `sensitive-express` covers
Express 4.

## Before and after

```typescript
// Before. Sends `authorization: Bearer [REDACTED:credential]`.
await got.post('charges', { headers: { authorization: `Bearer ${token}` }, json: { amount } });
```

```typescript
import got from 'got';
import { bearer, createSensitiveGot } from '@platform-sec/sensitive-string-got';

const api = createSensitiveGot(got.extend({ prefixUrl: 'https://api.example.com' }), {
  reason: 'billing sync',
  allowedHosts: ['api.example.com'],
  responseFields: { 'customer.email': 'sensitive' },
});

const res = await api.post('/charges', { amount, card: { number: cardNumber } }, {
  headers: { authorization: bearer(token) },
});
```

## Giving the instance a credential

got types an instance's default headers as strings, so a wrapped value or an `apiKey()` descriptor
in `got.extend({ headers })` does not compile. The wrapper's own `headers` option is the typed place
for it:

```typescript
const api = createSensitiveGot(got.extend({ prefixUrl: 'https://api.example.com' }), {
  headers: { 'x-api-key': apiKey(apiToken) },
  allowedHosts: ['api.example.com'],
});
```

It sits over got's own defaults and under each call's headers, and it goes through the same
pipeline as a call's header: revealed once per attempt, recorded in the plan, scrubbed on both
settlement paths, and under `allowedHosts: 'strip'` deleted at the origin boundary. A wrapped value
that reaches `got.extend({ headers })` at run time anyway, from JavaScript or through a cast, is
still read from `defaults.options.headers` and handled the same way.

## What it protects against

Measured on got 16.0.0 against a local recording server.

| Measured | What the wrapper does |
|---|---|
| a `SensitiveString` in a header or a `json` body reaches the wire as `[REDACTED:credential]` | reveals before the call |
| a `form` body carries `%5BREDACTED%3Acredential%5D`, which a literal-only scan misses | builds the form itself and scans the percent-encoded form |
| `searchParams` **rejects** a non-primitive, which is got failing closed | reveals into primitives before got validates, so the good error is never needed |
| a 401 leaves the credential in `error.options.headers`, in `error.options._init[n]` on got 14, in `HTTPError.message` and its stack when it is a query value, and in `error.response.url` | rewrites all of them |
| a **200** leaves it in `response.request.options.headers` and in `response.req._header` | scrubs the options and drops the request references |
| a 302 to another origin forwards `x-api-key` verbatim | refuses the hop through `beforeRedirect` unless the host is in `allowedHosts` |
| `ParseError` propagates `JSON.parse`'s quoted body **and appends the full request URL** | rewrites it to a `ResponseDecodeError` naming the request, carrying none of the body and chaining no `cause` |

got is the client that most needs the decoder rewrite: it is the one that puts the endpoint next to
the disclosed value in a single string.

## What it does not protect against

- **Encodings applied after the bytes leave the package**, including a stream body.
- **Calls made through `api.client`**, which is got's own instance, exposed for pagination, streams,
  and everything else this surface does not carry.
- **The objects the caller still holds.**

## Two behaviour changes

Both are conditional on the request actually carrying a `SensitiveString`.

**`response.request`, `response.req`, and the same on errors, are dropped.** got's `Request` is a
stream over a Node `ClientRequest`, whose `_header` holds the outgoing header block as raw text.
`util.inspect` on a got response prints `authorization: Bearer <value>` out of that buffer even after
`options.headers` has been rewritten, and no supported API rewrites it. This is the same call the
axios package makes for `response.request`.

**`error.options` is scrubbed in place, including got 14's `_init` array**, which keeps every raw
options object got was handed.

## Options the wrapper owns

| Option | What happens |
|---|---|
| `retry.limit` | set to 0; retries are driven by the wrapper, so a retried request reveals and audits once **per attempt** rather than once per call. The audit count then matches the number of times the value crossed a socket. The cost is got's retry-after handling |
| `hooks.beforeRedirect` | carries the host check. got's own redirect handling is kept, because its semantics (method rewriting on 303, body dropping) are worth keeping |
| `parseJson` | the decoder rewrite and the response field wrapping |
| `responseType` | forced to `'json'` when `responseFields` is configured |

Anything a hook throws is wrapped by got in a `RequestError` with the original on `cause`. The
wrapper unwraps it, so a refusal from this package arrives as itself.

`hooks.beforeRequest` is left alone. got is the one client where a hook could have revealed the
header correctly, but the reveal happens before the call anyway, so the guarantee is the same sentence
for all five packages, and the measured damage is after the send, where no hook runs.

## Full options

See [the shared package README](../sensitive-http/README.md).
