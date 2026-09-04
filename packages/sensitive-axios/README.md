# @platform-sec/sensitive-string-axios

axios integration for `SensitiveString`. One reveal point at the wire, the marker guard, and the
scrub that keeps a revealed credential out of the error, out of the response, and out of
`error.toJSON()`.

```bash
pnpm add @platform-sec/sensitive-string-core @platform-sec/sensitive-string-http \
         @platform-sec/sensitive-string-axios axios
```

Peer range `axios@^1.7.0`. axios 0.x is not supported: `AxiosHeaders` did not exist, and the header
normalization point this design depends on is different.

## Before and after

```typescript
// Before. Sends `Authorization: Bearer [REDACTED:credential]`, gets a 401, tells nobody why.
await axios.post('/charges', { amount, card: { number: cardNumber } },
  { headers: { Authorization: `Bearer ${token}` } });
```

```typescript
import axios from 'axios';
import { bearer, createSensitiveAxios } from '@platform-sec/sensitive-string-axios';

const api = createSensitiveAxios(axios.create({ baseURL: 'https://api.example.com' }), {
  reason: 'charge authorization',
  allowedHosts: ['api.example.com'],
  responseFields: { 'customer.email': 'sensitive' },
});

const res = await api.post('/charges', { amount, card: { number: cardNumber } }, {
  headers: { Authorization: bearer(token) },
});

res.data.customer.email; // SensitiveString<'sensitive'>, not a plain string
```

## What it protects against

Measured on axios 1.20.0 against a local recording server. Each row fails against a bare axios today,
which is what makes the suite a regression test rather than an aspiration.

| Measured | What the wrapper does |
|---|---|
| a `SensitiveString` in a header, in `params`, in a JSON body, in a `URLSearchParams` body or in `defaults.headers.common` reaches the wire as `[REDACTED:credential]` | reveals before `client.request()` is called, so `AxiosHeaders` never sees an instance |
| a `Map` in a JSON body is serialized as `{}` and the field is dropped | refuses, naming the path |
| a 401 leaves the credential in `error.config.headers`, `error.config.url`, and in `error.toJSON()` | overwrites `config`, which is what `toJSON()` reads, so both are fixed by one rewrite |
| a **200** leaves it in `response.config.headers` and in `response.request` | scrubs `config` and drops `request` |
| a 302 to another origin forwards `x-api-key` verbatim | refuses the hop unless the host is in `allowedHosts` |
| a body that is not JSON is handed back as `response.data`, a raw string, with no error | throws `ResponseDecodeError` naming the URL and the content type, carrying none of the body |

## What it does not protect against

- **Encodings applied after the bytes leave the package.** gzip, protobuf, MessagePack, a stream
  body, anything the caller encrypts. The inputs are checked before encoding; the outgoing bytes are
  not re-checked.
- **The objects the caller still holds.** The wrapper never mutates the caller's request objects, so
  an instance the caller revealed themselves before the call is theirs to manage.
- **Calls made through `api.client`.** That is axios's own instance, exposed for `CancelToken`,
  adapters, interceptors and everything else this surface does not carry. A call through it has no
  guard.
- **Memory.** As everywhere in this library, a revealed string exists in the V8 heap until it is
  collected.

## Two behaviour changes

Both are conditional on the request actually carrying a `SensitiveString`, so the wrapper can be
adopted one call site at a time. With an empty plan, axios's own response and error come back
untouched, `request` included.

**`response.request` is `undefined`, and `error.request` is deleted.** A Node `ClientRequest` keeps
its own copy of the outgoing header block in internal state (`_header`, plus a `kOutHeaders` symbol)
that no supported API rewrites. Returning it would leave the credential printable through
`util.inspect(res)` after a successful call. The response type says `undefined` so a caller who reads
it is told at compile time rather than at run time.

**A response body that is not JSON is an error** when `responseFields` is configured. axios would
have handed back the raw string. Silently handing a caller a raw secret as `response.data` is the
failure this integration exists to stop.

## Options the wrapper owns

| Option | What happens |
|---|---|
| `maxRedirects` | read as the hop budget; set to 0 on the outgoing config while the wrapper follows hops |
| `validateStatus` | wrapped **only** while following hops, so a 3xx comes back as a response for the loop to read. Every other status still goes through the caller's own predicate |
| `data`, `headers`, `params` | revealed and rebuilt; the caller's objects are not mutated |

`transformRequest` is left alone: revealing inside it would be a second reveal point for the body
only, and one reveal per outgoing value per attempt is the invariant. axios has no built-in retry, so
this package adds none and ignores the shared `retries` option.

## Full options

See [the shared package README](../sensitive-http/README.md) for `allowedHosts`,
`allowInsecureTransport`, `scanBase64`, `context`, `reason`, `log` and `responseFields`, and for the
marker guard's three encodings and what it cannot see.
