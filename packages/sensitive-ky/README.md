# @platform-sec/sensitive-string-ky

ky integration for `SensitiveString`. One reveal point at the wire, the marker guard, one audit
record per attempt on a retry, and the error scrub that ky's reject-on-non-2xx default puts on a
common path rather than an exceptional one.

```bash
pnpm add @platform-sec/sensitive-string-core @platform-sec/sensitive-string-http \
         @platform-sec/sensitive-string-ky ky
```

Peer range `ky@^2.0.0`. ky 1.x is excluded: `beforeRequest` changed from `(request, options)` to a
single state object, so a hook written against 1.x receives `undefined` and throws at the first call.
Nothing else here needs a ky 2 feature.

## Before and after

```typescript
// Before. Sends `authorization: Bearer [REDACTED:credential]`.
await ky.post('charges', { headers: { authorization: `Bearer ${token}` }, json: { amount } });
```

```typescript
import ky from 'ky';
import { bearer, createSensitiveKy } from '@platform-sec/sensitive-string-ky';

const api = createSensitiveKy(ky, {
  prefix: 'https://api.example.com',
  allowedHosts: ['api.example.com'],
  responseFields: { 'customer.email': 'sensitive' },
});

const body = await api
  .post(
    '/charges',
    { amount, card: { number: cardNumber } },
    {
      headers: { authorization: bearer(token) },
    }
  )
  .json<{ customer: { email: unknown } }>();
```

`prefix` is this package's option, named after ky 2's own, because ky does not expose the defaults of
an extended instance and the wrapper needs the destination host **before** it reveals anything.

The same opacity means a wrapped value placed in `ky.extend({ headers })` is never seen by the
wrapper: measured, it reaches the wire as `[REDACTED:credential]` on every hop, revealed nowhere and
stripped by nothing. It does not compile either, since ky types those headers as strings. The
wrapper's own `headers` option is where an instance credential goes:

```typescript
const api = createSensitiveKy(ky, {
  prefix: 'https://api.example.com',
  headers: { 'x-api-key': apiKey(apiToken) },
});
```

It is merged under each call's headers and goes through the same pipeline: revealed once per
attempt, recorded in the plan, scrubbed, and under `allowedHosts: 'strip'` dropped at the origin
boundary and not refilled on a later hop. The got and axios packages read their clients' instance
defaults as well; this one cannot, so here the option is the only instance-level layer there is.

## What it protects against

Measured on ky 2.1.0 against a local recording server.

| Measured                                                                                         | What the wrapper does                                                                                        |
| ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------ |
| a `SensitiveString` in a header or a `json` body reaches the wire as `[REDACTED:credential]`     | reveals before the call                                                                                      |
| a 401 leaves the credential in `error.request.headers` and in the frozen `error.options`         | sets the named headers on the `Request` to their markers, and replaces `error.options` with a scrubbed copy  |
| a 302 to another origin forwards `x-api-key` verbatim, because ky runs on the platform's `fetch` | refuses the hop unless the host is in `allowedHosts`                                                         |
| `.json()` propagates `JSON.parse`'s quoted body                                                  | rewrites it to a `ResponseDecodeError` naming the request, carrying none of the body and chaining no `cause` |

The **success** path needs nothing, and that is a measurement rather than an omission: a `Response`
carries no request headers, so `util.inspect` on a ky response holding a revealed `Authorization`
finds nothing. ky and `fetch` are the two clients where the wrapper returns the client's own object
unchanged.

## What it does not protect against

- **Encodings applied after the bytes leave the package**, including a stream body.
- **Calls made through `api.client`**, which is ky's own instance, exposed for `ky.extend` chaining,
  `afterResponse` hooks and everything else this surface does not carry.

## One behaviour change

**`error.request.body` is `null` on a scrubbed error** when the plan named a body path or a query key.
A `Request`'s body is a consumed stream by the time an error exists and its `url` is a getter with no
setter, so the request is replaced wholesale with one built from the scrubbed URL. When the plan named
a query key, `error.response` is dropped for the same reason: a `Response`'s `url` is read-only.

## Options the wrapper owns

| Option              | What happens                                                                                                                                                          |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `retry`             | set to 0; retries are driven by the wrapper, so a retried request reveals and audits once **per attempt**. The cost is ky's `ky.retry()` control from `afterResponse` |
| `redirect`          | set to `'manual'` while the wrapper follows hops, which it does whenever a redirect policy applies                                                                    |
| `prefix`, `baseUrl` | neutralized on the outgoing call, because the URL the wrapper hands ky is already absolute                                                                            |

ky throws on every non-2xx, so a 3xx under `redirect: 'manual'` arrives as an `HTTPError` rather than
as a response. The hop loop reads the response off that error; every other status keeps ky's own
semantics.

## Full options

See [the shared package README](../sensitive-http/README.md).
