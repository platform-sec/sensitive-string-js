# @platform-sec/sensitive-string-fetch

`fetch` integration for `SensitiveString`, covering Node 22's global `fetch` and `undici.fetch`. They
share an implementation and measured identically on every row this row's design ran against both, so
they share a package.

```bash
pnpm add @platform-sec/sensitive-string-core @platform-sec/sensitive-string-http \
         @platform-sec/sensitive-string-fetch
```

No third-party peer. Node `>=22.12.0` provides `fetch`.

## Before and after

```typescript
// Before. `new Headers({ ... })` converts in the constructor, so this sends
// `Authorization: Bearer [REDACTED:credential]` with nothing thrown.
await fetch(url, { method: 'POST', headers: { Authorization: `Bearer ${token}` },
                   body: JSON.stringify({ card: { number: cardNumber } }) });
```

```typescript
import { bearer, sensitiveFetch } from '@platform-sec/sensitive-string-fetch';

const body = await sensitiveFetch('https://api.example.com/charges', {
  method: 'POST',
  headers: { authorization: bearer(token) },
  sensitiveJson: { amount, card: { number: cardNumber } },
  allowedHosts: ['api.example.com'],
  responseFields: { 'customer.email': 'sensitive' },
}).json<{ customer: { email: unknown } }>();
```

The call resolves to the platform `Response`, and the body accessors hang off the returned promise the
way ky's do.

## `sensitiveJson` rather than `body`

A `RequestInit`'s `body` is already a serialized thing by the time `fetch` receives it, and accepting a
structured value there would mean silently ignoring a `Content-Type` the caller set. A separate option
makes the reveal-and-serialize path explicit and leaves `body` meaning what it means everywhere else:
an already-serialized payload, which this package **scans** for markers and never rebuilds.

## What it protects against

| Measured on Node 22.15.0 | What the wrapper does |
|---|---|
| a `SensitiveString` in a header object literal, in a `new Headers({...})`, as the whole body, or in a `new URLSearchParams({...})` reaches the wire as the marker | reveals before the call, and refuses a caller-built container whose contents hold a marker |
| `FormData.append(name, instance)` puts the marker in the multipart envelope | the same refusal; use the structured `form` option and let the package build it |
| a 302 to another origin forwards `x-api-key` verbatim | refuses the hop unless the host is in `allowedHosts` |
| a `.json()` on a body that is not JSON propagates `JSON.parse`'s quoted body | rewrites it to a `ResponseDecodeError` naming the request, carrying none of the body and chaining no `cause` |
| a network failure names the request URL, so a credential in the query is in the message | rewrites the message and the stack |

There is almost nothing else to scrub, and that is a measurement: a `fetch` rejection is a `TypeError`
with a `cause`, and a `Response` carries no request headers, so neither settlement path retains the
revealed value the way axios's and got's do.

## What it does not protect against

- **Encodings applied after the bytes leave the package**, including a stream body.
- **`fetch` called directly.** `sensitiveHeaders` exists for that case and comes with a warning; see
  below.
- **A browser.** `core` imports `node:async_hooks` and `node:crypto` and uses `Buffer`. This package
  is Node-only, deliberately.

## `sensitiveHeaders`, and why it comes with a warning

```typescript
const headers = sensitiveHeaders({ authorization: bearer(token), 'x-trace': traceId });
await fetch(url, { headers });
```

⚠️ **The result holds plaintext.** Do not store it, do not log it, and do not reuse it across
requests. Everything else in this package exists so that a revealed value has one owner for the length
of one call, and this hands the ownership to the caller: there is no plan, because there is no
settlement path for the package to scrub.

It exists because a caller who is not going to stop using `fetch` directly is better served by a
helper that reveals and guards than by interpolation that does neither. Whether it should exist at all
is an open question; it is in, with this warning.

## Full options

See [the shared package README](../sensitive-http/README.md). `fetch` has no built-in retry, so this
package adds none and ignores the shared `retries` option.
