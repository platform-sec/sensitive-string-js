# @platform-sec/sensitive-string-undici

undici dispatcher integration for `SensitiveString`. Covers `undici.request`, `Client`, `Pool` and
`Agent`.

```bash
pnpm add @platform-sec/sensitive-string-core @platform-sec/sensitive-string-http \
         @platform-sec/sensitive-string-undici undici
```

Peer range `undici@^7.0.0 || ^8.0.0`.

## This is the smallest package in the row, and why

undici is the only client in the measured set that **already fails closed**. Handed a
`SensitiveString`, it refuses rather than stringifying:

```
InvalidArgumentError: invalid x-secret header
InvalidArgumentError: body must be a string, a Buffer, a Readable stream, an iterable, or an async iterable
```

An application on the dispatcher API therefore discovers the problem at the first request in
development, instead of at the first 401 in production. Its message names the header and not the
value, which is correct behaviour this package leaves alone. That rule, refuse to send something that
is not what the caller thinks it is, is what the other four packages had to be built to reproduce.

## What this adds on top

```typescript
import { bearer, sensitiveRequest } from '@platform-sec/sensitive-string-undici';

const res = await sensitiveRequest('https://api.example.com/charges', {
  method: 'POST',
  headers: { authorization: bearer(token) },
  json: { amount, card: { number: cardNumber } },
  allowedHosts: ['api.example.com'],
  responseFields: { 'customer.email': 'sensitive' },
});

const charge = await res.json<{ id: string }>();
```

- The reveal, the guard and the context, so a caller gets a working request and an audit trail rather
  than an `InvalidArgumentError`.
- The redirect host policy. undici does not follow redirects by default, so the wrapper follows the
  hops itself when a policy applies, draining each hop's body before the next request is built.
- The transport check, which refuses to reveal a credential into a plaintext `http://` request to a
  non-loopback host.
- The response decoder, so `res.json()` on a body that is not JSON throws a `ResponseDecodeError`
  naming the request rather than a `SyntaxError` quoting what was probably the credential.
- The error scrub for `error.headers` and for a URL interpolated into a message.

## The dispatcher interceptor

For callers who use the dispatcher directly rather than through `sensitiveRequest`:

```typescript
import { Agent, setGlobalDispatcher } from 'undici';
import { markerGuard } from '@platform-sec/sensitive-string-undici';

setGlobalDispatcher(new Agent().compose(markerGuard()));
```

It cannot reveal. By the time a dispatch reaches an interceptor the caller has already had to produce
strings, and the instance that would have been revealed is gone. What it can do is refuse to send a
marker, in header values, in the request path, and in a string or `Uint8Array` body, which is the
guarantee that matters most in this direction and the one an interceptor is well placed to hold.

## What it does not protect against

- **Encodings applied after the bytes leave the package**, including a stream body.
- **The dispatcher API's full surface.** `sensitiveRequest` wraps `undici.request`; a caller using
  `stream`, `pipeline` or `connect` gets the interceptor's refusal and nothing else.

undici has no built-in retry, so this package adds none and ignores the shared `retries` option.

## Full options

See [the shared package README](../sensitive-http/README.md).
