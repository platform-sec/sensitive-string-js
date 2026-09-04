# Outbound charge

One outbound HTTP call whose credential is revealed exactly once, at the wire, and is not left
behind in the objects the client hands back.

## What this shows

| Line | What it prevents |
|---|---|
| `bearer(client.apiToken)` | `Bearer [REDACTED:credential]` reaching the gateway, which returns 401 and tells nobody why |
| `sensitiveJson` | the card number existing as a loose `string` in this frame |
| `allowedHosts` | a redirect carrying the credential to a host the caller never named |
| `responseFields` | the customer's email coming back as an unclassified `string` |

## The part that is not visible in the code

The wrapper scrubs both settlement paths before this function's `await` resolves. Measured, a bare
client keeps the revealed credential on the rejection **and** on the resolution: `console.log(res)`
after a *successful* axios or got call prints it, and no error ever existed for an error handler to
catch. The error tracking integration does not help, because by then the value is a plain `string`
and `containsSensitive` returns `false`.

## Running it

```bash
PAYMENT_API_TOKEN=... TEST_CARD_NUMBER=... node --experimental-strip-types outbound-charge.ts
```

The suite beside it runs against a local recording server and asserts on the bytes that crossed the
socket, not on what the client remembers having been told.
