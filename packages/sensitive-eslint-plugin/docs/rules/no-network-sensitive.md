# no-network-sensitive

Disallow sending an unaudited revealed value in a network request.

Severity in `recommended`: **error**.

## Why

Sending a secret to another service is sometimes exactly right: that is what an
`Authorization` header is. What should never happen is sending one *by
accident*, with no record that it left the process.

So the rule does not forbid transmission. It forbids transmission that nothing
audited.

## Examples

Incorrect:

```js
fetch(url, { body: secret.reveal() });
axios.post(url, { token: token.reveal() });
fetch(`https://api.example/?token=${token.reveal()}`);
superagent.post(url).send({ token: token.reveal() });

// A placeholder is not an audit context.
fetch(url, { body: secret.reveal(undefined) });
```

Correct:

```js
// The wire format, which keeps the shape under the library's control.
fetch(url, { body: JSON.stringify({ token: token.serialize() }) });

// A deliberate, recorded transmission.
fetch(url, { headers: { Authorization: token.reveal({ name: 'auth-header' }) } });
```

## Options

| Option | Default |
|---|---|
| `networkFunctions` | `fetch`, `$fetch`, `axios`, `got`, `ky`, `superagent`, `undici`, `http`, `https`, `XMLHttpRequest` |
| `allowWithContext` | `true` |

`allowWithContext: false` removes the exemption, so the only way a value leaves
the process is `serialize()`. The `strict` preset sets it.

`request` is deliberately absent from the defaults even though the library of
that name exists: Fastify calls its request object `request`, so the name
appears throughout handler code that sends nothing anywhere. Add it back through
`networkFunctions` in a project that uses the library.

## A resolved ambiguity

The roadmap's rule table describes this rule as catching any `reveal()` inside a
`fetch`, while the design document lists

```js
fetch(url, { headers: { Authorization: token.reveal({ name: 'auth-header' }) } });
```

among its examples of correct code. Both cannot hold. The design document has
the better of it, for the reason above, and `allowWithContext: false` is there
for a service that needs the stricter reading.

## Known limits

- A client reached under a name not in `networkFunctions` is not recognised. Add
  it: `{ networkFunctions: ['fetch', 'apiClient'] }`.
- The rule cannot tell a URL argument from a body argument across libraries, so
  an audited reveal interpolated into a URL is not reported even though a secret
  in a URL also reaches proxy logs and `Referer` headers. Prefer a header.
