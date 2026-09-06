# require-reveal-context

Require an audit context on `reveal()`, and on `hash()` and `hmac()` where types
are available, from an argument or an enclosing `withRevealContext()`.

Severity in `recommended`: **warn**.

## Why

The audit hook records that a value was read. Without a context it cannot record
*who* read it or *why*, which is the part an incident review needs.

`hash()` and `hmac()` are read the same way by the library: they reach the raw
value through the same gate, charge the same reveal budget, and write the same
audit record with `operation: 'hash'` on it. A record saying a digest of a
credential was taken, with nothing about who took it, is the gap this rule
exists to close, whichever method produced it.

## Examples

Incorrect:

```js
const raw = secret.reveal();
secret.reveal(undefined);
```

```ts
// Only where types are available; see below.
const lookupKey = token.hash('sha256');
const pseudonym = email.hmac('sha256', key);
```

Correct:

```js
const raw = secret.reveal({ name: 'payment', reason: 'charging the card' });

await withRevealContext({ name: 'handler' }, async () => {
  const raw = secret.reveal(); // context comes from AsyncLocalStorage
});
```

```ts
const lookupKey = token.hash('sha256', {}, { name: 'session-lookup' });
const pseudonym = email.hmac('sha256', key, {}, ctx);
```

The context is the argument each method actually takes it in: the first for
`reveal()`, the third for `hash()`, the fourth for `hmac()`. An options object
in the position before it is not a context, and is reported as one missing.

## What needs type information

`reveal()` is matched by its name, in every configuration. `hash()` and `hmac()`
are matched only when the receiver's type can be read and is a `SensitiveString`
or something extending one.

That asymmetry is deliberate. `magician.reveal()` being reported is the standing
cost of an untyped rule, and `.reveal()` is rare enough for that to be a fair
trade. `.hash()` is not: `bcrypt`, `argon2`, `node:crypto` and half the hashing
libraries on npm have one, and a rule that reported every `.hash()` call in a
codebase would be turned off within the hour.

In a file with no program the rule stays on and checks `reveal()` alone. It does
not report the missing type information the way `no-stringify-sensitive` does,
because it is not reduced to silence: most of its job needs no types.

## Options

| Option | Default |
|---|---|
| `requireReason` | `false` |
| `contextFunctions` | `withRevealContext`, `withAuditedReveals` |
| `sensitiveTypes` | `SensitiveString` |

`requireReason: true` additionally reports a context object literal with no
`reason` key. An object built elsewhere, or one carrying a spread, is left
alone: reading what it contributes means following a value rather than naming a
type, which is not what the receiver check above does, and warning on a context
that is very likely complete would train people to disable the rule. The `strict` preset sets it.

## Why this is a warning

The enclosing-context check is lexical. It sees

```js
withRevealContext(ctx, () => secret.reveal());
```

and misses a reveal in a function that is merely *called* from inside one:

```js
withRevealContext(ctx, () => readSecret());
function readSecret() {
  return secret.reveal(); // reported, though the context is present at runtime
}
```

Following that would need a call graph. The rule is therefore wrong in the
direction of a needless warning, never a missed one, and a warning is the honest
severity for a check with that shape.

`reveal` is also matched by name, so an unrelated `magician.reveal()` is
reported. That is the standing cost of a rule that reads syntax rather than
types, and the reason `hash` and `hmac` are not matched that way.

A spread ahead of the context argument, `secret.hash(...args)`, is left alone:
which argument is the context stops being a question syntax can answer.
