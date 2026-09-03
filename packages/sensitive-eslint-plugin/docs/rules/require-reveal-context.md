# require-reveal-context

Require an audit context on `reveal()`, from an argument or an enclosing
`withRevealContext()`.

Severity in `recommended`: **warn**.

## Why

The audit hook records that a value was read. Without a context it cannot record
*who* read it or *why*, which is the part an incident review needs.

## Examples

Incorrect:

```js
const raw = secret.reveal();
secret.reveal(undefined);
```

Correct:

```js
const raw = secret.reveal({ name: 'payment', reason: 'charging the card' });

await withRevealContext({ name: 'handler' }, async () => {
  const raw = secret.reveal(); // context comes from AsyncLocalStorage
});
```

## Options

| Option | Default |
|---|---|
| `requireReason` | `false` |
| `contextFunctions` | `withRevealContext`, `withAuditedReveals` |

`requireReason: true` additionally reports a context object literal with no
`reason` key. An object built elsewhere, or one carrying a spread, is left
alone: reading what it contributes needs type information this rule does not
have, and warning on a context that is very likely complete would train people
to disable the rule. The `strict` preset sets it.

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
types.
