# no-credential-equality

Disallow comparing a revealed sensitive value with an equality operator.

Severity in `recommended`: **error**. Offers suggestions.

## Why

`===` on strings returns as soon as it finds a differing byte. The time it takes
is therefore a function of how long a shared prefix the two strings have, and an
attacker who can measure it can recover a credential a byte at a time.

`equals()` compares in constant time for the `credential` class, which is the
behavioural difference the class exists to express.

## Examples

Incorrect:

```js
if (password.reveal() === userInput) { grant(); }
if (token.reveal() == storedToken) { grant(); }
const differs = password.reveal() !== expected;
switch (token.reveal()) { case a: break; }
```

Correct:

```js
if (password.equals(userInput)) { grant(); }
if (token.equals(new SensitiveString(stored, 'credential'))) { grant(); }
if (password.equals(userInput, { name: 'login' })) { grant(); }
```

## `switch`

A `switch` compares its discriminant against each case in turn and stops at the
first match, which is the same leak in a different shape. It is reported under
its own message.

## Suggestions, not fixes

The rewrite is offered as an editor suggestion and never applied by `--fix`.
`--fix` rewrites files with nobody reading the diff, and the two forms are not
interchangeable: `equals()` can throw where `reveal()` did not, on an expired
value or under a policy that requires a context. That difference is the point of
the rule, and a person should accept it one call site at a time.

A context on the reveal moves into `equals()`, which takes it second:

```js
token.reveal({ name: 'login' }) === input;
// suggested: token.equals(input, { name: 'login' })
```

No suggestion is offered when:

- the call is optional-chained. `x?.reveal() === y` yields `false` when `x` is
  nullish while `x?.equals(y)` yields `undefined`, and a suggestion must not
  change which branch runs.
- a comment sits inside the comparison, which the replacement would delete.
- both sides reveal with a context each, since `equals()` has room for one.

## Known limits

- Only a reveal in operand position is reported. `password.reveal().length === 8`
  is a comparison of a length, not of a value, and is deliberately not flagged;
  the cost is that `password.reveal().trim() === input` is not flagged either.
- `[a.reveal()].includes(b)` and similar library comparisons are not reported.
