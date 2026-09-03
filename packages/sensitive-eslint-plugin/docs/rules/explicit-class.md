# explicit-class

Require an explicit sensitivity class when constructing a `SensitiveString`.

Severity in `recommended`: **warn**. Offers suggestions.

## Why

The class decides how the value redacts and whether `equals()` compares in
constant time. A value constructed without one is not a weaker secret; it is a
broken object, since the constructor takes no default.

## Examples

Incorrect:

```js
new SensitiveString(value);
new core.SensitiveString(value);

// A placeholder names no class. The suggestion overwrites it rather than
// pushing it into the `label` position, where it is accepted and means nothing.
new SensitiveString(value, undefined);
```

Correct:

```js
new SensitiveString(value, 'credential');
new SensitiveString(value, 'sensitive', 'email');
new SensitiveString(value, klass);
```

## Options

| Option | Default |
|---|---|
| `constructorNames` | `SensitiveString` |

Set it to cover a re-exported or renamed constructor.

## Relationship to the type checker

The TypeScript signature already requires the class, so in a checked TypeScript
file this rule is a second line rather than the only one. It earns its place in
JavaScript sources, at `any`-typed call sites where the checker is silent, and
in a project whose build and lint run at different times.

## Suggestions

Two are offered, one per class, and neither is applied by `--fix`. The right
class is a security decision about the value being wrapped, and nothing in the
syntax reveals it. `credential` is the one to pick for anything compared against
user input.

A construction with no arguments at all is reported without suggestions: it is
broken in a way no sensitivity class fixes.

## Known limits

A spread argument makes the argument count unknowable, so
`new SensitiveString(...args)` is not reported.
