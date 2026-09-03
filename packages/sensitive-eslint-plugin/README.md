# @platform-sec/eslint-plugin-sensitive-string

Lint rules for the mistakes
[`@platform-sec/sensitive-string-core`](../sensitive-core)'s type system cannot
catch.

A type keeps a secret wrapped. It cannot stop `console.log(secret.reveal())`,
because the reveal produces an ordinary string and logging a string is ordinary
code. The same goes for `password.reveal() === input`, which type-checks
perfectly and leaks the password to a timing attack. Five rules read the shape
of the call instead.

## Installation

```bash
pnpm add -D @platform-sec/eslint-plugin-sensitive-string
```

ESLint 8.40 or newer is a peer dependency. Nothing else is: the rules work from
the syntax alone, so they run under any parser and cost nothing beyond the
parse.

## Usage

Flat config, `eslint.config.js`:

```js
import sensitive from '@platform-sec/eslint-plugin-sensitive-string';

export default [sensitive.configs.recommended];
```

eslintrc, `.eslintrc.cjs`:

```js
module.exports = {
  extends: ['plugin:@platform-sec/sensitive-string/legacy-recommended'],
};
```

Or set rules individually:

```js
{
  plugins: { '@platform-sec/sensitive-string': sensitive },
  rules: {
    '@platform-sec/sensitive-string/no-log-reveal': 'error',
    '@platform-sec/sensitive-string/no-credential-equality': 'error',
    '@platform-sec/sensitive-string/no-network-sensitive': 'error',
    '@platform-sec/sensitive-string/explicit-class': 'warn',
    '@platform-sec/sensitive-string/require-reveal-context': 'warn',
  },
}
```

The plugin's package name is `eslint-plugin-sensitive-string` under the
`@platform-sec` scope, so ESLint addresses it as
`@platform-sec/sensitive-string`.

## Rules

| Rule | `recommended` | Catches |
|---|---|---|
| [no-log-reveal](docs/rules/no-log-reveal.md) | error | `console.log(x.reveal())`, `logger.info({ k: x.reveal() })` |
| [no-credential-equality](docs/rules/no-credential-equality.md) | error | `x.reveal() === y`, `switch (x.reveal())` |
| [no-network-sensitive](docs/rules/no-network-sensitive.md) | error | `fetch(url, { body: x.reveal() })` |
| [explicit-class](docs/rules/explicit-class.md) | warn | `new SensitiveString(v)` with no class |
| [require-reveal-context](docs/rules/require-reveal-context.md) | warn | `x.reveal()` with no context and no enclosing `withRevealContext` |

## Presets

| Preset | Format |
|---|---|
| `configs.recommended` | flat |
| `configs.strict` | flat |
| `configs['legacy-recommended']` | eslintrc |
| `configs['legacy-strict']` | eslintrc |

Both formats configure the same rules at the same severities, and a test holds
them to it.

`recommended` errors on the three rules that catch a value escaping and warns on
the two that ask for more auditability. Those two each have a shape they
provably cannot see: a context installed in a caller, a class supplied through a
spread. A warning is the honest severity for a check that can be wrong.

`strict` raises everything to error, requires a `reason` in every reveal
context, and sets `allowWithContext: false` on `no-network-sensitive`, so the
only way a value leaves the process is `serialize()`.

## What is not here

The design calls for two more rules, `no-stringify-sensitive` and
`prefer-safe-log`. Both come down to deciding whether an arbitrary object
*contains* a sensitive value, which needs type information. The suggested
untyped substitute is to guess from variable names: flag `JSON.stringify(x)`
when `x` is called `token`, `secret`, `password`.

That heuristic reports the wrong lines and, worse, stays quiet on the right
ones. A rule you trust that is silent on `JSON.stringify(user)` is a rule that
made things worse. They will ship when they can run in typescript-eslint's
type-aware mode, and their documentation will say they require it.

## Suggestions, not fixes

No rule here is auto-fixable. Two offer editor suggestions, which a person
accepts one at a time:

- `no-credential-equality` rewrites `a.reveal() === b` to `a.equals(b)`,
  carrying any reveal context across into `equals()`'s second parameter.
- `explicit-class` offers each sensitivity class.

`--fix` rewrites files with nobody reading the diff, and every rewrite these
rules would make changes behaviour: `equals()` can throw where `reveal()` did
not, and a sensitivity class cannot be guessed from syntax at all.

## Precision

Every rule works from names, not types, so each has a shape it cannot see and a
shape it reports too eagerly. Each rule's documentation ends with a "Known
limits" section saying which. Two general points:

- **A logger or HTTP client under an unfamiliar name is invisible.** Both rules
  take an option naming the ones a project uses.
- **A value revealed into a variable and used later is not tracked.** Reveal at
  the point of use, which is better practice anyway: it keeps the raw string's
  lifetime as short as the library can make it.

## License

MIT
