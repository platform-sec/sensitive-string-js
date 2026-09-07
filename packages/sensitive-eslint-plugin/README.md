# @platform-sec/eslint-plugin-sensitive-string

Lint rules for the mistakes
[`@platform-sec/sensitive-string-core`](../sensitive-core)'s type system cannot
catch.

A type keeps a secret wrapped. It cannot stop `console.log(secret.reveal())`,
because the reveal produces an ordinary string and logging a string is ordinary
code. The same goes for `password.reveal() === input`, which type-checks
perfectly and leaks the password to a timing attack. Seven rules read the call
instead: five from its shape alone, two from the types of its arguments.

## Installation

```bash
pnpm add -D @platform-sec/eslint-plugin-sensitive-string
```

ESLint 8.40 or newer is a peer dependency, and nothing else is. The five
untyped rules work from the syntax alone, so they run under any parser and cost
nothing beyond the parse.

The other two ask what a value's type *contains*, which no syntax answers, so
they need a TypeScript program: `@typescript-eslint/parser` with `project` or
`projectService` set. They live only in the `-type-checked` presets, so a
project that has not configured one never meets them.

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

Those six are the untyped rules. `no-stringify-sensitive` and `prefer-safe-log`
are set the same way, under a config that gives them a program: see
[Type-aware linting](#type-aware-linting).

The plugin's package name is `eslint-plugin-sensitive-string` under the
`@platform-sec` scope, so ESLint addresses it as
`@platform-sec/sensitive-string`.

## Rules

Syntax only, in `recommended`:

| Rule | `recommended` | Catches |
|---|---|---|
| [no-log-reveal](docs/rules/no-log-reveal.md) | error | `console.log(x.reveal())`, `logger.info({ k: x.reveal() })` |
| [no-credential-equality](docs/rules/no-credential-equality.md) | error | `x.reveal() === y`, `switch (x.reveal())` |
| [no-network-sensitive](docs/rules/no-network-sensitive.md) | error | `fetch(url, { body: x.reveal() })` |
| [explicit-class](docs/rules/explicit-class.md) | warn | `new SensitiveString(v)` with no class |
| [require-reveal-context](docs/rules/require-reveal-context.md) | warn | `x.reveal()` with no context and no enclosing `withRevealContext`, and the same for `mask()`, `hash()`, `hmac()` and `serialize()` where types are available |
| [no-password-fast-hash](docs/rules/no-password-fast-hash.md) | warn | `password.hash('sha256')`, a fast digest where a KDF belongs |

Type-aware, in `recommended-type-checked` only:

| Rule | `recommended-type-checked` | Catches |
|---|---|---|
| [no-stringify-sensitive](docs/rules/no-stringify-sensitive.md) | error | `JSON.stringify(payload)` where `payload` holds a `SensitiveString` or a `serialize()` result |
| [prefer-safe-log](docs/rules/prefer-safe-log.md) | warn | `console.log(user)` where `user` holds one |

## Presets

| Preset | Format | Rules |
|---|---|---|
| `configs.recommended` | flat | the six untyped |
| `configs.strict` | flat | the six untyped, harder |
| `configs['recommended-type-checked']` | flat | all eight |
| `configs['strict-type-checked']` | flat | all eight, harder |
| `configs['disable-type-checked']` | flat | turns the two type-aware rules off |
| `configs['legacy-recommended']` | eslintrc | the six untyped |
| `configs['legacy-strict']` | eslintrc | the six untyped, harder |
| `configs['legacy-recommended-type-checked']` | eslintrc | all eight |
| `configs['legacy-strict-type-checked']` | eslintrc | all eight, harder |
| `configs['legacy-disable-type-checked']` | eslintrc | turns the two type-aware rules off |

Both formats configure the same rules at the same severities, and a test holds
them to it.

`recommended` errors on the three rules that catch a value escaping and warns on
the three that reason about something they cannot see: a context installed in a
caller, a class supplied through a spread, and a password recognised by what the
variable holding it is called. A warning is the honest severity for a check that
can be wrong.

`strict` raises everything to error, requires a `reason` in every reveal
context, and sets `allowWithContext: false` on `no-network-sensitive`, so the
only way a value leaves the process is `serialize()`.

## Type-aware linting

The `-type-checked` presets add `no-stringify-sensitive` and `prefer-safe-log`
to their untyped namesakes. Both need a `ts.Program`:

```js
import sensitive from '@platform-sec/eslint-plugin-sensitive-string';
import tseslint from 'typescript-eslint';

export default [
  {
    files: ['**/*.ts'],
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
  },
  sensitive.configs['recommended-type-checked'],
  // Files no tsconfig.json covers have no types to read.
  { files: ['**/*.js'], ...sensitive.configs['disable-type-checked'] },
];
```

Applied to a file with no program, both rules report that fact once, on the
file, rather than falling silent. Silence would be the worse failure: a rule
that reports nothing looks exactly like a rule that found nothing, and these
two get read as "no sensitive value is being stringified or logged here".
`disable-type-checked` is what turns them off where that is expected.

`require-reveal-context` is a third case: it works without a program and uses
one when it is there. `reveal()` is matched by name in every configuration;
`mask()`, `hash()`, `hmac()` and `serialize()` are checked only where the
receiver's type can be read, because `bcrypt` and `node:crypto` have a `hash`,
every ORM has a `serialize`, and a rule that reported those would be turned off
within the hour. It stays enabled under `disable-type-checked`, where it does
the half of its job that needs no types.

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

Every rule that asks for an argument treats an explicit `undefined` as the
absence of one: `reveal(undefined)` and `new SensitiveString(v, undefined)`
satisfy a signature and decide nothing, so accepting them would make passing
`undefined` the shortest way to silence a rule while looking like compliance
with it.

Beyond that, every rule has a shape it cannot see and a shape it reports too
eagerly. Each rule's documentation ends with a "Known limits" section saying
which. Three general points:

- **A logger or HTTP client under an unfamiliar name is invisible.** Every rule
  that matches one takes an option naming the ones a project uses.
- **A value revealed into a variable and used later is not tracked.** Reveal at
  the point of use, which is better practice anyway: it keeps the raw string's
  lifetime as short as the library can make it.
- **The two type-aware rules match a type by its name**, so anything called
  `SensitiveString` counts and a project's own wrapper does not until
  `sensitiveTypes` names it. Resolving the declaration back to this library
  would be more precise and would break under bundlers, path aliases and
  re-exports.

## License

MIT
