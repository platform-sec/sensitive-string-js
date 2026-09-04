# @platform-sec/sensitive-string-envalid

envalid with validators that produce a `SensitiveString`, and a validation report that never prints
a value and never exits the process.

## Why envalid gets a package when dotenv, convict and node-config do not

envalid is the one library in this row with an extension point that both survives and needs typed
wiring. Its output is otherwise well behaved: a validator that returns an instance yields an instance
through `cleanEnv`, the returned object is frozen and the instance still reveals through it,
`util.inspect` renders `{ API_KEY: SensitiveString<credential:API_KEY> { [REDACTED:credential] } }`,
and `JSON.stringify` produces `{"API_KEY":"[REDACTED:credential]"}`.

Four measured problems make it a package rather than a recipe:

1. `default`, `devDefault` and `testDefault` bypass the validator entirely.
2. `choices` compares against the wrapped value, so the check is broken rather than strict.
3. The error path prints the raw input and cannot be intercepted from outside.
4. The return value is a strict proxy that throws for any name it was not given.

## Installation

```bash
pnpm add @platform-sec/sensitive-string-envalid
```

## Requirements

- Node.js 22.12+
- `envalid` 8+ (peer dependency)
- `@platform-sec/sensitive-string-core` and `@platform-sec/sensitive-string-env` (peer dependencies)

Core is a peer dependency rather than a regular one. `redactInStructure`, `containsSensitive`,
`wrapSensitiveByPath` and `deserialize` all check `instanceof`, and two copies of core in
`node_modules` make every one of those checks miss.

## Basic use

```typescript
import { port } from 'envalid';
import { cleanEnvSafe, credential, sensitive } from '@platform-sec/sensitive-string-envalid';

const env = cleanEnvSafe(process.env, {
  DB_PASSWORD: credential({ label: 'db_password' }),
  SUPPORT_EMAIL: sensitive(),
  PORT: port(),
});

env.DB_PASSWORD; // SensitiveString<'credential'>, to the type checker as well as at run time
env.PORT;        // number
```

The validators are built on envalid's own `makeValidator`, so the class parameter survives into
`env`'s inferred type. A generic factory typed as `Function` would throw that away, which is most of
the point of the integration.

The audit label defaults to the variable's own name, so an audit record says
`SensitiveString<credential:DB_PASSWORD>` rather than `SensitiveString<credential>`.

**Import `cleanEnv` from envalid directly and you get the leaking reporter back.** That is why this
package re-exports envalid's validators and makers: one import site, and a lint rule can ban the
other one. `cleanEnv` and `customCleanEnv` are deliberately not re-exported, under any name.

## `default` bypasses the validator

Measured, and stated in envalid's own source comment: when a variable is absent, `default`,
`devDefault` and `testDefault` are assigned directly and **do not pass through validation**.

```typescript
const env = cleanEnv({}, { API_KEY: credential({ default: 'dev-fallback' }) });

typeof env.API_KEY;                       // 'string'
env.API_KEY instanceof SensitiveString;   // false
JSON.stringify(env);                      // {"API_KEY":"dev-fallback"}
```

TypeScript says `SensitiveString<'credential'>`. The runtime has a raw string. Every downstream call
of `.reveal()` throws a `TypeError`, every log line prints the development key, and nothing about the
failure points at the default. This is type erosion arriving through a supported option of the
library rather than through an `as any`.

So the validators refuse all three at construction and offer their own:

```typescript
credential({ default: 'x' });           // throws, naming sensitiveDefault
credential({ sensitiveDefault: 'x' });  // wrapped, same class and label as a parsed value
```

The raw string goes down as envalid's own `default`, which keeps the variable from being reported
missing, and `cleanEnvSafe` wraps the result afterwards for exactly the names envalid filled from a
default. A sensitive validator always returns an instance, so a marked name that came back as a raw
`string` can only have come from the default path, which makes the test exact rather than a guess.

## `choices` cannot see through the wrapper

envalid checks `spec.choices.includes(value)` against the **parsed** value, so an instance never
matches and the error message is built from it:

```
Value "[REDACTED:credential]" not in choices [a,b]
```

The check is broken and the message is a marker, which at least does not leak. `choices` is refused
at construction, and the message points at a format check on the raw string instead:

```typescript
credential({
  format: { check: (raw) => raw.startsWith('ghp_'), detail: 'a GitHub token prefix' },
});
```

`check` runs on the raw string, before wrapping. If it throws, the throw is caught and replaced,
because a check written as `(raw) => Boolean(new URL(raw))` throws a `TypeError` whose message holds
the input. `detail` is a fixed phrase naming the check, and must never be derived from the value.

A variable whose value is one of a short list of known constants is also, usually, not sensitive to
begin with, and the refusal message says so.

## The reporter prints the value, and only one hook reaches it

Every built-in envalid validator embeds the raw input in its message. From the source:

```javascript
throw new EnvError(`Invalid bool input: "${input}"`);
throw new EnvError(`Invalid number input: "${input}"`);
throw new EnvError(`Not a string: "${input}"`);
throw new EnvError(`Invalid email address: "${x}"`);
throw new EnvError(`Invalid host (domain or ip): "${input}"`);
throw new EnvError(`Invalid port input: "${input}"`);
throw new EnvError(`Invalid url: "${x}"`);
throw new EnvError(`Invalid json: "${x}"`);
```

and the default reporter prints them and exits:

```
================================
 Invalid environment variables:
    X: Invalid bool input: "LEAKED_SECRET_abc123xyz"
================================

 Exiting with error code 1
```

Three options exist, and which one is right turns on a detail worth measuring:

| Option | Measured result, envalid 8.2.0 |
|---|---|
| `reporter: null` | envalid rethrows the first failure and stops. One bad variable per run, and the value is in the thrown message |
| Replace the logger | Not possible from outside. `console.error.bind(console)` is captured at import |
| Replace the reporter | It receives every failure at once, and a throw from it propagates out of `cleanEnv` |

The third is the hook, and the first is what a first pass reaches for and should not: `reporter:
null` gives up envalid's most useful behaviour, which is naming every misconfigured variable in one
run.

`cleanEnvSafe` installs a reporter that never logs, rebuilds the report, and throws an
`EnvValidationError` carrying every failure:

```
Environment validation failed.

Invalid environment variables:
    DB_PASSWORD (credential): value rejected; the message is withheld because every built-in
        envalid validator embeds the raw input in it
    TOKEN (credential): value rejected by the 'a GitHub token prefix' check

Missing environment variables:
    API_URL (plain): the API base url (eg. "https://api.example"). See https://docs.example
```

The rebuild is not uniform, because the two error types do not carry the same thing:

| Error | Message | Treatment |
|---|---|---|
| `EnvError` (invalid) | `Invalid port input: "..."`, holding the value | Replaced with the name and the class |
| `SensitiveFormatError` (invalid) | written by this package, holding no value | Passed through |
| `EnvMissingError` (absent) | `formatSpecDescription(spec)` | Passed through |

An `EnvMissingError` message is built from the caller's own `desc`, `example` and `docs` and from
nothing the environment supplied, so passing it through discloses nothing and keeps the half of
envalid's output that is actually actionable. Only the invalid case loses detail, and it loses it for
every variable rather than per name, because deciding per name means being wrong once. The `PORT`
case is where that stings: a mistyped port is an ordinary configuration error whose message would
have been useful.

**Replacement rather than scrubbing.** Removing a known substring from a message looks safer and is
not: it depends on the value appearing verbatim, and every validator that truncates, quotes, escapes
or JSON-encodes its input defeats it silently.

**No `cause`.** Chaining the original error would satisfy the usual advice about preserving errors
and would put the message back, one `JSON.stringify` away, in every error reporter that walks a cause
chain.

### Two behaviours deliberately not preserved

envalid's default reporter calls `process.exit(1)`. `cleanEnvSafe` never exits: the decision to exit
belongs to the entry point.

And a custom reporter that neither exits nor throws leaves `cleanEnv` returning an unvalidated
object, which is quieter than it looks. An *absent* variable is assigned `undefined` before the
`EnvMissingError` is raised, so it stays an own property and the strict proxy answers `undefined`
rather than throwing: the caller has a variable typed `string` holding `undefined`, and nothing
points at the validation that did not happen. An *invalid* one is never assigned, so reading it
throws `[envalid] Env var X was accessed but not validated` from whatever code touched it first.
`cleanEnvSafe` always throws instead.

## The result is a proxy

The object envalid returns throws a `ReferenceError` for any property that was not declared. Core's
redaction walks treat a refusal as absence, so logging one is safe. What that does not do is make
every strict proxy safe everywhere: a third-party serializer that probes an unknown property on the
same object is outside this library.

```typescript
import { toEnvRecord } from '@platform-sec/sensitive-string-envalid';
import { toChildEnv } from '@platform-sec/sensitive-string-env';

const record = toEnvRecord(env);
spawn('pg_dump', args, { env: { PATH: process.env.PATH, ...toChildEnv(record, ['DB_PASSWORD'], ctx) } });
```

`toEnvRecord` copies own enumerable keys into the plain `EnvRecord` of the shared package, for two
reasons. `toChildEnv` takes an `EnvRecord`. And the proxy still throws for the application's own
mistakes: a typo in `env.DB_PASSWROD` is a `ReferenceError` at the read rather than `undefined`,
which is a feature of envalid and a hazard for any code that probes optionally. A record with plain
`Map`s does not have that edge, and its two halves are separated so nothing iterating `fields` can
reach a raw string.

envalid parses, so the plain half of the record holds numbers and booleans rendered as strings.
Anything structural, such as a `json()` result, is left out of both maps rather than stringified into
something a child process could not use.

`removed` is empty and `kernelCopy` is `'unknown'`: this record came from envalid, which deletes
nothing from `process.env` and cannot say what the kernel holds. Use `loadEnv` from the shared
package for those.

## What this package cannot do

- **Anything about `process.env` itself.** envalid reads it and does not touch it. Removal and the
  kernel-copy report are in [`sensitive-env`](../sensitive-env/README.md).
- **The values envalid already read.** `cleanEnv` receives the whole source object; wrapping copies.
- **A direct import of `cleanEnv`.** Nothing at run time can stop one. A lint rule can.

## API

| Export | What it does |
|---|---|
| `cleanEnvSafe(source, validators, options?)` | `cleanEnv` with an aggregate report that holds no value and never exits |
| `credential(spec?)`, `sensitive(spec?)` | Validators producing a `SensitiveString` of that class |
| `makeSensitiveValidator(klass)` | The factory behind both |
| `toEnvRecord(env)` | The plain `EnvRecord` the shared package's helpers take |
| `sensitiveMeta(spec)` | The class and label a sensitive spec carries, or `undefined` |
| `EnvValidationError`, `SensitiveFormatError` | The two error types |
| `bool`, `email`, `host`, `json`, `num`, `port`, `str`, `url` | envalid's validators, re-exported |
| `makeValidator`, `makeExactValidator` | envalid's makers, re-exported |

## License

MIT
