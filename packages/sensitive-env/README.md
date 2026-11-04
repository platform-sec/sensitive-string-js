# @platform-sec/sensitive-string-env

Read configuration into `SensitiveString` values: classify by variable name, wrap at the boundary,
and get an honest report of what removing a variable from `process.env` cannot reach.

One loader rather than one per library. dotenv, convict and node-config need no package of their
own, and this README has the recipe for each. envalid is the exception and has
[its own package](../sensitive-envalid/README.md).

## What actually goes wrong

Almost every Node service starts the same way:

```typescript
const password = process.env.DB_PASSWORD!;
await pool.connect({ host: process.env.DB_HOST, user: process.env.DB_USER, password });
```

Three things are already true before the first line of application logic runs, and none of them
throws.

The value is a plain string in a process-global object that every dependency can read.
`JSON.stringify(process.env)` returns it, `console.log(process.env)` prints it, and every child
process the service spawns inherits it by default.

Nothing distinguishes `DB_PASSWORD` from `LOG_LEVEL`. There is no class, no label, and no record
that a credential was read, and the environment is the one place in an application where a
name-to-value mapping is already written down.

And the layer people put in front of `process.env` to fix the second problem is a validator, which
is the component that prints the value when it rejects it. envalid's eight built-in validators embed
the raw value in their error message; convict appends `: value was "..."` to its own.

## Installation

```bash
pnpm add @platform-sec/sensitive-string-env
```

## Requirements

- Node.js 22.12+
- `@platform-sec/sensitive-string-core` (peer dependency)

Core is a peer dependency rather than a regular one. `redactInStructure`, `containsSensitive`,
`wrapSensitiveByPath` and `deserialize` all check `instanceof`, and two copies of core in
`node_modules` make every one of those checks miss.

This package has no third-party runtime dependencies. It reads `.env` files through `node:util`'s
`parseEnv`.

## Basic use

```typescript
import { commonSecretNameRules, loadEnv } from '@platform-sec/sensitive-string-env';

const record = loadEnv({
  fields: { DB_PASSWORD: 'credential', SUPPORT_EMAIL: 'sensitive' },
  rules: commonSecretNameRules,
  fallback: 'plain',
});

record.fields.get('DB_PASSWORD'); // SensitiveString<credential:DB_PASSWORD>
record.plain.get('PORT');         // '3000'
```

Two maps rather than one map of a union, so a caller iterating `fields` cannot find a raw string in
it. A single `Map<string, SensitiveString | string>` would move that check to every call site,
including the ones that log the map.

`loadEnv` is synchronous. Every source it reads is synchronous, and configuration loading happens
before the event loop matters.

## `fallback` is required, and for the environment it is `plain`

There is no default, and this is the one option with no sensible one.

`process.env` is the most mixed store this library meets. It holds `PATH`, `HOME`, `NODE_ENV`, `TZ`
and several dozen names the runtime and the container platform put there, next to the two or three
that are secret. Failing closed over that set is not conservative, it is broken, and it breaks in a
way that looks like an application bug rather than a security control:

- An instance is an object, so it is always truthy. A wrapped `DEBUG` read as `if (debug)` is
  permanently true, including for an empty string.
- A wrapped `PORT` is never `=== '3000'`, and never parses.
- Anything handed on to a library that expects a string becomes `[REDACTED:...]`.

## Name rules are opt-in

`commonSecretNameRules` is exported as a constant and is not applied unless you put it in the spec:

```typescript
export const commonSecretNameRules = [
  { pattern: /(PASSWORD|PASSWD|SECRET|TOKEN|CREDENTIALS?)$/, klass: 'credential' },
  { pattern: /_PWD$/, klass: 'credential' },
  {
    pattern: /(^|_)(API|ACCESS|SECRET|PRIVATE|ENCRYPTION|SIGNING|CLIENT|MASTER)_?KEYS?$/,
    klass: 'credential',
  },
  { pattern: /_AUTH$/, klass: 'credential' },
  { pattern: /_DSN$|^DATABASE_URL$|_CONNECTION_STRING$/, klass: 'credential' },
];
```

A pack that ran by default would classify by guessing, and both directions of a wrong guess are bad.
A missed name is a leak the library would report as protected; a false positive is the truthiness
bug above.

**How the patterns are shaped.** Every rule requires its keyword to end the name, and only some of
them require a separator in front of it.

Ending the name is what keeps an ordinary variable out. `PASSWORD_POLICY`, `TOKEN_URL`,
`SECRET_NAME`, `API_KEY_HEADER`, `AUTH_ENABLED` and `PRIVATE_KEY_PATH` all stay plain, and each is a
name whose shape is secret and whose value is not.

Not requiring a separator in front is what reaches `PGPASSWORD` and `MYSQLPASSWORD`, which an anchor
on `^` or `_` misses entirely. `PWD` is the exception and needs one, because `PWD` and `OLDPWD` hold
the working directory in every shell, and a wrapped `PWD` is the truthiness bug in the variable most
likely to be read as a string.

`KEY` needs a qualifier in front of it, which is what separates `AWS_SECRET_ACCESS_KEY` from
`PUBLIC_KEY`.

**It still guesses, and a guess is not a substitute for `fields`.** Two shapes it deliberately does
not reach, because nothing in the name distinguishes them from an ordinary variable:

| Name | Why it is left plain |
|---|---|
| `PRIVATE_KEY_PEM` | a suffix after the keyword, and `PRIVATE_KEY_PATH` has the same shape and is a path |
| `PUBLIC_KEY` | a key, and not a secret one |

Run `explainEnv` against a real environment before trusting the pack to have covered it, and name
anything it missed in `fields`:

```typescript
const explained = explainEnv(spec, { source: deployedNames });
explained.classes.get('DB_PASSWORD'); // 'credential'
explained.counts;                     // { credential: 3, sensitive: 1, plain: 41 }
```

`explainEnv` wraps nothing and reads no value into its result, so it is safe to log in full and safe
to run before anything has been decided. Check it into a test and a specification stops drifting from
the environment it describes.

### Connection strings

`DATABASE_URL=postgres://user:pw@host:5432/db` holds a credential inside a URL, and the pack
classifies the whole variable `credential`. That is the right call and it has a cost:
`new URL(record.fields.get('DATABASE_URL'))` does not work, because the argument is not a string.
Reveal at the driver boundary, which is what a connection string is for, and declare `DB_HOST` and
`DB_NAME` as their own `plain` variables when a log line needs them.

Splitting a URL into wrapped and plain parts is not offered, because it would mean parsing a value,
and every parser puts its input in its error.

### Names containing a dot

`wrapFlat` matches by exact key and does no path walking, so a variable literally named `A.B` is
wrapped like any other. `wrapSensitiveByPath` from core splits on `.` and would silently leave that
name a raw string; it is still the right tool for a nested config document, which is what `wrapTree`
uses it for.

## Removal, and what it cannot do

```typescript
const record = loadEnv(spec, { removeFromProcessEnv: true, checkKernelCopy: true });

record.removed;     // ['DB_PASSWORD', 'API_KEY']
record.kernelCopy;  // ['DB_PASSWORD']  <- exported before exec, still in /proc/self/environ
```

**Deleting a variable from `process.env` removes the copy JavaScript can see. It does not remove the
copy the kernel made at exec time.** Measured on Linux 6.18.33.1 under WSL2, Node 22.15.0:

| How the value reached the process | `process.env` | `/proc/self/environ` | After `delete` |
|---|---|---|---|
| Exported by the parent before exec | yes | yes | gone from `process.env`, still in `/proc/self/environ` |
| `node --env-file=.env` | yes | no | gone, and there was no kernel copy |
| `process.loadEnvFile()`, or dotenv writing to `process.env` | yes | no | gone, and there was no kernel copy |

Overwriting behaves the same way: `process.env.X = 'redacted'` leaves the original bytes in
`/proc/self/environ` for the life of the process.

The first row is the production case. Kubernetes `env:` and `envFrom:`, `docker run -e`, systemd
`Environment=`, and a CI runner injecting repository secrets all export before exec. So the option
protects the JavaScript copy, the copy a spread hands to a child process, and the copy a crash
handler serializes. It cannot protect the copy a debugger, a core dump, or anything running as the
same user reads out of `/proc`.

`kernelCopy` is how an operator learns which variables are in that position. A deployment that wants
the guarantee has to stop exporting those variables at exec time and load them from a file or a
secrets manager instead.

**`checkKernelCopy` costs a transient copy of the whole environment**, values included, so it is off
by default. The implementation narrows the cost as far as it can: the file is read as a `Buffer`,
only the name slices are decoded into JavaScript strings, and the buffer is zeroed before it is
dropped. No value is ever materialized as a string. The bytes still existed.

On a platform with no `/proc`, `kernelCopy` is the string `'unknown'`. It is never an empty array
there, which would be a false all-clear.

**What removal breaks.** Any library that reads `process.env` lazily stops finding the variable. That
includes an SDK reading `AWS_SECRET_ACCESS_KEY` on first call, a driver reading `PGPASSWORD`, and
anything that re-reads on reconnect. The failure is loud, and it arrives later than startup, which is
why the option is off by default and the recommended order is to adopt classification first and
removal second.

Who can read `/proc/<pid>/environ`: it is mode 0400, so the process owner, root, and anything with
`CAP_SYS_PTRACE`, subject to `ptrace_scope` and `hidepid`. In a container that is normally every
other process in the container, a shell someone `exec`s into it included. That is a smaller set than
can read `/proc/<pid>/cmdline`, which is mode 0444 and world readable. It is not a small enough set
to skip the option.

## Handing a credential to a child process

Anything assigned into an environment object is coerced with `String()`. Measured on Node 22.15.0:

| Path | What arrives |
|---|---|
| `process.env.API_KEY = wrapped` | `"[REDACTED:credential]"`, typed `string` |
| `spawn(cmd, { env: { API_KEY: wrapped } })` | the child reads `[REDACTED:credential]` |
| `{ ...process.env }` after either | the marker, copied onward |

The parent starts, the child starts, the child authenticates with the literal string
`[REDACTED:credential]`, and the first sign is an authentication failure in a process that is not the
one holding the bug.

```typescript
import { toChildEnv } from '@platform-sec/sensitive-string-env';

const childEnv = { PATH: process.env.PATH, ...toChildEnv(record, ['DB_PASSWORD'], ctx) };
spawn('pg_dump', args, { env: childEnv });
```

`toChildEnv` reveals exactly the named variables under an explicit `RevealContext`, never an ambient
one, and throws before returning anything if a produced value contains `[REDACTED:`. It returns only
what was asked for: the default that spreads `process.env` is the default that re-exports every
credential you just removed to every child the service starts.

The child receives a plain string, and the exec-time copy in the child's `/proc/<pid>/environ` is now
the child's problem. A package cannot hand a credential to another process without giving it a
credential.

## Reading `.env` files

```typescript
const record = loadEnv(spec, { files: ['.env', '.env.local'] });
```

Files are read in order, earlier entries losing to later ones, and all of them losing to `source`
(which defaults to `process.env`). A file that does not exist is skipped. A file that exists and
cannot be read throws, with the path and the errno and nothing else.

Parsing goes through `node:util`'s `parseEnv`, which never throws. That is a security property, since
a parser that does not fail on content cannot put content in an error. It is also a correctness
hazard, and a worse one than it looks. Measured on Node 22.15.0:

| Input | Result |
|---|---|
| `export A=1` | `{ A: '1' }`, the `export` prefix stripped |
| `B='x\ny'` | `{ B: 'x\ny' }`, multi-line quoted values supported |
| `A=1` then `A=2` | `{ A: '2' }`, last wins, silently |
| `KEY` alone at end of file | `{}`, the line dropped, silently |
| `KEY` followed by `B=2` | `{ 'KEY\nB': '2' }`, **`B` is gone** |
| `A="x=y"` | `{ A: 'x=y', '"x': 'y"' }`, **a second name invented from the value** |
| `A=b # c` as the last line | `{ A: 'b # c' }`, **the comment kept in the value** |

Node 22.16.0 rewrote the parser. From that release on (measured on 22.16.0, 22.23.3 and 24.19.0)
`KEY` followed by `B=2` gives `{ B: '2' }`, `A="x=y"` gives `{ A: 'x=y' }` alone, a last-line comment
is stripped, and an unterminated quote at end of file is kept as a value with the quote in it rather
than dropped.

Before the rewrite the table above is not one shape but several. Every release measured from 22.12.0
to 22.15.0, and 23.0.0 to 23.11.0, lets a stray line eat the next variable's name. Whether a quoted
`=` invents a second name, whether the last line keeps its comment, and whether a whitespace-only
line also eats the next name all differ between patch releases. The package supports Node from
22.12.0, so the handling below stays, and it does not depend on which of those a release does.

Three consequences, and each is handled rather than documented away.

**A stray line eats the next variable's name.** It does not lose itself, it folds itself into the
following assignment, so `TOKEN=...` two lines below a typo arrives under a name that no rule
anchored on `_` can match, and the credential lands in the plain half while the report says nothing
was wrapped. `loadEnv` drops any parsed name holding a character no exporter can set (a control
character, `=`, or a quote), so the mangled name never becomes an unclassified variable.

**Dropped lines are reported by number, never by content.** The comparison is a heuristic and this
package says so, which is why it is a warning through `onLoad` rather than a throw: a `.env` file
with a stray line should not stop a service that has the variable in its environment anyway, and a
heuristic should not be able to stop one at all.

```typescript
loadEnv(spec, {
  files: ['.env'],
  onLoad: (event) => {
    for (const dropped of event.droppedLines) {
      logger.warn('env line produced no variable', { file: dropped.file, line: dropped.line });
    }
  },
});
```

`EnvLoadEvent` carries names, classes, counts and line numbers. It never carries a value or a line's
content, so it is safe to log in full. `unexpectedNames` is a **count** and never a list, because the
extra name in the `A="x=y"` row is a slice of the value.

**Keep comments on their own lines.** On some releases before Node 22.16.0 the last variable in a file
keeps everything after a `#` in its value, which surfaces as an authentication error rather than a
parse error.

## dotenv

There is no dotenv package, because dotenv parses a file, writes the result somewhere, and never
holds a value again. It has one option that changes where the values land, and using it is the whole
integration:

```typescript
import dotenv from 'dotenv';
import { loadEnv } from '@platform-sec/sensitive-string-env';

// The values never touch process.env, so there is nothing to delete afterwards.
const { parsed } = dotenv.config({ processEnv: {}, quiet: true });
const record = loadEnv(spec, { source: parsed });
```

This is strictly better than wrap-then-delete: the value never enters the environment at all, so
there is no window during which a crash handler could capture it and no kernel copy to report.

Where a project already calls `dotenv.config()` at the top of its entry point, `loadEnv` over
`process.env` with `removeFromProcessEnv: true` is the migration step, and moving the call to
`processEnv` is the finished state.

Measured, so you do not have to check: dotenv's `debug: true` output names keys and never prints
values; the v17 startup line is a count, suppressed by `quiet: true`; `dotenv.parse()` on a buffer
has no side effects; and `override` decides whether an existing `process.env` entry wins, defaulting
to keeping it. None of them is a leak.

### Expansion is a second copy under a second name

`dotenv-expand` resolves `${VAR}` references, and a reference to a secret inlines the secret:

```
DB_PASSWORD=s3cr3t
DATABASE_URL=postgres://app:${DB_PASSWORD}@db:5432/app
```

Measured, the expanded record holds the full secret in `DATABASE_URL`. A specification that
classifies `DB_PASSWORD` and not `DATABASE_URL` has wrapped one of the two copies and reports
success. `explainEnv` cannot see this, because expansion happens before the loader runs and the
result is just another string.

Run this in a test, not at startup:

```typescript
import { findCrossContamination } from '@platform-sec/sensitive-string-env/testing';

it('leaves no secret inlined into a plain variable', () => {
  expect(findCrossContamination(expanded.parsed ?? {}, spec)).toEqual([]);
});
```

It compares raw values against raw values, which is the one thing this package otherwise never does,
so it lives behind a `/testing` subpath and is not reachable from a production import by accident. It
reports both variable names and neither value.

### Encrypted `.env` belongs to the other row

dotenvx encrypts values in `.env` and decrypts them with `DOTENV_PRIVATE_KEY`. Reading the value
requires a key, so it is a `SecretSource` in
[`sensitive-secrets`](../sensitive-secrets/README.md) rather than a loader here. The two rows meet
at the private key itself, which arrives as an ordinary environment variable and is classified
`credential` by the rule pack.

## convict

convict is the only library here with a sensitivity feature of its own, and it covers exactly two
paths. Measured with `sensitive: true` on `db.password`:

| Path | Result |
|---|---|
| `config.toString()` | `{ "db": { "password": "[Sensitive]" } }` |
| `config.validate()` error message | the value is suppressed |
| `config.get('db.password')` | the raw value |
| `config.getProperties()` | the raw value |
| `util.inspect(config)` | the raw value |
| `JSON.stringify(config)` | the raw value |

Two of the four unprotected paths are what a logger reaches for. The error suppression is genuinely
useful and is why the integration keeps the flag: without it, a failed `validate()` appends
`: value was "..."` to the message.

**Do not use `convict.addFormat` to coerce into a `SensitiveString`.** The coercion runs, and
`config.get()` then returns a `lodash.clonedeep`: a new object with the same prototype and the own
enumerable properties copied, so `klass` and `label` survive, `instanceof` still passes, and every
private field is gone.

```typescript
const v = config.get('apiKey');

v instanceof SensitiveString;  // true
v.klass;                       // 'credential'
v.reveal();                    // TypeError: Receiver must be an instance of class SensitiveString
String(v);                     // the same TypeError
util.inspect(v);               // the same TypeError, thrown from the redaction hook itself
```

That is worse than a plain leak in two ways. `console.log(config.get('db'))` throws from the inspect
hook, so the redaction path is the one that crashes. And `containsSensitive` returns true for the
clone, because `instanceof` passes, so the library's own leak detector reports a value as protected
when it is neither usable nor redactable.

Wrap on the way out instead, once:

```typescript
import { assertSensitiveFlags, wrapTree } from '@platform-sec/sensitive-string-env';

const CONFIG_FIELDS = {
  'db.password': { klass: 'credential', label: 'db.password' },
  'smtp.password': { klass: 'credential', label: 'smtp.password' },
} as const;

config.validate({ allowed: 'strict' });
const settings = wrapTree(config.getProperties(), CONFIG_FIELDS);
```

`assertSensitiveFlags(schema, CONFIG_FIELDS)` walks the convict schema structurally, with no convict
import, and throws if a classified path lacks `sensitive: true`. It belongs in a test rather than at
startup.

**The convict instance still holds every raw value**, and `config.get()` still returns them. Wrapping
copies the value; it does not remove the original.

## node-config

node-config has no extension point at all, and it is the one library here that destroys an instance
before the application ever calls a method. Measured with a `SensitiveString` placed in
`config/default.js`:

| Mode | `config.get('db.password')` | Result of any method call |
|---|---|---|
| Default | a `Proxy` around a prototype-preserving copy | `TypeError: Receiver must be an instance of class SensitiveString` |
| `ALLOW_CONFIG_MUTATIONS=true` | the copy, no proxy | the same `TypeError` |

The proxy is `Util.makeImmutable` and it binds methods to its target, so it is not the cause. The
cause is the loader's own deep merge, which copies own property descriptors onto a fresh object with
the same prototype. Instance identity is lost in both modes, `instanceof` still passes, and `klass`
still reads: the same misleading shape as convict's clone.

```typescript
import { wrapTree } from '@platform-sec/sensitive-string-env';

const settings = wrapTree(config.util.toObject(), CONFIG_FIELDS);
```

`config.util.toObject()` is `JSON.parse(JSON.stringify(config))`. On a tree of plain strings that is
the mutable deep copy the recipe wants. **On a tree that already holds an instance it throws**,
because `toJSON` reaches `toString` and `toString` reads the private field the merge destroyed. So
the recipe is one-directional: wrap the tree node-config hands out, and never put an instance into a
config file.

`custom-environment-variables.json` maps environment variables into the tree and offers no transform
hook, so a variable that arrives that way is classified by its path in `CONFIG_FIELDS` like any other
field, and is additionally still in `process.env` under its own name.

## Node's built-in loaders

Node 22 ships three ways to do this without dotenv, and they differ in what a package can hook.

| Mechanism | Hook available | Kernel copy |
|---|---|---|
| `node --env-file=.env` | none; values are in `process.env` before user code | no |
| `process.loadEnvFile(path)` | none; returns `undefined` and writes `process.env` | no |
| `util.parseEnv(content)` | the value never leaves the returned object | no |

`--env-file` is the one popular mechanism where the value is in `process.env` before any application
code runs and where deletion is nonetheless complete, because Node sets the variables after exec. A
deployment that must keep secrets out of the kernel copy should prefer it over exporting them, and
prefer `util.parseEnv` over both.

## Schema-first validation

This package produces a record. It does not wrap zod, does not re-export it, and does not grow a
second validation layer:

```typescript
import { sensitiveSafeParse } from '@platform-sec/sensitive-string-zod';

const record = loadEnv({ fields: { DB_PASSWORD: 'credential' }, fallback: 'plain' });

const Config = z.object({
  DB_PASSWORD: z.instanceof(SensitiveString),
  PORT: z.coerce.number().int().positive(),
});

const config = sensitiveSafeParse(
  Config,
  Object.fromEntries([...record.fields, ...record.plain])
);
```

`sensitiveSafeParse` is the parse whose issues do not echo input.

## What this package cannot do

Stated here rather than left implied:

- **The kernel's copy of an exec-time variable.** `kernelCopy` reports it; nothing removes it.
- **The raw values inside convict and node-config after wrapping.** Wrapping copies.
- **Anything a child process does with a credential** after `toChildEnv` hands it over.
- **The parsed record.** `dotenv.config()` returns `{ parsed }` holding every value as a raw string,
  and `util.parseEnv` returns the same shape. The loader wraps from that record and drops its
  reference; the strings live until collection.
- **Memory.** There is no way to zero a JavaScript string.

## API

| Export | What it does |
|---|---|
| `loadEnv(spec, options?)` | Read, classify, wrap. Optionally delete and report the kernel copy |
| `explainEnv(spec, options?)` | The classification each name would get, wrapping nothing |
| `commonSecretNameRules` | The opt-in name pack |
| `wrapFlat(source, spec)` | Wrap a flat record by exact key |
| `wrapTree(tree, config, options?)` | Wrap a nested document by dot path, over core's walker |
| `toChildEnv(record, names, ctx)` | Reveal named variables for a child process, with the marker guard |
| `removeFromProcessEnv(names)` | Delete names from `process.env`, reporting what was there |
| `kernelCopyNames(names)` | Which names are still in `/proc/self/environ`, or `'unknown'` |
| `parseEnvContent(content, file)` | Parse `.env` text and report what the parser swallowed |
| `readEnvFile(file)` | The same, from disk. `undefined` when absent |
| `assertSensitiveFlags(schema, config)` | Check a convict schema declares `sensitive: true` |
| `compileEnvSpec(spec)`, `envLabel(spec, name)` | The classifier and the label rule |
| `probeProperty`, `probeKeys` | Guarded reads for objects that refuse to answer |

From `@platform-sec/sensitive-string-env/testing`:

| Export | What it does |
|---|---|
| `findCrossContamination(source, spec)` | Secrets an expansion copied into a plain variable |
| `sweep`, `assertNoCanary`, `errorText`, `hostileObjects` | The canary and marker harness |

## License

MIT
