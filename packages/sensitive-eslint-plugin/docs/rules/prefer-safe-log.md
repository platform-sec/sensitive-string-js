# prefer-safe-log

Prefer `safeLog()` when logging a structure whose type carries a sensitive
value.

Severity in `recommended-type-checked`: **warn**. `strict-type-checked` raises
it to error.

**Requires type information.** The rule needs a `ts.Program`, which means
`@typescript-eslint/parser` with `project` or `projectService` set. Without one
it reports its own misconfiguration rather than falling silent; see
[No type information](#no-type-information).

## Why

Two different things, under one rule because the fix is the same call.

**A `serialize()` result in a log line is a leak.** The wire format is a plain
object holding the raw value. `toString()` never runs on it, `toJSON()` never
runs on it, and `util.inspect` prints it field by field. Nothing in the library
redacts it except `safeLog`, which recognises the `__sensitive` marker by hand
for exactly this reason.

**A `SensitiveString` inside a logged structure is not a leak today, and the
rule is about not depending on that.** The class redacts itself through
`toString()`, `toJSON()` and `util.inspect`, so `console.log(user)` prints the
redaction under every transport in common use. What makes that true is the
transport reaching for one of those three. `safeLog(user)` produces a redacted
copy before the logger is handed anything, which is true regardless of what the
transport does with it.

That difference in kind is why the rule warns rather than errors by default,
and why the two cases carry different messages.

## Examples

Incorrect:

```ts
declare const user: { name: string; token: SensitiveString };
console.log(user);
logger.info({ token });
logger.info('sending request', payload);

declare const wire: SerializedSensitiveString;
console.log(wire); // nothing redacts this one
logger.warn({ credentials: wire });
```

Correct:

```ts
console.log(safeLog(user)); // redacted copy, whatever the transport does
console.log(token); // the value itself: the class redacts
console.log(tokens); // and a list delegates to each element
console.log(token.toString());
logger.info('token present:', Boolean(token));
```

## What it looks at

A call counts as a log call under the same rules as
[`no-log-reveal`](no-log-reveal.md): a method whose name is in `logFunctions`
with some name along its callee chain in `logObjects`, or a bare call whose
function name is in `logObjects`. The two rules share one matcher, so a logger
configured for one is recognised by the other.

Every argument's type is then walked: union and intersection members, array and
tuple elements, base classes, object properties and index signatures.

**Logging the value itself is not reported.** `console.log(token)` and
`console.log(tokens)` are the documented way to log a sensitive value, and an
array delegates to each element, so both are left alone. What the rule reports
is a *structure* that holds one, where the redaction stops being the class's
business and becomes the transport's. A `serialize()` result is reported
wherever it sits, because nothing redacts one anywhere.

## Options

| Option | Default |
|---|---|
| `logFunctions` | `log`, `info`, `warn`, `error`, `debug`, `trace`, `fatal`, `verbose`, `silly`, `write` |
| `logObjects` | `console`, `logger`, `log`, `winston`, `pino`, `bunyan`, `stdout`, `stderr` |
| `sensitiveTypes` | `SensitiveString` |
| `serializedTypes` | `SerializedSensitiveString` |

A configured list replaces the default rather than extending it.

```js
{
  '@platform-sec/sensitive-string/prefer-safe-log': [
    'warn',
    { logObjects: ['console', 'logger', 'report'], sensitiveTypes: ['SensitiveString', 'ApiKey'] },
  ],
}
```

## Why there is no suggestion

Wrapping the argument in `safeLog(...)` is a safe rewrite, and it is still not
offered. `safeLog` has to be imported, and an editor suggestion that inserts a
call to a function the file does not import produces code that does not compile.
Nothing in this plugin rewrites code without a person reading the diff.

## No type information

Applied to a file with no TypeScript program, the rule reports
`missingTypeInformation` once, on the file, rather than falling silent. See
[`no-stringify-sensitive`](no-stringify-sensitive.md#no-type-information) for
the mixed-project configuration that turns it off where there is no program.

## Known limits

- **The match is by name.** Any type called `SensitiveString` is treated as one,
  and a project's own wrapper is invisible until `sensitiveTypes` names it.
- **A cast to a weaker type hides the field**, and `any` or `unknown` gives the
  rule nothing to walk.
- **A `Map` or a `Set` holding sensitive values is not walked.** Its entries
  redact themselves under `util.inspect` and disappear under `JSON.stringify`,
  so there is nothing this rule would add.
- **A revealed string is invisible**, because its type is `string`.
  `no-log-reveal` is the rule for that, and it needs no types.
- `console.log(token.serialize())` is reported here *and* by `no-log-reveal`,
  which sees the call rather than the type. The two findings agree on the fix.

## Related

- [`no-log-reveal`](no-log-reveal.md), the untyped rule for a revealed value
  reaching a logger.
- [`no-stringify-sensitive`](no-stringify-sensitive.md), the same question asked
  of `JSON.stringify`.
