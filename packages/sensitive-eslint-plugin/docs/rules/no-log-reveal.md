# no-log-reveal

Disallow passing a revealed sensitive value to a logger.

Severity in `recommended`: **error**.

## Why

`reveal()` returns an ordinary string, and logging an ordinary string is
ordinary code. No type can tell the two apart at the call site, so the one
mistake that defeats the whole library is also the one the compiler cannot see.

Log output is the widest distribution channel most services have: it goes to
disk, to a log aggregator, to a third-party vendor, and often to a lower
security tier than the process that produced it.

## Examples

Incorrect:

```js
console.log(secret.reveal());
logger.info({ key: secret.reveal() });
console.log(`token: ${token.reveal()}`);
console.log(secret.reveal().slice(0, 4));
console.log(secrets.map((s) => s.reveal()));
console.log(safeLog({ token: token.reveal() }));
console.log(token.serialize());
```

Correct:

```js
console.log(secret); // redacts through inspect()
console.log(secret.toString()); // redacts
console.log(secret.mask()); // partial, under the policy's floor
console.log(safeLog({ secret })); // redacts the wrapper, not a raw string
logger.info('token present:', Boolean(token));
```

## What it looks at

A call counts as a log call when either:

- its method name is in `logFunctions` **and** some name along its callee chain
  is in `logObjects`, which covers `console.log`, `this.logger.info`,
  `req.log.warn` and `logger.child({ id }).info`; or
- it is a bare call whose function name is in `logObjects`, as in `log(...)`.

Every argument is then searched for a call to one of `revealMethods`, at any
depth, through objects, arrays, template literals, concatenations, casts and
callbacks.

## Options

| Option | Default |
|---|---|
| `logFunctions` | `log`, `info`, `warn`, `error`, `debug`, `trace`, `fatal`, `verbose`, `silly`, `write` |
| `logObjects` | `console`, `logger`, `log`, `winston`, `pino`, `bunyan`, `stdout`, `stderr` |
| `revealMethods` | `reveal`, `serialize` |

A configured list replaces the default rather than extending it.

```js
{
  '@platform-sec/sensitive-string/no-log-reveal': [
    'error',
    { logObjects: ['console', 'logger', 'report'] },
  ],
}
```

### Why `serialize` is in `revealMethods`

The serialized wire format carries the value in the clear; the README's first
security note says so. `console.log(token.serialize())` is the more dangerous of
the two forms precisely because it reads like the safe one. Drop it from
`revealMethods` if a project uses the name for something else.

### Why `safeLog()` does not help here

`safeLog` redacts `SensitiveString` instances. `secret.reveal()` has already
produced a plain string, and no redactor can tell that string from any other.
Wrapping a reveal in `safeLog` is reported for exactly that reason.

## Known limits

- A logger reached under a name in neither list is not recognised. Add it to
  `logObjects`.
- A reveal inside a function that is passed to a logger but never called, as in
  `console.log(() => secret.reveal())`, is reported. The walk descends into
  function bodies because `console.log(list.map((s) => s.reveal()))` is a real
  leak written the ordinary way, and that is worth a false positive on an
  unused closure.
- A value revealed into a variable first, then logged, is not reported. Its
  type is `string` by then, so type information does not help either: reveal at
  the point of use, which keeps the raw string's lifetime as short as the
  library can make it.

## Related

- [`prefer-safe-log`](prefer-safe-log.md), which asks the type-aware version of
  the question: not "is a reveal being logged" but "does this structure carry a
  sensitive value at all".
