# no-allow-unaudited

Disallow `allowUnaudited` on `fromWorkerPayload()` and `withWorkerPayload()`.

Severity in `recommended`: **error**.

## Why

A `SensitiveString` crosses a worker thread or a child process through
`toWorkerPayload()`, which carries the sending context's `name`, `reason` and
`tags` along with the values. It cannot carry the context's `auditReveal`,
because a function does not survive structured clone or JSON, so a payload built
under an audited context arrives with `audited: true` and no hook.

`fromWorkerPayload()` refuses such a payload unless the receiving side supplies
a hook of its own, either through the `auditReveal` option or from an ambient
`withRevealContext()`. `allowUnaudited: true` is the way past that refusal, and
what it means is precise: the sender asked for every reveal of this value to be
recorded, and reveals in this thread will not be.

That is sometimes the right call, which is why the option exists. It is never a
call to make by accident, which is why this rule reports every use of it and
why the severity is error rather than warn: the flag is always deliberate, and
an inline disable comment is the right place for the reason it was deliberate.

## Examples

Incorrect:

```js
fromWorkerPayload(workerData, { allowUnaudited: true });
withWorkerPayload(workerData, { allowUnaudited: true }, ({ token }) => sign(token));
fromWorkerPayload(workerData, { auditReveal, allowUnaudited: true });
fromWorkerPayload(workerData, { allowUnaudited: skipAudit });
```

Correct:

```js
fromWorkerPayload(workerData, {
  auditReveal: (value, details) => log.info('reveal', { klass: value.klass, ...details }),
});

withWorkerPayload(workerData, { auditReveal }, ({ token }) => sign(token));

// Inside a context that already carries a hook, which the reverse direction
// of the handoff relies on: a parent handler registered inside
// withRevealContext() consumes a worker's reply with no options at all.
fromWorkerPayload(message);

// The default spelled out.
fromWorkerPayload(workerData, { allowUnaudited: false });
```

When the flag is the right answer:

```js
// eslint-disable-next-line @platform-sec/sensitive-string/no-allow-unaudited -- this worker only hashes the value and the digest is what gets recorded, downstream
fromWorkerPayload(workerData, { allowUnaudited: true });
```

## Options

```json
{
  "@platform-sec/sensitive-string/no-allow-unaudited": ["error", {
    "payloadFunctions": ["fromWorkerPayload", "withWorkerPayload"]
  }]
}
```

`payloadFunctions` names the functions the flag is read on. A configured list
replaces the default, for a project that wraps the two library functions in one
of its own.

## Known limits

- The flag is read from an object literal in the call. An options object built
  elsewhere and passed by name is invisible to syntax, and so is a spread that
  contributes it.
- A `false` literal and an explicit `undefined` are not reported. Any other
  value is, a variable included, because `allowUnaudited: flag` is still a
  deliberate decision to sometimes skip the audit.
- The functions are matched by name. A project that names something else
  `fromWorkerPayload` is reported on that too, and `payloadFunctions` is the
  fix.
- An aliased import is invisible for the same reason:
  `import { fromWorkerPayload as fwp }` and then `fwp(workerData, { ... })` is
  not reported, because resolving the alias needs types this rule does not
  take. Add the local name to `payloadFunctions`.
- `allowUnaudited: 0`, `null` or `''` are reported although the runtime reads
  anything but `true` as unset. That is deliberate: each is a confusing way to
  write the default, and the rule would rather ask for `false`.
