# no-stringify-sensitive

Disallow `JSON.stringify` on a structure whose type carries a sensitive value.

Severity in `recommended-type-checked`: **error**.

**Requires type information.** The rule needs a `ts.Program`, which means
`@typescript-eslint/parser` with `project` or `projectService` set. Without one
it reports its own misconfiguration rather than falling silent; see
[No type information](#no-type-information).

## Why

`JSON.stringify` does something to a `SensitiveString`, and does something else
to a `serialize()` result. Neither is what the call site says.

**A live wrapper becomes its redaction.** `SensitiveString` implements
`toJSON()`, so `JSON.stringify({ token })` produces
`{"token":"[REDACTED:credential]"}`. Nothing throws and nothing warns. If the
JSON was going to a log line, the substitution is what you wanted. If it was
going to another service, you have just sent the string `[REDACTED:credential]`
where a credential belonged, and you will find out at the far end, as an
authentication failure with no obvious cause.

**A `serialize()` result stays in the clear.** The wire format is
`{ __sensitive: true, klass, value }` with the raw value in it, and it is a
plain object, so `JSON.stringify` writes it out faithfully. This is the one
shape `toJSON()` cannot catch, and it is why `redactInStructure` recognises the
marker by hand.

The rule reports both, with different messages, because the fixes are
opposites: one call meant to redact and did not say so, the other meant to
transmit and did.

## Examples

Incorrect:

```ts
declare const payload: { token: SensitiveString };
JSON.stringify(payload); // writes "[REDACTED:credential]", silently
JSON.stringify(payload, replacer, 2); // the replacer changes nothing about this
JSON.stringify(token); // the value itself, same substitution

declare const wire: SerializedSensitiveString;
JSON.stringify(wire); // writes the raw value
JSON.stringify({ credentials: wire }); // and so does this
```

Correct:

```ts
// Redacted JSON, said out loud. Also handles a BigInt, and never returns
// undefined the way JSON.stringify does for a value JSON cannot represent.
safeStringify(payload);

// The value has to arrive on the other side, so it travels as the wire format
// and the receiver deserializes it.
JSON.stringify({ token: token.serialize() });

// Already reduced to a string.
JSON.stringify({ token: token.toString() });
```

## What it looks at

The first argument of a `JSON.stringify(...)` call, and only the first: the
second is a replacer and the third an indent, and neither is written into the
output as a value.

Its type is then walked the way a serializer walks a value: union and
intersection members, array and tuple elements, base classes, object properties
and index signatures. A type is reported when its own name, or the name of the
alias it was written as, is in `sensitiveTypes` or `serializedTypes`.

## Options

| Option | Default |
|---|---|
| `sensitiveTypes` | `SensitiveString` |
| `serializedTypes` | `SerializedSensitiveString` |

A configured list replaces the default rather than extending it.

```js
{
  '@platform-sec/sensitive-string/no-stringify-sensitive': [
    'error',
    { sensitiveTypes: ['SensitiveString', 'ApiKey'] },
  ],
}
```

Names are matched exactly, never by prefix. `SerializedSensitiveString` is the
shape `serialize()` produces and `deserialize()` consumes, and a rule that
reported every name containing "Sensitive" would report the recommended
transmission path at the point where it is correct.

## No type information

Applied to a file with no TypeScript program, the rule reports
`missingTypeInformation` once, on the file. That is deliberate: a rule that
reports nothing looks exactly like a rule that found nothing, and this one gets
read as "no sensitive value is being stringified here".

In a mixed project, layer `disable-type-checked` over the files a
`tsconfig.json` does not cover:

```js
export default [
  sensitive.configs['recommended-type-checked'],
  { files: ['**/*.js', '**/*.mjs'], ...sensitive.configs['disable-type-checked'] },
];
```

## Known limits

- **The match is by name.** Any type called `SensitiveString` is treated as one,
  wherever it came from, and a project's own wrapper is invisible until
  `sensitiveTypes` names it. Resolving the declaration back to this library
  would be more precise and would break under bundlers, path aliases and
  re-exports, which is a worse trade for a rule that runs in an editor.
- **A cast to a weaker type hides the field**, because after
  `payload as Record<string, unknown>` there is no longer a `SensitiveString` in
  the type. This is the same hole every type-aware rule has.
- **`any` and `unknown` report nothing.** There is nothing to walk. A payload
  arriving from an untyped module is invisible to this rule.
- **The call has to name `JSON`.** `JSON.stringify` and `globalThis.JSON.stringify`
  are recognised; a destructured `const { stringify } = JSON` or an alias
  `const J = JSON` is not. Requiring the name is what keeps `qs.stringify` and
  every other library's serializer out of the rule, since those call
  `toString()` and get the redaction.
- **A `Map` or a `Set` holding sensitive values is not walked.** Neither
  survives `JSON.stringify` as anything but `{}`, so there is nothing to
  report; a structure that converts one to an object first is walked normally.
- One search examines at most 1000 distinct types. This is a bound on the
  pathological case, not a design limit, and a payload type that reaches it
  without a sensitive value in it does not arise in practice.

## Related

- [`prefer-safe-log`](prefer-safe-log.md), the same question asked of a logger.
- [`no-log-reveal`](no-log-reveal.md), which catches `token.serialize()` handed
  straight to a logger without needing types.
