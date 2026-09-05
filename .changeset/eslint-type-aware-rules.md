---
'@platform-sec/eslint-plugin-sensitive-string': minor
---

Add the two type-aware rules, `no-stringify-sensitive` and `prefer-safe-log`.

The five rules already in the plugin read the shape of a call. These two answer a question no
syntax answers: does this *value* carry a sensitive one anywhere inside it? They need
typescript-eslint's type-aware mode, and they live only in the new `recommended-type-checked` and
`strict-type-checked` presets, so a project that has not configured a TypeScript program never
meets them.

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
  { files: ['**/*.js'], ...sensitive.configs['disable-type-checked'] },
];
```

Building them corrected the premise both rules were designed from. Neither `JSON.stringify` nor
`console.log` leaks a `SensitiveString`: `toJSON()` and the `nodejs.util.inspect.custom` handler
both redact, so every ordinary transport already prints the placeholder. What actually goes wrong
is two other things.

`JSON.stringify` substitutes silently. `JSON.stringify({ token })` produces
`{"token":"[REDACTED:credential]"}`. If the JSON was going to a log line, that is what you wanted.
If it was going to another service, a credential has just been replaced by a placeholder, nothing
threw, and the failure surfaces at the far end as an authentication error with no local cause.
`safeStringify()` says the first intent out loud; `serialize()` on the field serves the second.

A `serialize()` result is a plain object holding the raw value. `toJSON()` cannot reach it and
neither can `util.inspect`, which is why `redactInStructure` recognises the `__sensitive` marker by
hand. So `JSON.stringify(envelope)` writes the credential out in the clear and
`console.log(envelope)` puts it in a log line. That is the one genuine leak either rule catches,
and both report it under its own message.

Everything else `prefer-safe-log` reports is defence in depth, which is why it warns rather than
errors, and why it leaves `console.log(token)` and `console.log(tokens)` alone: passing the value,
or a plain list of them, is the documented way to log one. What the rule reports is a *structure*
holding one, where the redaction stops being the class's business and becomes the transport's.

Type-aware and untyped rules cannot share a preset, which is why there are now ten rather than
four. A type-aware rule applied to a file with no program has to either fall silent, which reads as
a clean file, or say so. Both say so, once per file, so a preset that also ran over plain
JavaScript would report a configuration error on every `.js` file in the project.
`recommended`, `strict` and their eslintrc twins are unchanged and still hold the five untyped
rules; `recommended-type-checked` and `strict-type-checked` hold all seven; `disable-type-checked`
turns the two back off for the files a `tsconfig.json` does not cover. `meta.docs.requiresTypeChecking`
is what the presets split on, and a test holds the split to it so a third type-aware rule cannot
land in an untyped preset by accident.

A type is matched by name, not by resolving its declaration back to this library. Resolving would
be more precise and would break under bundlers, path aliases and re-exports, which is a worse trade
for a rule that runs in an editor. `sensitiveTypes` and `serializedTypes` are the options that
follow, defaulting to `SensitiveString` and `SerializedSensitiveString`. Names match exactly rather
than by prefix, because `SerializedSensitiveString` is the recommended transmission path and a
prefix match would report it where it is correct.

The type walk mirrors what a serializer walks, which is what bounds it: union and intersection
members, array and tuple elements, base classes, object properties, index signatures. An array
stops there rather than going on to its own members, because `Array<T>` declares a numeric index
signature and following it would reach every element back through a property edge, turning
`console.log(tokens)` into a finding. A `Map` or a `Set` is not walked at all, since neither
survives `JSON.stringify` as anything but `{}` and both redact element by element under
`util.inspect`. One search examines at most 1000 distinct types, a bound on the pathological case
so that one unlucky call cannot make a lint run look hung.

The plugin still has no dependencies. The TypeScript API is reached structurally, the same way
ESLint's already was, because adding `typescript` as a dependency would put it in the install of
every consumer who lints plain JavaScript, for a pair of rules they cannot run. The checker arrives
through `parserServices`, already built by whoever configured type-aware linting, and nothing in
the package imports `typescript` at runtime or at type level.

`no-log-reveal` and `prefer-safe-log` now share one logger matcher, in `src/log-calls.ts`. Two
rules that disagreed about what a logger is would be one `logObjects` setting granting half of what
it says.

24 further cases across the two rule suites, plus a type-aware fixture project, adversarial
coverage for the shapes someone works around a finding with, and a canary that neither rule's
message ever quotes the code it flagged.
