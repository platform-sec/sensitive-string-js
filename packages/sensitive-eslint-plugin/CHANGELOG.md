# @platform-sec/eslint-plugin-sensitive-string

## 0.2.0

### Minor Changes

- 75261e8: `require-reveal-context` covers the other audited reads, and a new rule keeps a password away from
  a fast digest.

  The library audits a digest exactly as it audits a reveal: the same gate, the same reveal budget,
  the same audit record with `operation: 'hash'` on it. An audit line saying a digest of a credential
  was taken, with nothing about who took it or why, is the gap this rule exists to close, and until
  now the rule only knew about `reveal()`.

  Only where the receiver's type can be read, which is the difference between this and the way
  `reveal()` is matched. `magician.reveal()` being reported is the standing cost of an untyped rule
  and a fair trade, because `.reveal()` is rare. `.hash()` is not: `bcrypt`, `argon2`, `node:crypto`
  and half the hashing libraries on npm have one, this repository calls two of them, and a rule that
  reported every `.hash()` call would be turned off within the hour. So the rule reads the receiver's
  type when a program is there and says nothing about these two methods when it is not.

  That makes it the plugin's third kind of rule: it works without types and uses them when present,
  where `no-stringify-sensitive` and `prefer-safe-log` cannot run at all without them. It therefore
  stays enabled under `disable-type-checked`, doing the half of its job that needs no types, and does
  not report missing type information the way those two do, because it is not reduced to silence.

  The context argument is read at the position each method takes it in: the first for `reveal()`, the
  third for `hash()`, the fourth for `hmac()`. An options object in the position before it is not a
  context and is reported as one missing, which is the mistake the argument order invites. A spread
  ahead of the context is left alone, since which argument is the context stops being a question
  syntax can answer. The two messages now name the method they are about, so a `hash()` finding no
  longer says `reveal()`.

  `mask()` and `serialize()` are covered on the same reasoning, and for a plainer motive than the
  digests: one returns a partial view as a plain string and the other returns the raw value in a wire
  object. What stays out is the transforms, `substring` and `map` and the rest, which audit too and
  would make the rule unusable long before they made an audit log better.

  A `sensitiveTypes` option names the wrapper types, defaulting to `SensitiveString`, the same way it
  does on the two type-aware rules.

  `no-password-fast-hash` is new, and it is the one rule in this plugin that reads a name rather than
  a shape. It reports `password.hash('sha256')` and points at `hashForStorage()` from the `kdf`
  package, because a fast digest is not password storage: a wordlist runs through SHA-256 at billions
  of guesses a second, and a salt does nothing about that for whoever has the row it is stored in.
  `hmac()` reports too, since a key does not make a fast function slow.

  A name, because no type separates a password from an API key: both are
  `SensitiveString<'credential'>`. That is a different question from the one `type-info.ts` refuses to
  answer by name, where a type does the job properly, and the rule's page says so rather than leaving
  the contradiction for a reader to find. The match is a case-insensitive fragment over `password`,
  `passwd`, `passphrase` and `pwd`, against the name of the value being hashed rather than whatever
  holds it: `user.password.hash()` reports, `passwordService.token.hash()` does not. `secret`, `token`
  and `key` are deliberately absent, since those are the values `hash()` is for. Warning in
  `recommended`, error in `strict`, which is the honest severity for a check whose only signal is a
  name.

- b92ff33: `no-allow-unaudited` reports a worker accepting a payload without the audit hook its sender asked
  for.

  Core's worker handoff (ROADMAP 1.6) carries a value and its context across a thread boundary, and
  the one thing it cannot carry is the context's `auditReveal`, because a function survives neither
  structured clone nor JSON. A payload built under an audited context therefore arrives marked, and
  `fromWorkerPayload()` refuses it unless the receiving side installs a hook of its own.
  `allowUnaudited: true` is the way past that refusal, and what it means is exact: the sender asked
  for every reveal of this value to be recorded, and reveals in this thread will not be.

  The flag exists because that is sometimes the right call, and this rule exists because it is never
  a call to make by accident. It reports the property on `fromWorkerPayload()` and
  `withWorkerPayload()`, whatever its value short of a literal `false` or an explicit `undefined`,
  since `allowUnaudited: flag` is still a decision to sometimes skip the audit. Error in both presets
  rather than warn: the finding is never wrong, and a disable comment on the line is where the reason
  belongs.

  Syntax only, like the other rules that read a call's shape: an object property in a call, matched
  by the function's name. An options object built elsewhere and passed by name is invisible, the
  page says so, and `payloadFunctions` renames the functions for a project that wraps the two in one
  of its own. This makes seven untyped rules and nine in all; the design decided the rule ships with
  the escape hatch it makes defensible rather than following it.

- f5ba5a4: Add the two type-aware rules, `no-stringify-sensitive` and `prefer-safe-log`.

  The five rules already in the plugin read the shape of a call. These two answer a question no
  syntax answers: does this _value_ carry a sensitive one anywhere inside it? They need
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
  or a plain list of them, is the documented way to log one. What the rule reports is a _structure_
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

## 0.1.0

### Minor Changes

- Establish the initial public package baseline. The root changelog records the development
  history leading to this version.
