# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added protected string transformations for trimming, case conversion, padding, slicing,
  splitting, replacement, and character access.
- Added policy-controlled partial queries for prefix, suffix, containment, and index checks.
- Added protected regular-expression matching, named-group extraction, and match iteration.
- Added policy-controlled `test()` and `search()` regex queries and the anchored `patterns.email`
  helper.
- Added the `sensitiveTemplate` tagged template and its `st` alias for building protected values
  from template literals, with optional reveal context, label, and class.
- Added `mask()` for partial masking, with positional `showFirst` / `showLast` options and the
  `email`, `phone`, `card`, `ssn`, `uuid`, and `custom` strategies.
- Added the `minMasked` floor, which defaults to 4 for `sensitive` and 8 for `credential`.
- Added `RevealDetails` to the `auditReveal` callback and to `withAuditedReveals`, so an audit sink
  can tell a full reveal from a mask and see the options that produced it.
- Added expiration: the `ttl`, `expiresAt`, `allowRenewal`, `maxRenewals`, and `onExpire`
  construction options, the `expiresAt` and `renewalCount` properties, and the `isExpired()`,
  `ttlRemaining()`, `isRenewable()`, and `renew()` methods.
- Added the `ExpiredSensitiveValueError` and `RenewalNotAllowedError` error classes, so a caller can
  tell a lapsed deadline from a policy denial and decide whether to fetch a fresh secret.
- Added the `allowRenewal`, `defaultTtl`, `maxTtl`, and `requireExpiration` policy fields, which set
  and cap expiration for a whole sensitivity class.
- Added `expiresAt` to the serialized wire format, and a `renew` audit record carrying both
  deadlines and the renewal count.
- Added the `@platform-sec/sensitive-string-testing` package, which depends on no test framework
  and works with Vitest and Jest alike.
- Added `createTestSecret`, which builds unique, conspicuous canary values and accepts every
  `SensitiveStringOptions` field, plus the `createExpiredSecret` and `createExpiringSecret`
  factories for the two shapes tests need most.
- Added the `expectNotLeaked` and `expectRedacted` assertions, and the `LeakageDetectedError` they
  throw, which names the class, the label, and the path a value was found at.
- Added the `sensitiveMatchers` object and `setupSensitiveMatchers`, providing
  `toBeSensitiveString`, `toHaveSensitivityClass`, `toHaveLabel`, `toRevealAs`, `toBeExpired`, and
  `toContainSensitive`, usable asymmetrically as well, with a ready-made Vitest type augmentation at
  the `/vitest` entry point.
- Added `mockRevealContext` and `createMockAuditLog` for asserting on audit behavior. Both take a
  spy factory such as `vi.fn` rather than detecting a framework at runtime.
- Added `collectFragments`, `findRawValue`, and `joinFragments`, the leak-scanning primitives the
  assertions are built on, for a check the package does not already provide.
- Added `UnreadableSecretError`, raised when a check could not read the value it was asked to look
  for, so a refused reveal is never mistaken for a clean result.
- Added the `@platform-sec/eslint-plugin-sensitive-string` package, which has no runtime
  dependencies and works under ESLint 8.40 or newer, in flat and eslintrc configs alike.
- Added `no-log-reveal`, which reports a revealed or serialized value reaching a logger, at any
  depth inside an argument, and recognises a logger reached through `this`, through a request
  object, or through a builder call.
- Added `no-credential-equality`, which reports `===`, `==`, `!==` and `!=` on a revealed value, and
  a `switch` on one, with a suggestion rewriting the comparison to `.equals()` that carries any
  reveal context into the second parameter.
- Added `no-network-sensitive`, which reports an unaudited reveal in an HTTP request and allows one
  that names its purpose, with `allowWithContext: false` to forbid both.
- Added `explicit-class`, which reports `new SensitiveString(v)` with no sensitivity class and
  suggests each class.
- Added `require-reveal-context`, which reports a `reveal()` with no context argument and no
  enclosing `withRevealContext()`, with `requireReason: true` to also require the `reason` field.
- Added the `recommended` and `strict` presets in flat form, and `legacy-recommended` and
  `legacy-strict` in eslintrc form, built from one list of rule settings so the two cannot drift.
- Every rule that asks for an argument treats an explicit `undefined` as the absence of one, so
  `reveal(undefined)` neither silences `no-network-sensitive` nor satisfies `require-reveal-context`,
  and `new SensitiveString(v, undefined)` still reports a missing class.
- Added `sensitiveSerializer` and `createSensitiveSerializer`, a snapshot serializer that renders a
  `SensitiveString` as `SensitiveString<class:label>`, with optional `{length}` and `{expired}`
  fields and a custom `format`. It is available from the package root and, for a runner that loads
  a serializer by path, from the `/serializer` entry point.

- Added collection helpers to the `zod` package: `zSensitiveArray`, `zCredentialArray`,
  `zSensitiveStringArray`, `zSensitiveRecord`, `zCredentialRecord`, and `zSensitiveStringRecord`.
  Each wraps a per-element schema in a plain `z.array` or `z.record`, so the collection combinators
  still apply and a failing element reports its own index or key.
- Added `refineSensitive`, both as a method on every schema the `zod` package builds and as a
  standalone function, for a refinement whose predicate needs the raw string. It reads through
  `reveal()`, so the ambient context authorizes it and its `auditReveal` hook records it. It
  manufactures no context of its own: a policy that refuses a context-free reveal refuses this one
  too. An async predicate works under `parseAsync` and is refused, not skipped, under `parse`.
- Added `zSensitivePreprocess`, `zCredentialPreprocess`, and `zSensitiveStringPreprocess`, which
  normalize the input, validate it, then wrap it. Trimming a wrapped value would mean revealing it;
  doing it during the parse keeps the whole sequence on the raw string. Steps come from a
  declarative option set, a function, or a list of functions.
- Added `zSensitiveDefault`, which produces its fallback as a raw string and wraps it, so a
  generated default is classified the same way a parsed one is. `null` and `''` do not trigger it.
- Added `zConditionalSensitive`, which builds a discriminated union whose value field is classified
  by a sibling field, so an unknown discriminator is rejected before the value is looked at. It
  refuses a discriminator and a value field with the same name, which would otherwise collapse into
  one object key and leave the schema classifying nothing.
- Added `sensitiveErrorMap`, `installSensitiveErrorMap`, `redactZodError`, `redactZodIssues`,
  `sensitiveParse`, `sensitiveSafeParse`, and `sensitiveSafeParseAsync`, which keep the input out of
  validation errors. The parse helpers treat an explicit `errorMap: undefined` as no error map
  rather than as one that disables the default.

### Fixed

- `zSensitiveDeserialize` reports a class mismatch, an unregistered class, and a malformed payload
  as Zod issues instead of throwing out of the transform. A throw there escaped `safeParse`, so a
  caller who chose the non-throwing API got an exception anyway, from the one schema whose whole job
  is handling a payload from another service.
- Corrected the `exports` map in all three packages. Every one declared a `require` condition
  pointing at a `dist/*.cjs` file that `tsc` never emits, so `require()` of any package failed with
  `MODULE_NOT_FOUND`, and importing a package that depends on another failed the same way through
  the dependency. The build emits CommonJS `.js`, which one `default` condition serves for both
  `require` and `import`.
- Added `pnpm check:packaging`, which loads every built package by its own name through both
  `require` and `import` and checks that each path a manifest names exists and survives packing. The
  unit suite imports by relative path, so nothing exercised a manifest and three broken ones went
  unnoticed. It runs in CI after the build.

### Security

- Zod puts the input into the issue for four codes: `invalid_enum_value` and `invalid_literal` in
  `received`, `unrecognized_keys` in `keys`, and `custom` in `params`, with `invalid_union` nesting
  any of them one level down. An error map cannot reach those fields, only the message, so the
  `zod` package fixes both halves. `sensitiveSafeParse` applies the map and redacts the issues;
  `installSensitiveErrorMap` covers schemas that never pass through it. The map is not installed on
  import, because a library that rewrites a process's global Zod configuration behind the
  application's back is worse than one that asks for a line of setup.
- A sweep runs every schema factory in the `zod` package against a canary in every position it
  accepts and scans the message, the issue objects, and both formatted shapes of the error. A
  factory added to the package without an entry in the sweep fails the suite.
- The leak walk has no depth limit. A limit stops in the middle of a structure the walk could
  otherwise finish, and a leak below the cut reads as no leak at all; the walk uses an explicit
  stack so depth costs heap rather than call frames. A node budget bounds a hostile target that
  fabricates work without end.
- A reveal refused by a deadline or a policy raises `UnreadableSecretError` naming the value and the
  cause, rather than surfacing an unrelated error from inside an assertion about output where it
  would read as a clean result.
- Leak checks walk their targets instead of calling `JSON.stringify`, which asks each object what it
  wants to show. A `toJSON` that omits a field, a non-enumerable property, a value behind a getter,
  and a copy written into a `Buffer` are all reached; a value still wrapped in a `SensitiveString`
  is not reported.
- A wrapper whose rendering contains the whole raw value is reported as a leak rather than trusted,
  so a policy registered with `skipRedactValidation` cannot make a leak assertion pass.
- No failure message from the testing package contains the value it guards. A leak report replaces
  the value with `[LEAKED VALUE]`, and a failed `toRevealAs` reports the redacted rendering and the
  length, because an assertion message ends up in a CI log.
- `expectRedacted` checks the rendering the class policy actually produces, read from the instance,
  rather than hardcoding `[REDACTED:class]`, so it holds under a custom policy and fails when a
  policy stops redacting.
- `toRevealAs` reveals through the instance, so an expired value or a policy denial fails the
  assertion rather than passing on a value the code under test could not have read.
- Values the testing package generated are remembered by object identity so a leak check needs no
  reveal, which keeps it out of the caller's audit context and lets it run on an expired secret. The
  registry adds no property to the instance and is unreachable from outside the package.
- String transformations preserve sensitivity state and invoke reveal authorization and auditing.
- Partial queries are denied for credentials by default to prevent character-by-character oracle
  attacks.
- Replacement callbacks are rejected because they would receive raw matched content.
- Regex instances are snapshotted before raw access so overridden `exec` and symbol hooks cannot
  receive sensitive values; native match metadata containing the complete input is not returned.
- Regex queries follow `allowPartialQueries`, and credentials deny them by default to prevent
  caller-controlled pattern oracles.
- Template literals reveal each interpolated value through the authorization and audit gate, inherit
  the most restrictive class, and retain the state of every value they read.
- The template `klass` option may only tighten the inherited class, and unsupported interpolations
  are rejected with a `TypeError` that names the index and type but never the value, before any
  value is revealed.
- Masking is a partial reveal: it runs the same authorization and audit hooks as `reveal()`, and it
  follows `allowMask`, which credentials deny by default.
- The `minMasked` floor may be raised but not lowered, and a rendering that cannot hide that many
  characters falls back to the class's full redaction.
- A format strategy applied to a value that is not of that format redacts instead of degrading to a
  positional view, which would disclose a fixed prefix of whatever the value actually is. Counting
  digits is not enough to recognize a card: a hex token holds twelve or more of them among its
  letters.
- The `card` strategy is the only definition of card masking in this repository. It shows the
  six-digit BIN and the last four digits, which is the PCI-DSS maximum.
- The `email` strategy masks the domain as well as the local part, since a full domain leaks the
  employer or provider, and it hides a one-character local part completely.
- `customStrategy` receives the raw value, so it is rejected unless the caller names
  `strategy: 'custom'`, and its output is never measured against the floor.
- Mask options are validated before the value is read, so a rejected call leaves no audit record
  for a mask that was never rendered.
- Expiry is checked in the single gate every path to the raw value goes through, so `equals()`,
  `mask()`, `serialize()`, and every string, regex, and template operation refuse an expired value
  alongside `reveal()`. The check runs before authorization and before the audit hook, so a refusal
  is never logged as a reveal, and it cannot be lifted by overriding or shadowing `isExpired()`.
- Derived values carry the deadlines of every value they were built from and expire with the first
  of them, so a substring of an expired value is expired and a concatenation is usable only while
  both operands are.
- Only the value that owns a deadline may renew it. A derivative shares its sources' state by
  reference, so renewing through one would silently extend the value it came from.
- `ttl: 0` means "already expired" rather than "no TTL", and a value is not usable at its own
  deadline. A negative `ttl` is rejected rather than read as a deadline in the past.
- A policy's `allowRenewal: false` is a prohibition that the construction option cannot lift, and
  `maxTtl` is measured from construction, so no renewal can push an absolute lifetime forward.
- A renewal is audited before it takes effect, so an audit sink that throws stops it, and a renewal
  that a cap swallows entirely throws rather than reporting a success that changed nothing.
- Renewal permission and renewal counts do not cross the wire, so a payload cannot grant the right
  to extend a credential's lifetime; the receiving policy applies its own caps to a received
  deadline.
- An absolute deadline is read once, through the intrinsic `Date.prototype.getTime`, so neither
  mutating the `Date` afterwards nor overriding its `getTime` moves a deadline the library accepted.
- A finite but absurd `ttl` is rejected rather than accepted as a deadline past the largest date a
  `Date` can represent, which would never be reached and would throw on `serialize()`.
- `zSensitiveDeserialize()` reconstructs through `SensitiveString.deserialize()`, so the Zod
  receiving path carries a deadline and rejects an unregistered sensitivity class exactly as the
  core wire format does. It previously rebuilt the value and would have dropped the deadline,
  turning an expiring token into one that never expires.

## [0.1.0] - 2024-XX-XX

### Added

#### @platform-sec/sensitive-string-core
- `SensitiveString` class with ES2022 `#private` fields for true encapsulation
- Automatic redaction in `toString()`, `toJSON()`, and `util.inspect()`
- Sensitivity classification system: `sensitive` and `credential` (with optional labels)
- Policy registry with customizable redaction and security behaviors
- Constant-time comparison for the `credential` class
- `RevealContext` for audit-ready reveal operations
- `withRevealContext()` for AsyncLocalStorage-based context propagation
- `redactInStructure()` and `safeLog()` for safe logging of nested structures
- `SerializedSensitiveString` for service-to-service transmission
- Utility methods: `concat()`, `substring()`, `map()`, `reclassify()`, `isEmpty()`

#### @platform-sec/sensitive-string-zod
- `zSensitiveString()` for parsing strings into `SensitiveString` instances
- `zSensitive()` and `zCredential()` convenience helpers
- `zSensitiveWithValidation()` for custom string validation
- `zSensitiveOptional()` for nullable sensitive fields
- `zSensitiveDeserialize()` for parsing serialized format

### Security
- All serialization methods redact by default
- Timing-safe comparison for credentials
- Private fields inaccessible via reflection or type coercion
- Comprehensive test suite with canary leak detection
