# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added `@platform-sec/sensitive-string-scrub` and `@platform-sec/sensitive-string-sentry`, the
  error tracking row of roadmap 3.7. The roadmap described this as "one `beforeSend` hook running
  `redactInStructure`", and all three nouns were wrong. Measured on Node 22.15.0 against
  `@sentry/node` 10.73.0: `beforeSend` receives an event the SDK has already normalized through its
  JSON form, so every `SensitiveString` in it is a string by then and structural redaction there is a
  no-op; `redactInStructure` replaces the second visit to a shared reference with `'[Circular]'`,
  which corrupts an event that legitimately holds one object at two paths; and the leak is not
  unredacted instances at all, because a wrapped value is already safe on every path tested. The
  leak is the raw strings nobody wrapped, sitting beside the wrapped ones: at stock defaults, with no
  `sendDefaultPii` and no `dataCollection`, one inbound request puts `request.headers.authorization`,
  `request.headers.cookie`, `request.cookies`, `request.url` and `request.query_string` into the
  outgoing event verbatim.
- `scrub` is the shared layer, with no third-party runtime dependencies. It runs two walks, one per
  stage, with the report accumulated during the second rather than computed by a third: structural
  redaction through `redactCopy`, which keeps prototypes and shared references and replaces a
  `serialize()` result with the marker of the class it names, and then a key and path denylist over
  the copy. `DEFAULT_DENY_KEYS` is the union of `rollbar` 3.1.0's three key-shaped default lists,
  which a test asserts is still a superset of what the installed `rollbar` ships, plus the
  credential-bearing names those lists omit. Matching is on key names and paths and never on values.
  A denied value is replaced rather than deleted, and `allowKeys` requires a reason string, because
  taking a key off the default list is the one operation here that makes it leak more. `urlKeys`
  replaces the denied query parameters of a URL and keeps the route, since deleting the URL removes
  most of an error report's value. A value structural redaction already replaced keeps its marker
  rather than being censored over, because the marker names the class and is equally safe.
- The marker rule inverts here. 3.7 says an integration that transmits throws if the outgoing bytes
  contain `[REDACTED:`; an error tracker is a sink rather than a wire, so the marker is the desired
  output and its absence is the failure. A marker in *captured* data is instead evidence that another
  integration failed, and is reported through the `sensitive.marker_seen` tag rather than thrown on,
  since throwing would suppress the report of the incident the marker is evidence of.
- No hook body throws. Measured: a `beforeSend` that throws makes Sentry drop the original event and
  send a replacement describing the scrubber's own exception, so the error the user needed is gone
  and the alert names the wrong thing. On an internal failure the payload becomes a stub carrying the
  exception type, the grouping data the vendor already computed, and a `sensitive.scrub_failed` tag,
  and `onScrub` is called with `failed: true`. Only two independent failures, a scrub that throws and
  a stub that throws, drop a payload.
- `sentry` is an options wrapper rather than an integration, which the measurements force. An
  integration cannot reach `beforeBreadcrumb`, a client option, and an integration's `processEvent`
  runs in registration order: one listed before `extraErrorDataIntegration()` never sees the
  `contexts.<ErrorName>` it writes, which is where a custom property on a thrown error lands with raw
  values intact. `withSensitiveScrubbing` composes all six `before*` hooks at `init` and appends an
  integration whose `setup()` registers a scope event processor, which the SDK runs after every
  integration's `processEvent` regardless of array order. A caller's hook is composed rather than
  replaced and runs after the scrubber on the already-scrubbed payload; one returning `null` still
  drops the payload; one that throws does not lose the event. The wrapper is idempotent and does not
  modify the options object it was given, and it refuses `sendDefaultPii: true` rather than scrubbing
  harder, because that option enables every collection category and is deprecated in v10.
- Two rows of the hook map were measured that the design had recorded as unmeasured and assumed:
  `beforeSendLog` and `beforeSendMetric` both hand over live `SensitiveString` instances, while
  `beforeSendTransaction` and `beforeSendSpan` do not. Structural redaction runs at every seam
  regardless, because "already normalized" is a property of one version rather than a documented
  contract. `beforeSend` runs as a quiet backstop: it scrubs without reporting, so one payload still
  produces one report, and with marker counting off, since by then the earlier pass has written a
  marker everywhere a wrapped value stood.
- Added `recommendedDataCollection`, an object to spread into `Sentry.init` rather than a default
  this package applies. `sendDefaultPii` defaults to `false` and headers, cookies and query strings
  were still captured verbatim, because `dataCollection`'s per-category defaults are what governs
  collection. The object turns off `cookies`, `httpBodies`, `databaseQueryData` and `genAI`, and the
  README explains each. Silently changing what an error tracker collects is too large a behavioural
  change to make from inside a scrubbing package.
- Added a type-level seam check. `COVERED_HOOKS` is asserted against
  `Extract<keyof NodeOptions, 'before${string}'>` in both directions, so a seventh hook in a future
  SDK release fails compilation with the new hook's name in the failure, and a stale name here fails
  it from the other side. Verified by removing `beforeSendMetric` and watching the check name it.
- Added a canary sweep for each package. Every position an SDK captures gets a canary, a real error
  is driven through the real SDK to a capturing transport, and the canary is asserted absent from the
  whole outgoing envelope. A companion case runs the same positions with no scrubbing and requires
  every one of them to leak, so a fixture that stopped exercising anything fails rather than passing
  quietly. Nothing in either suite mocks the SDK. Alongside them are five pinning tests recording the
  vendor behaviour the design depends on, and an import-surface test asserting that shipped source
  imports only `SensitiveString`, `redactCopy`, `containsSensitive`, `sensitiveClassesIn` and
  `SensitivityClass` from core, since a scrubbing package that reveals has inverted its own purpose.

### Fixed

- Fixed a leak in the tracing seams found by reviewing the first cut. One `http.get` to
  `/pay?token=SECRET&page=2` puts the token into five span attributes on `@sentry/node` 10.73.0,
  `url.full`, `http.url`, `http.target`, `http.query` and `url.query`, and the URL key list carried
  only the second, so the other four left the process with the token in them. The list is now the
  measured set, and a test drives a real outbound request through the SDK's own HTTP instrumentation
  and asserts the canary reaches no attribute, with a companion case requiring it to leak when the
  scrubbing is removed and a pinning test naming the attributes so a rename is diagnosable rather
  than just red. The event-shaped canary sweep could not have caught this: a span is assembled by the
  SDK's instrumentation, not by anything an application writes, so a fixture built by hand never sees
  what one carries.
- `scrubUrl` now handles a relative URL. `new URL()` refuses `/pay?token=SECRET&page=2`, and handing
  it to `URLSearchParams` yields the keys `['/pay?token', 'page']`, so nothing matched and the string
  was kept whole. That is the shape a span's `http.target` holds. It is resolved against a base that
  is discarded, re-emitted from the path onwards, and only when a denied parameter actually matched:
  an arbitrary string also resolves against a base and would otherwise come back percent-encoded.
  Nothing is rewritten purely to normalize it, so a subject with nothing denied in it comes back
  byte-identical.
- The failure behaviour is now per payload kind. `buildEventStub` was used for all of them, which
  produces a span with no `span_id`, a log with no body and a transaction with no trace context.
  `beforeSend` and `beforeBreadcrumb` keep their stubs, because losing an error or a position in a
  timeline loses information; `beforeSendTransaction`, `beforeSendLog` and `beforeSendMetric` now
  drop, which all three accept, because a malformed payload is worse than an absent one and losing
  one is what sampling already does.
- `beforeSendSpan` never answers `null`. Measured: the SDK logs "Returning null from
  `beforeSendSpan` is disallowed" and then pushes the **original, unscrubbed span** into the
  envelope. Both paths that would have returned one are closed, the scrub-and-stub double failure
  with a content-emptied span stub, and a caller's own null with the scrubbed span. A caller's intent
  to drop is not honoured, because the SDK does not offer it, but it no longer becomes a raw send.
- Installing the package no longer disables span streaming. `spanStreamingIntegration` resets
  `traceLifecycle` to `'static'` when it finds a `beforeSendSpan` the SDK did not mark, and this
  package installs one unconditionally. Its hook now carries the marker, and deliberately does not
  when the caller supplied an unmarked hook of their own, so the SDK's warning still reaches the
  person it is aimed at.
- `composeAfter` now catches a rejected promise from a caller's hook, not only a synchronous throw.
  `beforeSend` may return a promise, so a rejection reached the SDK as a dropped payload, which is
  the outcome the never-throw contract exists to prevent.
- A caller taking a key off the denylist that a vendor package had added no longer fails at init.
  `mergeScrubPolicy` treats it as the override it is, rather than handing the caller a
  `ScrubPolicyError` naming a `denyKeys` list they never wrote. A caller who writes the same key into
  both of their own lists still gets the error, which is the contradiction it is for.

### Changed

- Added a `typecheck` script, `tsc --noEmit` over the whole repository including tests, and a CI step
  that runs it. The type-level seam checks live in `.test-d.ts` files that `vitest` does not collect
  and a package build excludes, so without this they would have compiled nowhere.

- Added `redactCopy()`, the walk a response body needs before a serializer other than
  `JSON.stringify` sees it. It copies the structure with every `SensitiveString` replaced by its
  redaction and every `serialize()` result, recognised by its `__sensitive: true` marker, replaced by
  the redaction of the class it names, keeping each object's prototype so an entity `toJSON()` still
  runs, preserving shared references, and passing streams, `Buffer`, `Date`, `Map`, `Set`, `RegExp`,
  and `URL` through by reference. `redactInStructure()` remains the walk for log lines, where a
  plain-object copy is what a log wants. The NestJS `SensitiveResponseInterceptor` now delegates to
  it, which is how that interceptor gained the serialized-value case.
- Added `@platform-sec/sensitive-string-fastify`, the Fastify integration. `sensitiveKeyword` is an
  Ajv keyword: a `sensitive: { klass, label }` annotation on a string property in a body,
  querystring, or params schema replaces that property with a `SensitiveString` during validation,
  after the property's own `type`, `minLength`, and `format` checks have run on the raw string, and it
  reaches nested objects, array items, and `$ref` schemas added with `fastify.addSchema`. It goes into
  `Fastify({ ajv: { customOptions: { keywords: [sensitiveKeyword] } } })`, because Ajv is built with
  the instance. `sensitivePlugin` covers what a schema cannot: a `body` field map through core's
  `wrapSensitiveByPath` for routes without one, scoped by Fastify's own encapsulation and merged with
  a route's `config.sensitive.body`; `headers`, which puts wrapped copies on
  `request.sensitive.headers` and leaves `request.headers` byte-identical; `context`, a callback-style
  hook whose `AsyncLocalStorage` scope covers every later hook, the handler, its `await`
  continuations, and the error handler; and `responseFilter`, a `preSerialization` walk through
  `redactCopy` for the serialized values and entity instances neither of Fastify's serializers
  redacts on its own. A headers schema using the keyword is refused at route registration, because
  there the keyword would replace the value in the raw Node headers object that Fastify itself reads
  as strings, and the field map is gated to `application/json` and
  `application/x-www-form-urlencoded` by default, widened with `contentTypes`, because the clone
  inside `wrapSensitiveByPath` flattens a `Buffer` into a numeric-keyed object and a `Map` or `Set`
  into `{}`. The keyword must also stay out of a union branch that can fail after it has run: Ajv
  does not undo a `modifying` write, so a sibling branch requiring `type: 'string'` then sees an
  object. Fastify 5 only.
- Added `@platform-sec/sensitive-string-express`, the Express integration. `sensitiveBody()` wraps
  configured `req.body` fields through core's `wrapSensitiveByPath`, scoped by the mount path;
  `sensitiveHeaders()` puts wrapped copies on `req.sensitive.headers` and leaves `req.headers`
  byte-identical, so `req.get()`, CORS, and authentication middleware keep working;
  `sensitiveContext()` establishes the reveal context for every later middleware, the handler, its
  `await` continuations, and any error handler; `sensitiveResponseFilter()` patches `res.json` and
  `res.jsonp` to run `redactCopy` over the body, which covers serialized values and entity instances
  that `toJSON()` cannot; and `stripParseErrorBody()` removes the raw request body that body-parser
  attaches to the 400 it raises for a malformed payload. Field maps are validated when the
  middleware is constructed, so a typo is a startup failure rather than a field that quietly stays a
  plain string. Express 4.21+ and 5 are both supported, with the suite running on 5 and a smoke test
  of the whole stack on 4.
- Added `@platform-sec/sensitive-string-decorators`, the framework-agnostic Stage 3 decorators.
  `@Sensitive` wraps every value an auto-accessor field receives, including the field initializer
  and a value hydrated onto the instance through an untyped path, and refuses one whose class is
  less restrictive than the field's. `@WithRevealContext` runs a method inside a named reveal
  context, nesting it over the ambient one so an outer audit sink keeps receiving records, and
  covers generators and async generators by wrapping the iterator, since their bodies resume after
  the context would otherwise have closed. Stage 3 only: NestJS applications get the same two names
  from the NestJS package. Note that an `accessor` field is a prototype getter and setter pair
  rather than an own property, so `JSON.stringify` omits it instead of redacting it; declare
  `toJSON()` where the serialized shape matters.
- Added `@platform-sec/sensitive-string-nestjs`, the NestJS integration. `@Sensitive` marks DTO
  properties, `SensitiveTransformPipe` wraps them after `ValidationPipe` has validated the plain
  strings, `SensitiveContextInterceptor` and `@WithRevealContext` establish the reveal context for
  the request, `SensitiveResponseInterceptor` redacts response bodies, serialized values included, before a
  serializer sees them,
  and `@SensitiveHeader`, `@SensitiveParam`, and `@SensitiveQuery` wrap sensitive data that arrives
  outside a DTO. The package ships legacy-signature decorators, since NestJS cannot run the Stage 3
  ones the decorators package targets.
- Added `sensitiveFormat()`, a winston format that redacts every `SensitiveString` in a log record
  before a terminal format or a transport serializes it. Install it at the front of
  `format.combine(...)`; in a later position the output string already exists and the format emits a
  process warning saying so. It adds no runtime dependency, because winston's format contract is
  satisfied structurally.
- Added `dropClasses` to `sensitiveFormat()`, which discards a whole record that carries a given
  sensitivity class rather than redacting it, so a transport can refuse credential-bearing records
  outright. Its companion `stampClasses` records what a record carried before redaction erased the
  evidence, which is what lets a transport-level check work behind a logger-level redaction.
- Added `sensitiveClassesIn()`, which collects the sensitivity classes present anywhere in a
  structure, where `containsSensitive()` only answers yes or no.
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

### Changed

- A policy's `checkRevealAllowed` now receives the value being read and what is being authorized,
  as `(ctx, value, access)`, where `access` is `'compare'` for `equals()`, `'expose'` for every
  operation that hands the raw value or part of it to the caller, and `'renew'` for a deadline
  extension. It had received the context alone, so a policy could refuse a read only on the class
  and the context, never on the label or the deadline of the value in front of it, while the
  `auditReveal` call three lines below it in the same gate already got the instance. Reads that
  only feed redaction or documented metadata, such as `toString()` and `length`, still never reach
  a policy. The parameters are additive: a hook written against the context-only form keeps
  working. It must not read the value it is handed, through `reveal()`, `equals()` or `mask()`,
  because the gate is not reentrant and the read would recurse until the stack is exhausted.
- `new SensitiveString()` throws a `TypeError` for a value that is not a string, naming the kind of
  value and never its content. It accepted anything: a number redacted like a string and then threw
  inside `equals()`, and an instance wrapped a second time revealed the inner instance rather than
  the value. Every derived value goes through the same check, so a `map()` callback that returns a
  non-string is refused as well. `fromOptional()` still maps `null`, `undefined`, and the empty
  string to `null`.
- The release workflow now reads the packages to release from `packages/` rather than from a
  hardcoded pair of steps per package. It offers all six in its dropdown, skips a package marked
  `private`, and carries `{dir, name, version}` through one output that every later step loops
  over. `decorators`, `eslint-plugin`, `nestjs`, and `testing` could not be released before this,
  and `all` released only `core` and `zod` while reporting success. Tags take the package's npm
  name, so `@platform-sec/eslint-plugin-sensitive-string` no longer has to match its directory.
  Workflow inputs reach the scripts through the environment rather than `${{ }}` interpolation.

### Fixed

- The redaction walks no longer fail when an object refuses a property read. `redactInStructure()`,
  `safeLog()`, `safeStringify()`, `containsSensitive()`, `sensitiveClassesIn()`, and `redactCopy()`
  each ask an arbitrary object a duck-type question or two: whether it carries the
  `__sensitive: true` marker that a `serialize()` result has, and in `redactCopy()` whether it has a
  `pipe` method and is therefore a stream. Both were plain property reads, and reading an absent
  property is not universally safe, because a Proxy may throw for an unknown name rather than
  answering `undefined`. envalid's `cleanEnv()` result is such a Proxy, so logging a validated
  configuration object through any of these helpers raised
  `ReferenceError: [envalid] Env var not found: __sensitive` instead of redacting anything, and it
  did so when the object was merely nested inside the record being logged, which is how it is
  normally logged. The probes now go through one guarded read that treats a refusal as absence, so
  the walk descends into the object and redacts every `SensitiveString` it holds as it would for any
  other object. Nothing that answers the question behaves differently.

- `safeStringify()` returns the string its signature promises. It forwarded `JSON.stringify`'s
  `undefined`, which is what that function returns for a value JSON cannot represent: `undefined`
  itself, a function, a class constructor, a symbol, or a root dropped by a caller's replacer.
  TypeScript's own lib declares `JSON.stringify` as returning `string`, so nothing flagged the
  mismatch and a caller who believed the declaration failed on the result rather than at the call.
  Those values now serialize as `'null'`, which is what `JSON.stringify` already substitutes for
  them in array position, so the return stays parseable. Deliberately not `String()`: a function's
  string form is its source text, which would put a static field's initializer into the output this
  function exists to keep safe.
- `safeStringify()` no longer throws on a `BigInt`. `JSON.stringify` rejects one with a `TypeError`
  rather than skipping it, so a single `id: 1n` anywhere in a payload took down the logging call
  that was meant to be the safe one. A `BigInt` now serializes as its decimal string, which is
  lossless where `Number()` would silently round anything past 2^53. A caller's `replacer` still
  runs first and sees the real value, so it can choose its own representation, and it keeps
  receiving the holder object as `this`.
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

- `redactInStructure()`, and with it `safeLog()`, `safeStringify()`, `createSensitiveSerializer()`,
  and the winston format, replace a `serialize()` result with the redaction of the class it names,
  or `'[REDACTED]'` for a class that is not registered. The serialized form is a plain object holding
  the raw value, so it passed through every log-path helper untouched and `JSON.stringify` emitted
  it; it was the one shape `toJSON()` could not catch. `containsSensitive()` now reports it and
  `sensitiveClassesIn()` counts the class it names, so `dropClasses` in the winston format refuses a
  record carrying a serialized credential as it refuses one carrying the instance.
- `redactInStructure()` walks the JSON form of a plain object that carries its own `toJSON`, as it
  already did for class instances. The plain-object copy kept the function and left it for
  `JSON.stringify` to call later, on a form the walk had never seen.
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
