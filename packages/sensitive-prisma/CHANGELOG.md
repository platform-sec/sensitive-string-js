# @platform-sec/sensitive-string-prisma

## 0.2.0

### Minor Changes

- 1c87ee4: A shared layer under the ORM integrations, `sensitive-data`, extracted from the three that were
  already built rather than designed ahead of them. It holds the bound-parameter walk, the query-log
  redactor, the statement identifier scan, the driver error sanitizer and the write reveal context.
  Nothing installs it directly; each ORM package takes it as a peer.

  Extracting from three consumers instead of one was the point, and it is a deliberate departure from
  how `scrub` and `secrets` were built. Those shipped alongside a single first consumer and held up,
  because their consumers are homogeneous. A `customType`, a `ValueTransformer` and a client extension
  are not, and every piece of this layer differs from what any one of the three had.

  Two of those differences were gaps in shipped code, and neither was reachable by the suite of the
  package that had it, because each package's development driver could not produce the shape the other
  covered.

  **The bound-parameter walk missed a shape in each direction.** TypeORM's descended into nested
  containers and terminated on cycles, but walked only arrays and objects whose prototype is
  `Object.prototype`, so a `Map` or a bag from another realm passed the guard unchecked. Drizzle's
  walked every object shape but stopped at one level, so an instance inside a nested filter object
  passed. The shared walk does both, and both packages gain what they were missing.

  **The error sanitizer had the message and stack half in one package only.** `DrizzleQueryError`
  interpolates the parameters into its message and V8 bakes that message into the stack header at
  construction, so Drizzle's sanitizer rewrote all three copies. TypeORM's rewrote the structured
  property alone, which is correct for `QueryFailedError` and leaves nothing for the next consumer
  whose message does carry a value. The machinery now exists once and is exercised by both shapes.

  Two behaviour changes in the ORM packages follow from unifying them:

  `DrizzleParameterRefusedError.parameter` is now a `string` rather than `number | string`. A numeric
  index cannot name a position inside a container, and the walk descends into one, so the field
  carries a path such as `0.filters[1]`.

  The TypeORM write context now tags a reveal with `klass`, which the Drizzle one already did, and the
  Prisma one now tags with `sink`, which neither of the others was missing. An audit sink receiving
  records from an application using more than one of these packages can now tell them apart.

  Prisma keeps its own reveal context builder, deliberately. The shared one is per column and carries
  one of six `WriteOperation` members; Prisma's is built once per operation, its `path` is a position
  in a nested argument object rather than a column, and its `operation` is Prisma's own free-form
  name. Filling the shared shape would mean reporting `unknown` for an operation that hook actually
  knows.

  Three things were deliberately not extracted, because three consumers proved they are not shared:
  the column specification, which is a path map in one, a model-keyed object in another and a
  declaration on the column itself in the third; the drift check, which reads entity metadata, the
  runtime data model and registered column objects respectively; and the `sensitive-scrub` fragments,
  which name different properties on different errors. Each package also keeps its own error types, on
  the same reasoning that kept `SecretWriteRefusedError` where it is.

- 820e703: Add the Prisma integration: classified columns read back wrapped, and every write unwraps through an
  audited reveal.

  ROADMAP 3.3, the Prisma half. Reads are a Prisma `result` extension, one computed field per
  classified column. Prisma applies a result extension per model wherever that model appears in a
  result, so relations loaded through `include` or `select` are covered by the same definition and this
  package never walks a result tree; the generated result types pick up each `compute`'s declared
  return type, so `select`, `include` and `omit` keep narrowing in the value and in the type. The
  design document left that as a spike. It is resolved affirmatively on Prisma 6.19.3 and 7.10.0:
  `user.email` is exactly `SensitiveString<'sensitive'>` rather than a union with `string`, and an
  `omit` of a classified field, per query or global, removes it from both the type and the value with
  no raw copy left under the original key.

  Writes do not work the way the design assumed, and the reason is worth stating because it inverts
  what the package is for. `applyQueryExtensions` calls `deepCloneArgs` before it hands arguments to
  any query hook, and that copy reproduces only the types Prisma knows: object enum values, field
  references, `Decimal`, `Date` and typed arrays. Every other class instance is rebuilt from a
  `for...in` copy, which cannot reach an ES `#private` field. A `SensitiveString` in `data` is
  therefore already `{ klass, label }` with no value behind it by the time a hook could see it, so no
  query extension can unwrap a write. `sensitiveInput()` does the reveal at the call site instead,
  which is the last point at which the value exists; it was already required there for Prisma's
  generated input types, so the amount of code at a call site is unchanged.

  What makes that the point rather than a technicality is the measurement on a client with no query
  extension. There is no clone, the instance reaches Prisma's serialiser, `toJSON()` is called, and the
  column ends up holding `[REDACTED:credential]`. The write reports success, and a later lookup by the
  same unwrapped value matches the corrupted row because both sides are the marker, so even a
  round-trip test passes. The secret is destroyed silently. The extension's query hook is what closes
  that: it refuses any operation still carrying the flattened remains of an instance, naming the model,
  the operation and the argument path, and it unwraps the one argument shape the copy does preserve,
  the `values` of a `$queryRaw`, `$executeRaw` or `$queryRawTyped` template. See ADR-003.

  Every unwrap is one `reveal()` under a child context tagged with the model, the operation and the
  argument path, layered on any ambient `withRevealContext()` so its `auditReveal` hook and tags
  survive. Core hands that context to the hook as its third argument, which is where a sink reads the
  tags.

  The names in the configuration are checked against the client when the extension is applied, which
  turned out to matter as much as anything else here. Neither TypeScript nor Prisma catches a typo:
  `models` is keyed by string, and measured three ways on both versions, Prisma ignores a result
  component under a model it does not know, adds a computed field under a name it does not know beside
  the real column rather than replacing it, and does not throw on a `needs` entry for a column that
  does not exist. In all three the configured column reads back as a plain string, so one wrong
  character turned the guarantee off with nothing said. `PrismaUnknownModelError` and
  `PrismaUnknownFieldError` are raised at `$extends` time instead, before a query runs.

  Also in this release: `wrapRows` for raw query results, since a type argument such as
  `$queryRaw<User[]>` is erased before the query runs; configuration validated when the extension is
  built rather than on the first query that reaches it; and `nullable` and `list` in a field spec,
  because the `compute` return type is what Prisma publishes and a nullable column typed as a required
  scalar is a lie the compiler propagates.

  Peer range is `@prisma/client@^6 || ^7`, measured on 6.19.3 and 7.10.0. Scalar lists are unit-tested
  against the real result builder rather than end to end, because the suite runs on SQLite, which has
  none; TypedSQL is matched by shape and not exercised end to end. Prisma's own query log carries bound
  parameters and no extension can intercept engine logging, so the README says not to enable query
  logging in production and a test pins the leak so a Prisma change is noticed.

### Patch Changes

- 3e054e2: Hand `auditReveal` the context the operation ran under.

  The hook was called with the value and the operation and nothing else, so a sink could not tell which
  unit of work a reveal belonged to. That is not a gap anyone works around cheaply: `sensitive-prisma`
  tags each unwrap with the model, the operation and the argument path, and `sensitive-typeorm` tags
  each column write with the table and the column, and both had to install their per-value context as
  the ambient one around every single reveal so a sink could recover the tags from
  `getCurrentRevealContext()` inside its own hook. One `AsyncLocalStorage` entry per sensitive value,
  paid to move three strings.

  `auditReveal(value, details, context)` now carries it. The context is the one passed to the call, or
  the ambient one when the call passed none, which is the same context the policy's
  `checkRevealAllowed` was asked to authorize, so an audit record and an authorization decision are
  comparable after the fact. It is not always the context the hook was installed on: a reveal under a
  `createChildContext()` is audited under the child, which is exactly what makes an integration's tags
  reachable. Both packages now reveal plainly, and the entry went with the workaround.

  The argument is typed as `AuditContext`: `name`, `reason` and `tags`, and no `auditReveal`, since the
  sink reading it is that hook. The narrowing is in the type and not in a copy, so a sink may compare
  the context by identity and an audited reveal allocates nothing; `tags` is the caller's own object,
  shared by every reveal under the context, so a sink copies out what it means to keep rather than
  writing to it.

  A hook written with two parameters is unaffected, in types and at runtime. Code that calls a
  context's `auditReveal` itself must pass the third argument; the only such caller in this repository
  was the worker handoff's hook forwarder, which now passes the receiving context through so a
  forwarded sink sees the work the sender named.

  In `sensitive-string-testing`, `AuditCall` gains `context` and `AuditEntry.contextName` is read from
  what core reports rather than from the log's own name, so an entry made under a nested child is
  recorded under the child. The recorded context is a one-level copy: a record pointing at the live
  mock context would close a cycle through `calls` that `JSON.stringify` could not walk. Both helpers
  degrade rather than throw when a caller forwards the hook with two arguments, recording the mock's
  own name; they run inside the reveal gate, where a `TypeError` would surface as a failing reveal in
  somebody's suite rather than as a missing tag.

- Updated dependencies [3e054e2]
- Updated dependencies [49ad21c]
- Updated dependencies [200a5c9]
- Updated dependencies [b362710]
- Updated dependencies [aa609af]
- Updated dependencies [14ed60e]
- Updated dependencies [7de6338]
- Updated dependencies [e721fbd]
- Updated dependencies [a90709f]
- Updated dependencies [785c101]
- Updated dependencies [f8377ff]
- Updated dependencies [1eb5030]
- Updated dependencies [dfe8ae4]
- Updated dependencies [342f7e4]
- Updated dependencies [1c87ee4]
- Updated dependencies [7de3033]
- Updated dependencies [98fd326]
- Updated dependencies [f1d6d96]
- Updated dependencies [5950b87]
- Updated dependencies [b92ff33]
- Updated dependencies [dbb643a]
- Updated dependencies [2c5bd7f]
- Updated dependencies [1c87ee4]
- Updated dependencies [635b4c2]
- Updated dependencies [59ace7a]
- Updated dependencies [29c6f87]
  - @platform-sec/sensitive-string-core@0.6.0
  - @platform-sec/sensitive-string-data@0.2.0
