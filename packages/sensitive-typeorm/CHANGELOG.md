# @platform-sec/sensitive-string-typeorm

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

- acf3c68: Add the TypeORM integration: classified columns read back wrapped, writes unwrap through an audited
  reveal, and the query builder path where TypeORM never calls the transformer is refused rather than
  left to the driver.

  ROADMAP 3.3, which did not list TypeORM as a target. Reads and writes are one `ValueTransformer`,
  built through `defineSchema()` so the class of a column is named once next to the entity rather than
  repeated at each `@Column` and drifting from it. That hook is the right one, it is exactly what the
  ORM advertises for intercepting column values, and it is sufficient for neither of the section's two
  security constraints on its own.

  **TypeORM does not call the transformer for a query builder's named parameters.** Measured on 1.1.1:
  `qb.where('u.email = :e', { e: value })` is a SQL fragment and a name, with no `ColumnMetadata`
  connecting the two, so the parameter map is bound straight to the driver. What happens next belongs
  to the driver and the three common ones disagree. `better-sqlite3` throws. `pg` 8.23.0 binds
  `"[REDACTED:sensitive]"`, quotes included, because `prepareValue` falls through to `JSON.stringify`
  for an object with no `toPostgres` and `toJSON()` returns the marker. `mysql2` 3.24.3 stringifies it
  to the same marker, and with `SET ?` produces syntactically valid SQL assigning the instance's two
  own enumerable properties, `klass` and `label`, to columns that do not exist. Only SQLite fails
  loudly; on the two drivers TypeORM applications overwhelmingly run on, the query executes and matches
  nothing, and the same fragment in an `UPDATE ... SET` stores the marker. This is the ORM's most-used
  query API. `guardParameters()` refuses an instance or a marker at the query runner, which is the only
  seam that sees the parameter map between the query builder and the driver, and it names the
  find-options form as the fix because that one does run the transformer.

  The guard checks both parameter shapes TypeORM passes. The positional array is the usual one; the
  named map is the other, because `ds.query(sql, { e: value })` hands the runner that object unchanged
  and `better-sqlite3` answers a named-placeholder statement with `Your driver does not support named
placeholders`, so an array-only check looks correct on the driver most suites run against. The
  logger redacts both shapes for the same reason: TypeORM's own `Logger` types the argument as an
  array and a named map arrives as an object.

  The wrapper has to be idempotent per runner, and that is not tidiness. The SQLite family's driver
  caches a single query runner and returns it from every `createQueryRunner()` call, while `pg` builds
  a fresh one each time, so a wrapper without a marker would layer itself once per call and no test
  written against `pg` would ever have shown it. The uninstall flips a flag those wrappers share
  rather than restoring each runner, because a guard that remembered runners in order to restore them
  would keep every query runner the process ever made alive, which on `pg` is one per query.

  Three more surfaces carry plaintext beside the column and none is reachable from a transformer.
  `logging: ['query']`, which appears in most getting-started templates, prints every statement with
  its bound parameters, and the transformer has already run by then, so what is printed is the revealed
  value; `sensitiveLogger()` rewrites the parameters of any statement mentioning a classified column.
  `QueryFailedError` carries `parameters` as an own enumerable array on every failing statement on
  every driver, which is exactly what an error tracker serialises;
  `sanitizeQueryFailedError()` removes it through property descriptors so a throwing getter is never
  invoked, in place where the property allows it and by a prototype-preserving copy where it does not,
  and `typeormScrubFragment` is the `sensitive-scrub` seam for a payload that already reached a sink.
  And `cache: true` writes into a second table with none of the first table's grants: measured, it
  stores the driver's rows before the read transformer runs **and** the statement with its bound
  parameters as part of the cache key, so a cached lookup by a classified column leaks the predicate
  even when it selects nothing classified. `schema.check()` refuses it unless
  `allowCachedPlaintext: true` says otherwise in writing.

  Two measurements shape the README rather than the code. `save()` on an entity with N classified
  columns of which k changed costs `2N + k` reveals, because `ColumnMetadata.getEntityValue` applies
  the transformer unguarded and `SubjectChangedColumnsComputer` applies it again to answer "did this
  change" and then discards the answer; at k = 0 that is 2N reveals and no `UPDATE` statement at all.
  So `insert()` and `update()` are recommended over `save()` with a number behind it, and it is an
  audit-volume recommendation before it is a performance one. And `operation` in the audit tags is
  always `'unknown'`, permanently: a `ValueTransformer` receives one argument and is not told whether
  the value is being inserted, updated, compared for change detection or used as a predicate, and the
  only way to recover that is to read the stack, which is not something a security library does in a
  hot path.

  Both directions of the transformer guard `value == null` rather than `value === null`, which is one
  character and two ordinary paths: `IsNull()` on a nullable classified column routes through
  `transformValue` with no operand, and `upsert` passes `undefined` for a column the row object omits.
  A transformer that guards only `null` throws a `TypeError` from inside the ORM on both, and a test
  asserts that so the correction cannot silently regress.

  The package imports no `typeorm` and no driver at runtime. Every ORM type it reads is restated
  structurally, which keeps it correct in a process holding two copies of the ORM and is what lets the
  guard be right about a driver nobody has measured.

  `schema.check()` catches configuration drift in four directions, and the fourth is the one worth
  naming: an exact `fields` entry that no column on the `DataSource` matches. That is what a renamed
  table or a mistyped column name produces, and it is the failure that looks most like success,
  because the entry classifies nothing, no column is wrapped, every read returns a plain string where
  the property type promises an instance, and every other check passes. `allowUnmatchedFields` is the
  bypass for a specification deliberately shared across `DataSource`s. A `rules` entry cannot be
  checked this way, since a pattern has no list of names behind it, and the README says so. The other
  three are a classified column with no transformer, a transformer the specification no longer
  classifies, and a transformer built for a different path than the column it sits on, which works and
  audits every reveal under the wrong column.

  The DDL for a classified column is byte-identical to the DDL without it, measured, so adoption is a
  one-line diff per column with no migration.

  Named as uncovered in the README rather than implied: `ds.query()` and `getRawMany()` return
  plaintext, with `hydrateRaw()` as the audited bypass; `Raw()` builds SQL and binds nothing;
  migrations and seed scripts bypass everything here; `softDelete()` leaves the plaintext row; there is
  no read and write subpath split, because a `ValueTransformer` is one object holding both directions;
  and there is no compile-time guarantee, because a TypeORM property is typed by the author's own
  annotation and no transformer can make the compiler check it. The Mongo driver is not supported and
  not measured. See ADR-004.

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

- 1c87ee4: `containsRedactionMarker()` and `redactionMatchers()` in core, replacing four separate answers to
  the same question: given a string about to be written to a column, sent in a request body or stored
  in a secret, does it carry the text a `SensitiveString` renders as? `sensitive-http` derived its
  answer from the policy registry, `sensitive-typeorm` and `sensitive-drizzle` each shipped a narrower
  copy of that derivation, and `sensitive-secrets/write` used a hardcoded `[REDACTED:`. Core owns the
  format, so the detector lives there and the four call it.

  Two gaps close, both in the database packages and both security-relevant.

  **`markerPattern` was ignored.** Core declares it on `SensitivityPolicy` for a policy whose redaction
  varies with the value, `deterministicRedaction()` sets it, and core's own documentation for the field
  names the http guard as its consumer. The two copies written for a database did not read it, so a
  deployment using deterministic redaction had a marker check in front of its columns that could not
  recognise its own markers.

  **A marker for an unregistered class went unrecognised.** Both copies enumerated the registry and
  looked for `[REDACTED:${klass}]` per class. For a reader that is the ordinary case rather than an
  edge one: the column was written by an older release, or by a service that registered a class this
  process does not have. The detector matches the `[REDACTED:` prefix, which covers those, and also
  catches a marker that a composed transformer altered without destroying.

  `policyRegistryVersion()` is new and exported. The memo is keyed on it rather than on the set of
  registered class names, because an `overwrite` re-registration replaces a policy's `redact` while
  leaving the names identical, and both copies kept answering from the previous policy until something
  else changed.

  `sensitive-typeorm` and `sensitive-drizzle` no longer export `redactionMarkers` or
  `resetMarkerCache`; they re-export core's `redactionMatchers` and `resetRedactionMarkerCache`
  instead. `redactionMatchers()` returns `(string | RegExp)[]` rather than a `Set<string>`, since a
  `markerPattern` is a pattern.

- 2c5bd7f: Three fixes from reviewing the extracted layer, one of them a leak that existed in
  `sensitive-typeorm` before the extraction and was carried into the shared code.

  **A nested driver error that would not take the censor in place was returned with its plaintext.**
  `sanitizeQueryError` censors the parameter property on the error and on any nested one a shape
  names, and falls back to a copy of the outer error when a property will not move. That copy carried
  the nested error across by descriptor, so a frozen `driverError`, or one whose parameter property is
  a non-configurable accessor, ended up on the returned error with the original values still on it.
  The outer error reads as sanitized, which makes this the worst of the three possible outcomes rather
  than a partial fix. A censored copy of the nested error now goes onto the outer copy. Neither
  package's fixtures had a nested error that resists a write, which is why neither suite saw it.

  **The total-failure path dropped a message that was safe to keep.** When everything else fails,
  `sanitizeQueryError` returns a minimal error. For a shape that declares no `sanitizeMessage`, which
  is a measurement that the ORM's message carries no value rather than a default, the original message
  and stack are the diagnosis and are now carried across. This restores what `sensitive-typeorm` did
  before the extraction.

  **The recovery path could throw from the function whose contract is that it does not.** The `catch`
  that produces the minimal error read `message`, `name` and `stack` as plain properties, so a
  throwing getter there escaped `sanitizeQueryError` entirely, at the one moment the contract is being
  relied on. Every read in that path is now guarded individually, so a single hostile property costs
  only that property rather than the whole recovery, and the path as a whole is guarded again beneath
  that. Carried in from `sensitive-typeorm`, where the same three reads were unguarded.

  **The Drizzle logger scanned each statement twice.** `touchesClassifiedColumn` called the shared
  predicate once per column set, and the shared predicate scans the statement for identifiers. It now
  scans once and checks both sets against the one result, which is what that package's README already
  claimed. This is on the path that runs for every query the process makes.

  Two README claims are corrected to match the code. The TypeORM composition section said the write
  refusal "does not catch that and cannot" for a reversed transformer array; since the marker detector
  moved to core it matches the `[REDACTED:` prefix, so it does catch a transform that leaves the prefix
  intact and still cannot catch one that destroys it. Both halves are now asserted. The Drizzle cost
  section described the marker memo as keyed on the registered class list, which is no longer how it
  works.

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
- Updated dependencies [f67efd7]
- Updated dependencies [48f6213]
- Updated dependencies [29c6f87]
  - @platform-sec/sensitive-string-core@0.6.0
  - @platform-sec/sensitive-string-scrub@0.2.0
  - @platform-sec/sensitive-string-data@0.2.0
