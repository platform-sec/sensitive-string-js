# @platform-sec/sensitive-string-drizzle

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

- 8e492e7: A Drizzle ORM integration. A classified column is declared in the schema, so a select returns a
  `SensitiveString` in the type as well as in the value; every write unwraps through an audited
  `reveal()`; and the two parameter paths Drizzle routes past the column are refused rather than left
  to the driver. Everything below was measured against `drizzle-orm` 0.45.2, `better-sqlite3` 12.11.1,
  `pg` 8.23.0 and `mysql2` 3.24.3.

  Reads and writes are one `customType` mapping, and that hook covers considerably more of this ORM
  than a `ValueTransformer` covers of TypeORM: inserts, updates, deletes, `returning()`, the predicate
  builders, `onConflictDoUpdate`, partial selects, subqueries, transactions, a prepared statement whose
  values were bound at build time, `sql.param()`, and the relational query builder's nested rows all
  route through it. It is also the only integration in the family where the classification and the
  TypeScript type come from a single declaration, so `$inferSelect` carries `SensitiveString` through
  relations and partial selects, and a misspelled column name is a compile error rather than a column
  that quietly reads back plain.

  **The logger is the parameter guard.** Two paths reach the driver without a column behind them: a
  value interpolated into a `sql` template, and a prepared statement whose predicate is
  `eq(col, sql.placeholder('x'))`, which is the form Drizzle's own documentation recommends for hot
  queries. Both hand the instance to the driver, where `better-sqlite3` throws, `pg` binds
  `"[REDACTED:credential]"` and reports success, and `mysql2` escapes the instance's two enumerable
  properties into the statement. `logQuery(sql, params)` is the only seam in the ORM called with a
  statement's parameters after the placeholders are filled and immediately before the driver runs, on
  every session including the ones a transaction opens for itself, so `sensitiveLogger()` is both the
  log redaction and the refusal. It is passed to `drizzle()` at construction and cannot be installed
  afterwards, because `node-postgres` builds a fresh session for a transaction on a pool.

  `sanitizeQueryError()` removes the revealed parameters from all three places `DrizzleQueryError`
  keeps them: `params`, an own enumerable property; `message`, which interpolates them; and `stack`.
  The third needs care. `stack` is an own accessor on a real error and stays one, and V8 formats it at
  first access from whatever `message` says by then, so fixing the message alone looks correct until
  something reads the stack first, which a logger or an APM agent between the throw and the `catch`
  does. The stack is read through the getter, before the message moves, and written back.

  `checkSchema(db, schema)` runs once at boot and refuses a database built without the guard, a
  configured query cache, which stores the driver's rows before any column's read side has run, and a
  column named in `requireClassified` that was declared with a plain factory, which is the one drift
  the compiler cannot see. It also reports a classified column carrying a column default, since that is
  a secret in the schema file and in every migration generated from it.

  Both directions pass `null` through. Drizzle skips the mapping for `null` almost everywhere, which
  makes a column that refuses one look correct against an ordinary insert; one path does send one,
  namely a prepared statement whose `values()` used `sql.placeholder` and whose `execute()` supplied
  `null`. A value that is neither text nor a `SensitiveString` is refused on the write path, and a
  non-string read back raises `DrizzleColumnTypeError`, which is a different failure from a column an
  earlier write corrupted.

  A classified column declares a standard SQL type, so `drizzle-kit generate` and `drizzle-kit push`
  are unaffected and adoption on an existing column is a type change rather than a migration.
  `hydrateRawRows()` is the audited bypass for the two read paths Drizzle does not map, a `sql`
  selection and `.values()`. A `sql` selection, `.values()`, `drizzle-kit` introspection, JSON columns
  and the edge and serverless drivers are named in the README as uncovered.

  The insert type is the same `SensitiveString` as the select type, because `customType` has one `data`
  type serving both directions, so a literal in a predicate takes a cast. `strictWrites` is off by
  default for the same reason.

### Patch Changes

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
