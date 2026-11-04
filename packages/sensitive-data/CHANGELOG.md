# @platform-sec/sensitive-string-data

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

### Patch Changes

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

- 635b4c2: Stop paying for the failure the guards almost never find.

  Both of these guards run on every request and every statement, and both did work whose only consumer
  was a branch that does not fire. Neither change alters what is refused. What changes is what a clean
  request costs to clear.

  `assertNoMarker` percent-decoded every outgoing body before scanning it, which allocates two full
  copies of the body: one from `replace(/\+/g, ' ')` and one from `decodeURIComponent`. A JSON body
  contains neither `%` nor `+`, so `percentDecoded` is the identity on it and the decoded scan searches
  a string identical to the one just searched. The decode is now skipped when the body holds neither
  character, which is not a heuristic: with no `+` the replace has nothing to replace, with no `%` the
  decode has nothing to decode, so `decoded !== wire` was already dead and the branch was unreachable.
  Measured on Node 22.15.0 over a marker-free JSON body, median of seven rounds with each size in its
  own process: 1 KB from 2.6 us to 105 ns, 16 KB from 34.9 us to 613 ns, 128 KB from 366 us to 5.9 us.
  It is the only figure in this release that scales with payload size, so it is worth most to whoever
  sends the largest bodies.

  `+` is checked as well as `%`, and that half is load-bearing rather than defensive. A custom
  `registerPolicy` redaction may contain a space, a form encoder puts that space on the wire as `+`,
  and the resulting body carries the marker with no percent-escape anywhere in it. A check for `%`
  alone would skip that body without looking at it, and a test now fails if the `+` is removed. A
  second test compares the guard against an implementation that decodes unconditionally over a corpus
  of bodies, so the equivalence is asserted rather than argued.

  `findUnsafeParameter` walked the bound parameters through `parameterEntries`, which materialises a
  `[string, unknown][]`, then carried a path string down the recursion and allocated a `WeakSet` per
  container. On a bag with nothing wrong in it, which is every bag in a working application, all three
  are built and discarded. The walk now reads the three bag shapes in place, builds the path only while
  unwinding the branch that found something, and creates the cycle guard on the first descent rather
  than on entry. Measured the same way: 5 scalars from 237 ns to 81 ns, 6 named scalars from 486 ns to
  201 ns, 3 parameters with one nested array from 532 ns to 162 ns, a 4-level nesting from 1017 ns to
  372 ns.

  Whether that second one is worth having depends on the driver, and the doc comment says so rather
  than quoting the ratio alone. Against a networked Postgres, 300 ns is invisible. Against in-process
  `better-sqlite3`, where a small query is single-digit microseconds, it is a few percent of the
  statement.

  `parameterEntries` keeps its shape and its exported signature, but nothing calls it on the hot path
  any more, so two walkers now read the same three bag shapes. They are held together by a test that
  runs both over the same bags rather than by one calling the other, and adding a shape to one without
  the other fails it.

  Mutation testing found two coverage gaps that a green suite did not. Deleting the array segment from
  the path on the unwind passed every test, because no fixture had an offence nested inside a container
  inside an array, only inside an array directly. Removing the array cycle guard also passed, because
  the only cycle in the fixtures was an object cycle. Both are now in the corpus, along with a mutual
  cycle between an array and an object, and all six mutations of the new walk fail.

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
- Updated dependencies [59ace7a]
- Updated dependencies [29c6f87]
  - @platform-sec/sensitive-string-core@0.6.0
