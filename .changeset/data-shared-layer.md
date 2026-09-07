---
'@platform-sec/sensitive-string-data': minor
'@platform-sec/sensitive-string-typeorm': minor
'@platform-sec/sensitive-string-drizzle': minor
'@platform-sec/sensitive-string-prisma': minor
---

A shared layer under the ORM integrations, `sensitive-data`, extracted from the three that were
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
