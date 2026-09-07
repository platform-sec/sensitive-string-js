---
'@platform-sec/sensitive-string-prisma': minor
---

Add the Prisma integration: classified columns read back wrapped, and every write unwraps through an
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
survive. Core calls that hook with no context and with `details` of only `{ operation: 'reveal' }`,
so the package installs each per-value context as the ambient one for the duration of the reveal;
that is the only way a sink can read the tags.

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
