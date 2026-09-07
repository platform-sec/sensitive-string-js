---
'@platform-sec/sensitive-string-typeorm': minor
---

Add the TypeORM integration: classified columns read back wrapped, writes unwrap through an audited
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
