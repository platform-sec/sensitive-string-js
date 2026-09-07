---
'@platform-sec/sensitive-string-drizzle': minor
---

A Drizzle ORM integration. A classified column is declared in the schema, so a select returns a
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
keeps them: `params`, an own enumerable property; `message`, which interpolates them; and the header
of `stack`, which V8 composes once at construction, so rewriting the message alone would have moved
the leak into the field an error tracker is most likely to keep.

`checkSchema(db, schema)` runs once at boot and refuses a database built without the guard, a
configured query cache, which stores the driver's rows before any column's read side has run, and a
column named in `requireClassified` that was declared with a plain factory, which is the one drift
the compiler cannot see. It also reports a classified column carrying a column default, since that is
a secret in the schema file and in every migration generated from it.

A classified column declares a standard SQL type, so `drizzle-kit generate` and `drizzle-kit push`
are unaffected and adoption on an existing column is a type change rather than a migration.
`hydrateRawRows()` is the audited bypass for the two read paths Drizzle does not map, a `sql`
selection and `.values()`. A `sql` selection, `.values()`, `drizzle-kit` introspection, JSON columns
and the edge and serverless drivers are named in the README as uncovered.

The insert type is the same `SensitiveString` as the select type, because `customType` has one `data`
type serving both directions, so a literal in a predicate takes a cast. `strictWrites` is off by
default for the same reason.
