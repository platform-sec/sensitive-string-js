# @platform-sec/sensitive-string-drizzle

Drizzle ORM integration for [`SensitiveString`](../sensitive-core). Classified columns are declared
in the schema, so a select returns a `SensitiveString` in the type as well as in the value; every
write unwraps through an audited `reveal()`; and the two parameter paths Drizzle routes past the
column are refused rather than left to the driver.

## Installation

```bash
pnpm add @platform-sec/sensitive-string-drizzle @platform-sec/sensitive-string-core \
  @platform-sec/sensitive-string-data
```

Both `drizzle-orm` and the core package are peer dependencies. Core is a peer because
`redactInStructure`, `containsSensitive` and every other structural check is an `instanceof`, and two
copies of core in one application make all of them miss. `@platform-sec/sensitive-string-scrub` is an
optional peer, needed only for `drizzleScrubFragment`.

`@platform-sec/sensitive-string-data` is a peer too, and is what holds the parts every ORM package
in this family needs: the bound-parameter walk, the query-log redactor, the driver error sanitizer
and the write reveal context. You install it, and you do not otherwise interact with it.

No driver is a dependency, not even a dev one for the code that ships. The package never imports
`pg`, `mysql2` or `better-sqlite3`: it refuses a bad value _before_ the driver sees it, which is what
keeps the guard correct on a driver nobody has measured.

## Requirements

- Node 22.12 or later, ESM or CommonJS
- `drizzle-orm` 0.45 or later on the 0.x line. Measured against 0.45.2. `customType` has been stable
  since 0.30, which is what the peer range says, but only 0.45 is exercised by the suite
- Postgres, MySQL and SQLite, through the `/pg`, `/mysql` and `/sqlite` entry points
- Not supported on edge runtimes. Core needs `node:async_hooks` and `node:crypto`

## Quick start

```ts
// schema.ts
import { pgTable, serial, varchar } from 'drizzle-orm/pg-core';
import { credentialText, sensitiveText } from '@platform-sec/sensitive-string-drizzle/pg';

export const users = pgTable('users', {
  id: serial('id').primaryKey(),
  name: varchar('name', { length: 255 }),
  email: sensitiveText('email', { table: 'users' }).notNull(),
  passwordHash: credentialText('password_hash', { table: 'users' }).notNull(),
});
```

```ts
// db.ts
import { drizzle } from 'drizzle-orm/node-postgres';
import { checkSchema, sensitiveLogger } from '@platform-sec/sensitive-string-drizzle';
import * as schema from './schema.js';

export const db = drizzle(pool, { schema, logger: sensitiveLogger() });

// Refuses a database built without the guard, a configured query cache, and a
// column that should have been classified and was not.
checkSchema(db, schema, { requireClassified: ['password_hash'] });
```

```ts
const user = await db.query.users.findFirst({ where: eq(users.id, 1) });
user.email; // SensitiveString<'sensitive'>, in the type and in the value
user.passwordHash; // SensitiveString<'credential'>

await db.insert(users).values({
  name: 'ann',
  email: new SensitiveString('ann@example.com', 'sensitive'),
  passwordHash: new SensitiveString(hash, 'credential'),
});
```

## The thing to know before anything else

**In this package the logger is the parameter guard.** `sensitiveLogger()` is not a diagnostic that
you can leave out to save a log line. It is the security control, and a database constructed without
it has two unguarded paths.

Drizzle calls `logQuery(sql, params)` from inside every prepared query's execute path, with the
parameters in their final form and immediately before the driver call, on every session including
the ones a transaction opens for itself. That is the only seam in the ORM with all four of those
properties. `checkSchema()` refuses a database that does not have it.

It has to be passed at construction. Assigning to `db.session.logger` afterwards covers the outer
session only: `node-postgres` builds a **new session** for a transaction when the client is a pool,
from the options the first one was given, so a mutation after the fact does not follow.

## What the column covers, and what it does not

`customType` covers more of Drizzle than a `ValueTransformer` covers of TypeORM. Measured on 0.45.2
against a real database, all of these route through the column:

| Path                                                       | Covered                    |
| ---------------------------------------------------------- | -------------------------- |
| `insert().values()`, single and many                       | yes                        |
| `update().set()`, `delete()`                               | yes                        |
| `returning()`                                              | yes                        |
| `eq()`, `inArray()` and the other predicate builders       | yes                        |
| `onConflictDoUpdate({ set })`                              | yes                        |
| `select()`, partial `select({ ... })`                      | yes                        |
| `db.query.*` with `with:` and `columns:`                   | yes, including nested rows |
| subqueries, CTEs, `db.transaction()`                       | yes                        |
| a prepared statement whose values were bound at build time | yes                        |
| `sql.param(value, table.column)`                           | yes                        |

Two do not, because neither has a column behind it for Drizzle to consult:

- **A value interpolated into a `sql` template.** ``db.all(sql`... = ${value}`)`` binds the value
  directly. Use `sql.param(value, users.email)`, which does go through the column.
- **A prepared statement's placeholder.** `eq(col, sql.placeholder('e'))` followed by
  `.execute({ e: value })` substitutes the value into the parameter array after the statement was
  built. This is the form Drizzle's own documentation recommends for hot queries. A prepared
  _insert_ with `sql.placeholder` in `values()` is fine; it is the predicate form that escapes.

Both are refused by `sensitiveLogger()`, with `DrizzleParameterRefusedError`, before the driver runs.

An array or JSON column reaches the guard in a third shape. `text('tags').array()` and `jsonb('meta')`
serialise their contents to a string _before_ the parameter array exists, and a `SensitiveString`
serialises as its redaction marker, so there is no instance left to find by then. The guard catches
those on the marker instead, which is why it looks for a marker anywhere in a string rather than only
for an instance.

Two more are read paths rather than parameter paths, and neither can be refused because nothing goes
wrong at the driver: ``db.select({ e: sql`${users.email}` })`` and `.values()` both return the
plaintext, because the decoder is `sql`'s own or absent. `hydrateRawRows()` is the audited way back.

### What the drivers do with an unwrapped value

This is why the refusal is a refusal rather than a warning. Measured, with a real `SensitiveString`:

| Driver           | Result                                                                      |
| ---------------- | --------------------------------------------------------------------------- |
| `better-sqlite3` | throws `SQLite3 can only bind numbers, strings, bigints, buffers, and null` |
| `pg`             | binds `"[REDACTED:credential]"`, quotes included, and **reports success**   |
| `mysql2`         | escapes `` `klass` = 'credential', `label` = 'token' `` into the statement  |

On the two drivers that do not throw, the statement runs. The `pg` case is the dangerous one: the
write succeeds, the column holds the marker, and a later lookup by the same unwrapped value matches
the corrupted row because both sides are the marker.

## The two surfaces beside the column

### `DrizzleQueryError` carries the revealed parameters three times

Every failing statement on every dialect throws one, and it holds the bound values as `params`, an
own enumerable property; interpolated into `message`, as `Failed query: ${query}\nparams: ${params}`;
and in the header of `stack`, which V8 composes once at construction. By then the parameters are the
revealed plaintext, because that is what was sent.

The third copy is the one worth naming, and it is subtler than "rewrite the message and the stack
follows". `stack` is an own **accessor** on a real error and stays one; V8 formats it at first access
from whatever `message` says by then. So a sanitizer that fixed the message and left the stack looks
correct right up until something reads the stack first, which a logger, an APM agent or one
`console.error` between the throw and the `catch` does. From that point the string is fixed with the
plaintext in it. `sanitizeQueryError()` reads the stack through the getter, before the message moves,
and writes back a data property.

```ts
try {
  await db.insert(users).values(row);
} catch (error) {
  throw sanitizeQueryError(error);
}
```

`sanitizeQueryError()` removes all three, keeps `query`, `cause`, `name` and the frames, never throws,
and falls back to a copy with the same prototype when the error is frozen. `cause` is left alone: it
is the driver's own error, and Postgres puts the conflicting value in its `detail` for several
constraint classes. That is what `drizzleScrubFragment` covers on the way out to an error tracker.

### A query cache stores the rows before the column reads them

Drizzle's cache stores what the driver returned, which for a select is the rows before any
`mapFromDriverValue` has run. A cached query therefore puts the plaintext of every classified column
it selected into whatever store backs the cache. `checkSchema()` refuses a database with one
configured, unless you pass `{ allowCachedPlaintext: true }` and accept it in writing.

The key is a SHA-256 of the statement and its parameters, so the predicate values are not in the key.
The rows are the exposure.

## Types

The classification and the type come from the same declaration, which is the difference from the
Prisma and TypeORM integrations. There, classification is a string key checked against a schema, and
a typo leaves the column reading back unwrapped with nothing to say so. Here a name that does not
exist is a compile error.

```ts
type Selected = typeof users.$inferSelect;
// { id: number; name: string | null;
//   email: SensitiveString<'sensitive'>; passwordHash: SensitiveString<'credential'> }
```

**The insert type is the same `SensitiveString`.** Drizzle's `customType` has one `data` type serving
both directions, so widening the insert type to accept a plain string would widen what a select
returns by the same amount, which is the type lie this package exists to remove. A plain string still
works at runtime, so a literal predicate needs a cast:

```ts
// A compile error: `eq` takes the column's data type.
await db.select().from(users).where(eq(users.email, 'ann@example.com'));

// Either construct the value, which is the audited form,
await db
  .select()
  .from(users)
  .where(eq(users.email, new SensitiveString('ann@example.com', 'sensitive')));

// or cast, which puts the decision in the diff.
await db
  .select()
  .from(users)
  .where(eq(users.email, 'ann@example.com' as never));
```

`like()` needs a cast in the other direction, because it wants a string column and a string pattern.
The pattern does **not** go through the column's mapping, measured, so a plain pattern is bound as
given and an instance used as one would reach the driver, where the guard catches it.

## Nulls

The write side passes `null` through, and the column's nullability stays Drizzle's business. This is
worth stating because Drizzle skips the mapping for `null` almost everywhere, so it is easy to build
a column that refuses one and never notice: an insert, an update, an `onConflictDoUpdate` and every
predicate builder all bypass the mapping entirely. One path does not. A prepared statement whose
`values()` used `sql.placeholder` calls the write side at fill time with whatever `execute()` was
given, `null` included.

`undefined` is refused rather than treated as `null`. Both arrive by the same route and mean
different things: a missing placeholder key throws inside Drizzle, so an `undefined` that gets here is
a caller who thought they were passing a value, and writing NULL for it would overwrite a stored
credential on the quietest path available.

A value that is neither text nor a `SensitiveString` is refused rather than passed through, since a
classified column's declared type is text and nothing well typed can produce one. On the read side, a
value that is not a string raises `DrizzleColumnTypeError`, which is a different failure from
`DrizzleMarkerReadError` and has a different fix: the column is not carrying text, rather than
carrying a value an earlier write destroyed.

## The audit record

Every write is one `reveal()` under a child context that keeps the caller's `withRevealContext()`
name, reason, tags and `auditReveal` hook, and adds the table and the column:

```ts
await withRevealContext(
  { name: 'user-registration', tags: { requestId }, auditReveal: (v, d, ctx) => log(ctx) },
  async () => {
    await db.insert(users).values({ email, passwordHash });
  }
);
// two audit records, tagged { sink: 'drizzle', table: 'users', column: 'email' | 'password_hash',
//   klass, operation: 'unknown', requestId }
```

The ambient context reaches the column on every path, including inside `db.transaction()`, and it is
taken at execution rather than at description: Drizzle builds a statement's parameters when the query
is awaited, not when it is built. There is no second context store to configure, and there should not
be one; a package-local `AsyncLocalStorage` would compete with core's and drop the ambient hook.

`operation` is always `'unknown'`. `mapToDriverValue` is called with one argument and is not told
whether the value is being inserted, updated, or used as a predicate.

The volume is exactly one reveal per classified value per statement. There is no change-detection
pass, which is the cost that makes `save()` expensive in the TypeORM integration.

## The query log

`sensitiveLogger()` prints nothing unless you give it an inner logger. When you do, it censors the
parameters of any statement mentioning a column name this package has classified:

```ts
const db = drizzle(pool, { schema, logger: sensitiveLogger({ inner: new DefaultLogger() }) });
```

The censoring is positional-blind: it cannot tell which parameter belongs to which column without
parsing the statement, so a statement that touches a classified column loses all of its string
parameters. Numbers, booleans, dates and nulls survive, which keeps the ids and the limits that make
a log entry useful. `redactAllParameters: true` censors every string in every statement, for a log
shipped somewhere with a wider audience than the database.

A column classified some other way, in a view or in another service's tables, can be named through
`alsoClassified`.

## `checkSchema()`

Run it once at boot, after the database is constructed:

```ts
const { classified, skipped } = checkSchema(db, schema, {
  requireClassified: ['password_hash', 'ssn'],
});
```

It refuses:

- a database built without `sensitiveLogger()`, or with one built with `refuse: false`
  (`allowUnguarded: true` to proceed);
- a configured query cache (`allowCachedPlaintext: true` to proceed);
- a column named in `requireClassified` that was declared with a plain factory. This is the one drift
  the compiler cannot catch: `text('ssn')` where `sensitiveText('ssn')` was meant compiles, and
  stores plaintext;
- a classified column carrying a column default, which is a secret in the schema file and in every
  migration generated from it (`allowColumnDefaults: true` if the default is not one).

`classifiedColumns(schema)` reports the same inventory without enforcing anything.

It inspects tables. Anything else a schema module exports comes back in `skipped`, views included, so
a classified column reachable only through a view is neither counted nor checked. Name it in
`alsoClassified` on the logger if the log redaction should still know about it.

Classification is detected by asking the column: `checkSchema` runs each column's own
`mapFromDriverValue` over a sentinel and looks at what comes back. That is public API on Drizzle's
`Column` in every dialect, so the check does not depend on internals that a patch release can move.

## Migrations

A classified column declares a standard SQL type: `text` for `sensitiveText`, `varchar(n)` for
`sensitiveVarchar`. `drizzle-kit generate` and `drizzle-kit push` see exactly what they would see for
Drizzle's own `text()` and `varchar()`, and the SQL they write is unchanged. The classification lives
in the TypeScript schema and leaves no trace in the database.

Adopting the package on an existing column is therefore a type change and not a migration: swap
`text('email')` for `sensitiveText('email')`, fix what the compiler reports, and the table is
untouched. Backing it out is the same move in reverse.

`drizzle-kit` introspection does not generate classified columns, and is not meant to: there is
nothing in a database that says which columns are sensitive.

## Raw queries

`hydrateRawRows()` wraps the classified columns of rows that came back from a path Drizzle did not
map:

```ts
const rows = await db.execute(sql`select id, email from users`);
const users = hydrateRawRows(rows, usersTable);
users[0].email; // SensitiveString<'sensitive'>
```

Keys are matched against the database name and the schema key, and anything else is left alone. It is
not a substitute for the column: nothing about a raw path made the value safe on its way out of the
database, and the wrapping happens after it has already been an ordinary string in the process.

## Strict modes

Both are off by default and both are per column.

`strictWrites` refuses a plain string on the write path. It is off by default because a literal
predicate is an ordinary query and reaches the same mapping; with it off, a plain write is reported
once per column through `console.warn` when core's development mode is on, and costs one property
read otherwise.

`strictContext` refuses a write with no ambient `withRevealContext()`. It is off by default because a
row write happens on every request, and refusing one for want of a context turns a security library
into an availability incident.

```ts
sensitiveText('email', { table: 'users', strictWrites: true, strictContext: true });
```

## Cost

The guard runs on every statement. It walks the parameter array once and, for each string in it,
tests containment against the redaction markers the policy registry can currently produce, which is
two for the default policies and is memoized against the registered class list. There is no SQL
parsing on this path.

The log redaction costs more and only runs when an inner logger is configured: one regular expression
pass over the statement to collect its identifiers, then a set lookup each. A database constructed
with `sensitiveLogger()` and no `inner` pays the guard and nothing else.

## Not covered

Named here rather than implied, because silent partial coverage is worse than none:

- **Edge and serverless drivers** (`neon-http`, `d1`, `libsql`, `bun-sqlite`, `pglite`). The column
  factories are dialect-level and work; the guard depends on `logQuery` being called before the
  driver on that session, which is measured for `better-sqlite3`, `node-postgres` and `mysql2` only.
- **`drizzle-kit` introspection and `drizzle-kit studio`**, which read the database rather than the
  schema module.
- **JSON columns holding sensitive fields.** `sensitiveJson` is not shipped; wrap the fields with
  core's `wrapPaths` after reading.
- **Drizzle's relational query builder v2** (`defineRelations`), which 0.45.2 does not have.
- **`cause` on a query error**, which is the driver's own object. `drizzleScrubFragment` covers it on
  the way to a tracker.

## Errors

Every one extends `SensitiveStringError` and carries a `code`.

| Error                          | `code`                        | Raised by                        |
| ------------------------------ | ----------------------------- | -------------------------------- |
| `DrizzleConfigError`           | `DRIZZLE_INVALID_CONFIG`      | a column factory, at module load |
| `DrizzleWriteRefusedError`     | `DRIZZLE_WRITE_REFUSED`       | the column's write side          |
| `DrizzleMarkerReadError`       | `DRIZZLE_MARKER_IN_COLUMN`    | the column's read side           |
| `DrizzleParameterRefusedError` | `DRIZZLE_SENSITIVE_PARAMETER` | `sensitiveLogger()`              |
| `DrizzleGuardMissingError`     | `DRIZZLE_GUARD_MISSING`       | `checkSchema()`                  |
| `DrizzleCacheRefusedError`     | `DRIZZLE_QUERY_CACHE`         | `checkSchema()`                  |
| `DrizzleDriftError`            | `DRIZZLE_SCHEMA_DRIFT`        | `checkSchema()`                  |

## API

From `/pg` and `/mysql`: `sensitiveText`, `credentialText`, `sensitiveVarchar`, `credentialVarchar`.
From `/sqlite`: `sensitiveText`, `credentialText`. Each takes `(name)`, `(name, options)`,
`(name, klass)` or `(name, klass, options)`.

From the root, which imports no `drizzle-orm` at all: `sensitiveLogger`, `checkSchema`,
`classifiedColumns`, `classificationOf`, `sanitizeQueryError`, `hydrateRawRows`,
`drizzleScrubFragment`, `assertParametersSafe`, `touchesClassifiedColumn`, `redactParameters`,
`loggerBrand`, `containsRedactionMarker`, `redactionMarkers`, `sensitiveMapping`, and the errors.

## License

MIT
