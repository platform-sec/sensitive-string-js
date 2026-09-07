# @platform-sec/sensitive-string-typeorm

TypeORM integration for [`SensitiveString`](../sensitive-core). Classified columns read back wrapped,
every write unwraps through an audited `reveal()`, and the query builder path where TypeORM never
calls the transformer at all is refused rather than left to the driver.

## Installation

```bash
pnpm add @platform-sec/sensitive-string-typeorm @platform-sec/sensitive-string-core
```

Both `typeorm` and the core package are peer dependencies. Core is a peer because
`redactInStructure`, `containsSensitive` and every other structural check is an `instanceof`, and two
copies of core in one application make all of them miss. `@platform-sec/sensitive-string-scrub` is an
optional peer, needed only for `typeormScrubFragment`.

No driver is a dependency, not even a dev one for the code that ships. The package never imports
`pg`, `mysql2` or `better-sqlite3`: it refuses a bad value *before* the driver sees it, which is what
keeps the guard correct on a driver nobody has measured.

## Requirements

- Node 22.12 or later, ESM or CommonJS
- `typeorm` 1.x. Measured against 1.1.1. The `ValueTransformer` interface is unchanged from the 0.3
  line, so `>=0.3.20` is declared, but only 1.x is exercised by the suite
- Not supported on edge runtimes. Core needs `node:async_hooks` and `node:crypto`
- The TypeORM Mongo driver is not supported and not measured

## Quick start

```ts
import { Column, DataSource, Entity, PrimaryGeneratedColumn } from 'typeorm';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import {
  defineSchema,
  guardParameters,
  sanitizeQueryFailedError,
  sensitiveLogger,
} from '@platform-sec/sensitive-string-typeorm';

// One place names the class of every classified column.
export const schema = defineSchema({
  fields: {
    'users.email': 'sensitive',
    'users.password_hash': 'credential',
  },
  rules: [{ pattern: /(^|[._])(token|secret)([._]|$)/i, klass: 'credential' }],
  fallback: 'plain',
});

@Entity('users')
export class User {
  @PrimaryGeneratedColumn() id!: number;

  @Column({ type: 'text' })
  name!: string;

  @Column({ type: 'text', transformer: schema.column('users.email') })
  email!: SensitiveString<'sensitive'>;

  @Column({ type: 'text', name: 'password_hash', transformer: schema.column('users.password_hash') })
  passwordHash!: SensitiveString<'credential'>;
}

const ds = new DataSource({
  type: 'postgres',
  entities: [User],
  logging: ['query', 'error'],
  logger: sensitiveLogger(new AdvancedConsoleLogger('all'), schema),
});

await ds.initialize();
guardParameters(ds); // refuses the query builder bypass, below
schema.check(ds);    // drift, and the query result cache

const user = await ds.getRepository(User).findOneByOrFail({ id: 1 });
user.email; // SensitiveString<'sensitive'>: toString(), toJSON() and inspect all redact

await ds.getRepository(User).insert({
  name: 'ann',
  email: new SensitiveString('ann@example.com', 'sensitive'),
  passwordHash: new SensitiveString(hash, 'credential'),
});
```

## The thing to know before anything else

**The column transformer does not run for a query builder's named parameters.**

```ts
// The transformer is never called. The instance goes to the driver as it is.
await ds.createQueryBuilder(User, 'u').where('u.email = :e', { e: value }).getOne();
```

`u.email = :e` is a SQL fragment and `:e` is a name. Nothing connects the name to a column, so there
is no `ColumnMetadata` for TypeORM to consult and it binds the parameter map straight through. What
happens next belongs to the driver, and the three common ones disagree:

| Driver | What it binds |
|---|---|
| `better-sqlite3` | throws `SQLite3 can only bind numbers, strings, bigints, buffers, and null` |
| `pg` 8.23.0 | `"[REDACTED:sensitive]"`, quotes included, via `prepareValue` reaching `JSON.stringify` |
| `mysql2` 3.24.3 | `'[REDACTED:sensitive]'`, via `format`/`escape` stringifying |

Only SQLite fails loudly. On Postgres and MySQL the query runs, matches nothing, and a lookup
silently returns no rows; the same fragment in an `UPDATE ... SET` stores the marker. `mysql2` with
`SET ?` is worse again: `SensitiveString` has exactly two own enumerable properties, so it produces
valid SQL assigning `` `klass` `` and `` `label` `` to columns that do not exist.

Two answers, and you want both:

- `guardParameters(dataSource)` refuses an instance or a marker at the query runner, which is the
  only place that sees the parameter map between the query builder and the driver. It checks both
  shapes TypeORM passes: the positional array, and the named parameter map that
  `ds.query(sql, { e: value })` hands the runner unchanged. `better-sqlite3` rejects named
  placeholders, so the map is one more thing the driver you develop against will not show you.
- The find-options form runs the transformer normally, so it is the fix the refusal names:

```ts
await ds.createQueryBuilder(User, 'u').where({ email: value }).getOne();
```

## What it protects against, and what it does not

It stops a classified column from being logged, serialised or transmitted by accident, because what
you hold is an instance whose `toString()`, `toJSON()` and `inspect` all redact. It makes every write
of a classified value an audited `reveal()`. It refuses a write that would persist a redaction
marker, and raises on a read that finds one already there.

It does not encrypt anything. Both default policies set `allowPersistPlain: false`, which core
records as advice and does not enforce, so **this package writes plaintext to the database**. If the
column must not hold plaintext, put an encryption transformer under this one; see
[Composing with encryption](#composing-with-encryption).

It cannot give you the compile-time guarantee Drizzle's `customType` does. A TypeORM property is
typed by the annotation you write on the entity field, and no transformer can make the compiler check
that the annotation matches the specification. `schema.check(dataSource)` is the runtime answer.

There is no read-only and write-only subpath split. A `ValueTransformer` is one object holding both
directions, registered on the schema and loaded whenever the schema is, so the split cannot pass
through.

## What it does not see

Stated here because a partial-coverage claim that is not written down is a false one.

- **`ds.query()` and `qb.getRawMany()` return plaintext.** Neither has entity metadata for a
  transformer to hang off. `schema.hydrateRaw(table, rows)` is the explicit opt-in.
- **`Raw(alias => ...)`** builds SQL and binds nothing through the transformer.
- **Migrations and seed scripts** that write through `queryRunner.query()` bypass everything here.
- **`find({ select })`** that omits a classified column omits it entirely, which is safe; a caller who
  then reads the property gets `undefined` rather than a redacted value.
- **`softDelete()` is not erasure.** It sets `deletedAt` and leaves the row, classified columns
  included. A `deletedAt` column reads like a deletion to a compliance reviewer and is not one.
- **The `parameters` on a `QueryFailedError`** reach an error tracker unless
  `sanitizeQueryFailedError` is called from a catch block or an exception filter.
- **Memory.** Wrapping a string does not erase the string you wrapped.

## The three surfaces beside the column

Each is plaintext at rest or plaintext in a log, and none is reachable from a transformer.

### The query log prints the revealed value

`logging: ['query']` prints every statement with its bound parameters, and the transformer has
already run by then, so the parameters are the plaintext:

```
query: INSERT INTO "users"("name", "email") VALUES (?, ?) -- PARAMETERS: ["ann","ann@example.com"]
```

`sensitiveLogger(inner, schema)` delegates every method and rewrites the parameters of any statement
that mentions a classified column. Redaction is by column where the specification names one exactly,
and by identifier where a rule classified it; string parameters are replaced and everything else
(ids, timestamps, booleans) is kept, because a classified column's revealed value is always a string.
Over-redaction is the correct failure direction for a log.

Named parameter maps are redacted too, since `ds.query(sql, { e: value })` reaches the logger as that
object even though TypeORM's own `Logger` types the argument as an array.

It is opt-in through the `DataSource`'s own `logger` option, because a `DataSource` option cannot be
reached from a transformer and this package does not patch prototypes.

What it does not touch is the `error` argument of `logQueryError`. That is the driver's own error,
and on Postgres its `detail` can hold the conflicting value for several constraint classes. Statement
text is not rewritten either, so a `Raw()` fragment that inlined a literal is logged as written. Both
are the scrub fragment's territory rather than the logger's.

### `QueryFailedError` carries the revealed parameters

`parameters` is an own enumerable array of the bound values on every failing statement on every
driver, which is exactly what an error tracker serialises.

```ts
try {
  await repo.insert(row);
} catch (error) {
  throw sanitizeQueryFailedError(error);
}
```

It redacts in place where the property allows it and falls back to a copy with the same prototype
where it does not, so `instanceof`, `name`, `message` and the stack all survive. It never throws: it
works through property descriptors, so a getter is never invoked, and a frozen error or a null
prototype is handled rather than propagated. A `parameters` defined as an accessor is replaced by a
single censor entry rather than read, so the parameter count is lost and the value is not.

For an application already using `sensitive-scrub`, merge the fragment:

```ts
import { mergeScrubPolicy } from '@platform-sec/sensitive-string-scrub';
import { typeormScrubFragment } from '@platform-sec/sensitive-string-typeorm';

const policy = mergeScrubPolicy(yourPolicy, typeormScrubFragment);
```

It denies `parameters`, `query` and `driverError` as keys at any depth. `driverError` goes whole
because Postgres puts the conflicting value in its `detail` for several constraint classes; the
useful part, the SQLSTATE, is mirrored on the error itself as `code`. If your payload has an
unrelated `query` key, keep it with `allowKeys: [{ key: 'query', reason: '...' }]`.

### The query result cache stores plaintext in a second table

`cache: true` on the `DataSource` writes into a `query-result-cache` table, or into Redis. It caches
the driver's rows *before* `from()` runs, and it stores the statement with its bound parameters as
part of the cache key, so a cached query puts the plaintext of the columns it selected **and** of the
values it filtered on into a table with none of the first table's grants and a name no schema review
recognises as holding user data.

`schema.check(dataSource)` refuses it. A refusal rather than a warning, because the copy outlives the
request and a boot-time warning is a line nobody reads in a log nobody keeps. The bypass is
deliberately awkward to type:

```ts
schema.check(ds, { allowCachedPlaintext: true });
```

## Prefer `insert()` and `update()` over `save()`

Measured on TypeORM 1.1.1: for an entity with **N** classified columns of which **k** changed,
`save()` costs **2N + k** reveals. Two per column unconditionally, and no `UPDATE` at all when
nothing changed.

| Operation | Reveals | Statements |
|---|---|---|
| `insert(row)` | N | one INSERT |
| `update(criteria, patch)` | one per patched column | one UPDATE |
| `save(existing)`, nothing changed | 2N | **none** |
| `save(existing)`, k changed | 2N + k | one UPDATE |

`ColumnMetadata.getEntityValue` applies the transformer with no guard, and
`SubjectChangedColumnsComputer` applies it again to normalise the value before comparing it with the
database. The second reveal exists purely to answer "did this change", and its result is compared and
discarded. `reload: false` does not reduce it.

That is an audit-volume fact before it is a performance one. One record per reveal means `2N + k`
records per `save()`, and for a hot entity on a busy endpoint that is the audit sink falling over.

## The audit record

Every write inherits the ambient reveal context, so a request-scoped trail is not flattened into one
bucket per column:

```ts
await withRevealContext(
  {
    name: 'req-42',
    auditReveal: (value, details, context) =>
      logger.info('reveal', { klass: value.klass, ...context.tags }),
  },
  async () => repo.insert(row)
);
```

The tags carry `sink: 'typeorm'`, the `table`, the `column`, and `operation: 'unknown'`.

**`operation` is always `'unknown'`, permanently.** A `ValueTransformer` receives one argument. It is
not told whether the value is being inserted, updated, compared for change detection or used as a
predicate, and the only way to recover that is to read the stack, which is not something a security
library does in a hot path. An audit trail from this package is coarser than one from a hook with a
statement boundary, and it says so rather than guessing `'update'`.

The per-column context reaches the sink as the hook's third argument, which core hands it alongside
the value and the operation. It is the same context the policy's `checkRevealAllowed` was asked to
authorize, and it is not what `getCurrentRevealContext()` returns inside the hook: that is the
caller's own context, which names where the caller stood rather than which column this write was
for.

Coalesce on `{ sink, table, column }` if the volume is a problem.

## Drift, and what the compiler will not check

```ts
schema.check(dataSource);
```

Four directions, because all four failures are silent:

- a column the specification classifies with no transformer on it stores plaintext and hands the
  application a string where the property type promises a `SensitiveString`;
- a column carrying one of this package's transformers that the specification no longer classifies is
  a stale annotation nothing else reports;
- a transformer built for a *different* path than the column it sits on. It works, and it audits every
  reveal under the wrong column. That is what a copied `schema.column()` line looks like;
- **an exact `fields` entry that no column matches.** This is the quietest of the four and the one a
  renamed table or a mistyped column name produces: the entry classifies nothing, no column is
  wrapped, every read returns a plain string, and nothing else in the package is in a position to
  notice. One wrong character turns the whole guarantee off. Pass
  `{ allowUnmatchedFields: true }` for a specification deliberately shared across `DataSource`s,
  which is the one case where an entry with no column here is correct.

A `rules` entry cannot be checked this way, because a pattern has no list of names behind it. That
asymmetry is why the exact entries are worth writing out for the columns that matter.

Every finding is reported at once, so one run fixes them all. Drift is reported before the cache is
examined, so a `DataSource` with both problems reports the drift first. Run it in the test suite
unconditionally; at boot it is one walk of `entityMetadatas`, against the risk that a boot-time throw
in a security package is an outage in a deployment that was working a minute ago.

## Adoption is additive and reversible

The DDL for a transformed column is byte-identical to the DDL without it. Measured:
`createSchemaBuilder().log()` reports zero pending changes after adoption, and `migration:generate`
produces nothing. Adopting this package on an existing database is a one-line diff per column and
nothing else.

## Composing with encryption

`transformer` accepts an array, applied left to right on the way to the database and right to left on
the way back:

```ts
@Column({ type: 'text', transformer: [schema.column('users.email'), encryptAtRest()] })
email!: SensitiveString<'sensitive'>;
```

The reveal happens first going out and the wrap happens last coming in, so the encryption transformer
never sees a `SensitiveString` and this package never sees ciphertext.

**The order is load bearing.** Reversed, the first transformer receives the instance, stringifies it
through `toString()`, and what gets encrypted is the redaction marker. The write refusal does not
catch that and cannot: the marker has already been transformed by the time this package sees it. A
test in this package asserts the failure so the ordering rule is not just documentation.

## Raw queries

```ts
const rows = await ds.query('SELECT id, email FROM users');
const wrapped = schema.hydrateRaw('users', rows);
```

Keys are classified as `table.key`. `getRawMany()` on an entity selection returns `User_email` rather
than `email`; pass `{ aliasPrefix: 'User' }` to strip a prefix you know. Nothing is stripped by
default, because guessing at a separator would classify `api_key` by its `key` suffix.

## Strict modes

Both off by default, both worth turning on once a service is ready for them.

```ts
const schema = defineSchema(spec, { strictWrites: true, strictContext: true });
```

`strictWrites` refuses a plain string on the write path. It is off by default because
`find({ where: { email: 'ann@example.com' } })` with a literal hands `to()` a plain string and is an
ordinary query; the default reports it once per path when core's development mode is on and passes it
through. `strictContext` refuses a write with no ambient reveal context. It is off by default because
a row write happens on every request, and refusing one for want of a context turns a security library
into an availability incident.

## Cost

Measured on Node 22.15.0 against `better-sqlite3` in memory, which is the most hostile comparison
available: the control is the driver's own row parsing with no network in it at all. A query against
a real database has a round trip that dwarfs the difference.

For 200 rows of 6 text columns, one representative run of
`src/__benchmarks__/hydration.bench.ts`:

| Classified columns | Relative to the unwrapped control |
|---|---|
| 1 of 6 | at or below the noise floor |
| 3 of 6 | about 1.5x |
| 6 of 6 | about 2x |

Read these as ratios inside the benchmark's `describe` group and not as absolutes. Reproduce them on
your own machine with `pnpm bench`, and use `vitest bench --outputJson` and `--compare` for a
before-and-after: a single run of this benchmark has reported one wrapped column as *faster* than the
unwrapped control, which is what a machine under load does to a sequential measurement.

One deliberate false positive: the guard also refuses a bound string that *contains* a redaction
marker, which is what catches `ds.query('UPDATE users SET email = ?', [marker])`. A user who types
`[REDACTED:sensitive]` into a search box therefore gets a refusal rather than a result. That is the
trade the containment check makes, and it is stated here rather than tuned away, because a marker in
a bound parameter is otherwise indistinguishable from the corruption it exists to catch.

`guardParameters` adds one type check per bound parameter, with no allocation on the path a scalar
parameter takes. It does not separate from the noise on a trivial in-memory statement, and the
statement it guards is about to cross a socket.

## Errors

Every refusal extends `SensitiveStringError` and carries a `code`.

| Error | `code` | Raised by |
|---|---|---|
| `TypeOrmConfigError` | `TYPEORM_INVALID_CONFIG` | `defineSchema`, `schema.column`, `sensitiveColumn` |
| `TypeOrmWriteRefusedError` | `TYPEORM_WRITE_REFUSED` | the write transformer |
| `TypeOrmMarkerReadError` | `TYPEORM_MARKER_IN_COLUMN` | the read transformer, `hydrateRaw` |
| `TypeOrmParameterRefusedError` | `TYPEORM_SENSITIVE_PARAMETER` | the parameter guard |
| `TypeOrmDriftError` | `TYPEORM_SCHEMA_DRIFT` | `schema.check` |
| `TypeOrmCacheRefusedError` | `TYPEORM_QUERY_CACHE` | `schema.check` |

## API

| Export | What it is |
|---|---|
| `defineSchema(spec, defaults?)` | Compiles a specification; returns `classify`, `column`, `check`, `hydrateRaw` |
| `schema.check(ds, options?)` | `allowCachedPlaintext` and `allowUnmatchedFields` are the two bypasses |
| `sensitiveColumn(klass, options?)` | A transformer for one column, with no specification behind it |
| `guardParameters(dataSource)` | Wraps the query runner; returns an uninstall function |
| `assertParametersSafe(statement, parameters)` | The guard's check, for a caller with their own runner; takes an array or a named map |
| `sensitiveLogger(inner, schema)` | A `Logger` that redacts the parameters of classified statements |
| `sanitizeQueryFailedError(error)` | Removes `parameters` from a query error, in place or by copy |
| `typeormScrubFragment` | A `sensitive-scrub` policy fragment for a captured query error |
| `hydrateRawRows(schema, table, rows, options?)` | The free-function form of `schema.hydrateRaw` |
| `redactionMarkers()`, `containsRedactionMarker(value)` | The policy-derived marker set |
| `brandOf(transformer)` | The class, label and path a transformer of this package's carries |

## Notes on the specification

The key is `table.column` as the **database** spells them, not the entity class and property.
TypeORM lets both differ, and the transformer only ever sees the value, so the binding from path to
transformer is made by hand at the `@Column` site. That hand-written link is exactly what
`schema.check` verifies.

`fallback` is required and is normally `'plain'`. A wrongly wrapped column is an object where a
string was, so `row.status === 'active'` becomes permanently false and the application misbehaves in
a way that reads as a bug rather than as a security control. `schema.column()` on a path that
resolves to `'plain'` throws at module load, because a pass-through transformer is worse than no
transformer: it looks like coverage.

The bare column name is offered as an alias at every level, so a rule written `/password/` matches
`users.password_hash` without you anticipating the table.

## License

MIT
