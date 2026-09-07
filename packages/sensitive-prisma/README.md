# @platform-sec/sensitive-string-prisma

Prisma integration for [`SensitiveString`](../sensitive-core). Configured columns read back wrapped,
including through relations, and every write unwraps through an audited `reveal()`.

## Installation

```bash
pnpm add @platform-sec/sensitive-string-prisma @platform-sec/sensitive-string-core
```

Both `@prisma/client` and the core package are peer dependencies. Core is a peer because
`redactInStructure`, `containsSensitive` and every other structural check is an `instanceof`, and two
copies of core in one application make all of them miss.

## Requirements

- Node 22.12 or later, ESM or CommonJS
- `@prisma/client` 6 or 7. Both are measured: Prisma 6.19.3 and 7.10.0 behave identically for
  everything this package relies on. 5.x is untested and not claimed
- Not supported on edge runtimes. Core needs `node:async_hooks` and `node:crypto`

## Quick Start

```ts
import { PrismaClient } from './generated/prisma/client.js';
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { sensitiveExtension, sensitiveInput } from '@platform-sec/sensitive-string-prisma';

const prisma = new PrismaClient({ adapter }).$extends(
  sensitiveExtension({
    models: {
      User: {
        email: 'sensitive',
        passwordHash: 'credential',
        nickname: { klass: 'sensitive', nullable: true },
      },
      PaymentMethod: { cardNumber: 'credential', cardCvv: 'credential' },
    },
  })
);

// Reads come back wrapped, with the types to match.
const user = await prisma.user.findUniqueOrThrow({ where: { id: 1 } });
user.email;        // SensitiveString<'sensitive'>
user.passwordHash; // SensitiveString<'credential'>
user.name;         // string, because it is not configured

// Writes unwrap at the call site.
await prisma.user.update({
  where: { id: 1 },
  data: sensitiveInput({ passwordHash: new SensitiveString(hash, 'credential') }),
});
```

## What it protects against, and what it does not

It stops a configured column from being logged, serialised or transmitted by accident, because what
you hold is an instance whose `toString()`, `toJSON()` and `inspect` all redact. It makes every write
of a sensitive value an audited `reveal()`. And it refuses, by name, a write that would have
persisted a redaction marker instead of the secret.

It does not encrypt anything. Both default policies set `allowPersistPlain: false`, which core
records as advice and does not enforce, so this package works today and writes plaintext to the
database. If the column must not hold plaintext, encrypt it; a future enforcement mode may start
denying reveals whose context name is `prisma`.

It cannot remove the copy the value arrived in. Wrapping a string does not erase the string you
wrapped, and Prisma's own query log is outside any extension's reach (see
[Query logging](#query-logging)).

## Why writes need `sensitiveInput()`

This is the part of the integration that is not obvious, so it is worth stating plainly.

Prisma copies query arguments before it hands them to an extension.
`applyQueryExtensions` calls `deepCloneArgs`, and `deepCloneValue` reproduces only the types Prisma
knows: object enum values, field references, `Decimal`, `Date` and typed arrays. Every other class
instance is rebuilt as a plain object from a `for...in` copy, which keeps the enumerable own
properties and drops the prototype. A `SensitiveString` keeps its value in an ES `#private` field, so
what survives that copy is `{ klass, label }` and nothing else.

An extension therefore **cannot** unwrap a write. By the time any query hook runs, the value is
already gone. `sensitiveInput()` does the unwrapping where the value still exists, in your code,
under whatever reveal context you established.

What happens if you forget it depends on whether this extension is installed:

| | Result |
|---|---|
| With the extension | `PrismaUnwrappedValueError`, naming the model, the operation and the argument path. Nothing is written |
| Without it | Prisma serialises the instance through `toJSON()` and the column ends up holding `[REDACTED:credential]`. The write reports success |

That second row is measured on Prisma 6.19.3 and 7.10.0 and is the reason the guard exists. The
secret is destroyed, nothing surfaces the mistake, and a later lookup by the same unwrapped value
matches the corrupted row, so even a round-trip test passes.

The compiler catches it first in the ordinary case: Prisma's generated input types say `string`, so a
`SensitiveString` in `data` does not compile. The guard is what catches the cases where a cast, an
`any`, or a generic helper got around that.

## Reads

Reads are a Prisma `result` extension: one computed field per configured column. Prisma applies a
result extension per model wherever that model appears in a result, so relations are covered by the
same definition, and the generated result types pick up each `compute`'s return type.

```ts
const user = await prisma.user.findUniqueOrThrow({
  where: { id: 1 },
  include: { posts: { include: { author: true } } },
});
user.posts[0].author.email; // SensitiveString<'sensitive'>

const partial = await prisma.user.findUniqueOrThrow({
  where: { id: 1 },
  select: { id: true, email: true },
});
partial.email; // SensitiveString<'sensitive'>; partial.name does not exist
```

`select`, `include` and `omit` keep narrowing normally, in the value and in the type, because none of
it is a parallel type layer over Prisma's output. A per-query or global `omit` of a configured field
removes it from both, with no raw copy left under the original key.

A computed field is evaluated on first access and then replaced by a data property, so within one
result object the instance is stable and `user.email === user.email`. Two separate queries produce
two instances, so compare with `equals()` rather than `===`.

**Null and empty.** A `null` column stays `null`. The empty string is wrapped rather than turned into
`null`, so a required `String` column typed `SensitiveString<C>` does not become nullable because a
row holds `''`. Use `isEmpty()` on the instance. This deliberately differs from
`SensitiveString.fromOptional`.

**Nothing wraps by surprise.** A model or field absent from the configuration is returned exactly as
Prisma produced it.

## Configuration

```ts
sensitiveExtension({
  models: {
    // Model keys use the schema's casing; the extension maps them to Prisma's
    // client casing (`PaymentMethod` -> `paymentMethod`).
    User: {
      email: 'sensitive',                              // label defaults to the field name
      passwordHash: { klass: 'credential', label: 'password' },
      nickname: { klass: 'sensitive', nullable: true }, // String?
      recoveryCodes: { klass: 'credential', list: true }, // String[]
    },
  },

  // Name and reason for reveals the extension performs when no ambient context
  // supplies them. Optional.
  writeContext: { name: 'prisma-write', reason: 'database persistence' },

  // Refuse a query still carrying an unwrapped SensitiveString. On by default.
  detectUnwrapped: true,
});
```

`nullable` and `list` describe the column and decide the published type; the runtime follows the
value it is given either way, so getting one wrong produces a wrong type rather than a failed read or
an unwrapped value. Keep them matching the schema.

The configuration is validated when `sensitiveExtension()` is called, so an unregistered sensitivity
class or a malformed entry throws at startup rather than on the first query that reaches it. Unknown
model and field names are caught by TypeScript against the generated client, and by Prisma on the
first query that touches them.

Turn `detectUnwrapped` off only for a schema with two columns named `klass` and `label` where the
first holds a registered class name, which is the one shape the check can misread.

## The audit trail

Every unwrap is one `reveal()` and one audit entry. An ambient context set with `withRevealContext()`
is inherited, hook and tags included, and each reveal runs under a child context tagged with the
model, the operation and the argument path.

```ts
await withRevealContext(
  {
    name: 'password-reset',
    auditReveal: (value) => {
      // Core hands this hook the value and `{ operation: 'reveal' }` and no
      // context, so read the context the reveal is running under.
      const tags = getCurrentRevealContext()?.tags;
      logger.info('revealed', { klass: value.klass, ...tags });
    },
  },
  async () => {
    await prisma.user.update({
      where: { id: userId },
      data: sensitiveInput(
        { passwordHash: new SensitiveString(hash, 'credential') },
        { model: 'User', operation: 'update' }
      ),
    });
  }
);
// { klass: 'credential', model: 'User', operation: 'update', path: 'passwordHash' }
```

The ambient `name` and `reason` outrank `writeContext` and the extension's defaults, because they
name the unit of work the caller cares about; the model and the field are not lost by deferring to
them, since both travel in the tags.

`sensitiveInput()` knows only what you tell it, so pass `{ model, operation }` when you want them in
the tags. Reveals the extension performs itself, on raw parameters, always carry the operation.

A bulk write is one reveal per value: a `createMany` of ten thousand rows with one configured column
produces ten thousand audit entries. Count them rather than logging each one if that matters.

## Raw queries

**Parameters.** A `SensitiveString` interpolated into a `$queryRaw` or `$executeRaw` tagged template
is unwrapped by the extension before the statement reaches the driver. This works where the model
path does not because `deepCloneArgs` rebuilds a `Sql` with its `values` array by reference, leaving
the instances intact.

```ts
await prisma.$executeRaw`
  UPDATE users SET password_hash = ${newHash} WHERE id = ${id}
`;
```

The `Unsafe` variants take their parameters through the same copy that flattens a model argument, so
they need `sensitiveInput()` like any other write:

```ts
await prisma.$executeRawUnsafe(
  'UPDATE users SET password_hash = ? WHERE id = ?',
  ...sensitiveInput([newHash, id])
);
```

A `SensitiveString` passed as the *statement text* of an `Unsafe` call is refused
(`PrismaUnsafeStatementError`). That argument is interpolated rather than bound, so revealing it
would write the value into SQL.

**Results.** Raw results cannot be wrapped automatically: a type argument such as `$queryRaw<User[]>`
is erased before the query runs, and the hook is handed `model: undefined` for every raw operation.
Use `wrapRows`, and alias columns back to the configured field names.

```ts
const rows = await prisma.$queryRaw<{ id: number; email: string; passwordHash: string }[]>`
  SELECT id, email, password_hash AS "passwordHash" FROM users WHERE id = ${id}
`;
const users = wrapRows(rows, { email: 'sensitive', passwordHash: 'credential' });
users[0].email; // SensitiveString<'sensitive'>
```

## Composing with other extensions

Apply this one wherever you like; a later extension still sees wrapped results. If another extension
claims a field this one configures, the later one wins, as Prisma's protocol says. What it wins is
this extension's output rather than the column: `needs` resolves through the computed field, so a
later `compute` receives the `SensitiveString` and cannot reach the raw value through it.

## Query logging

Query-level log events carry the bound parameters, whether `emit` is `stdout` or `event`, and Prisma
offers no option to redact them. A client extension cannot intercept engine logging, so this is not
something the package can fix.

- Do not enable `query` level logging to stdout in production.
- With `emit: 'event'`, drop `params` before forwarding the event.

```ts
prisma.$on('query', ({ params: _params, ...event }) => logger.debug('query', event));
```

The suite pins this: a test asserts the leak exists, so a Prisma release that changes it is noticed
rather than silently making this section wrong.

## Errors

Every refusal extends core's `SensitiveStringError` and carries a stable `code`. None of them puts a
value in the message.

| Class | `code` | Raised when |
|---|---|---|
| `PrismaConfigError` | `PRISMA_INVALID_CONFIG` | The configuration is malformed or names an unregistered class. At startup |
| `PrismaUnwrappedValueError` | `PRISMA_UNWRAPPED_VALUE` | An argument still carries a `SensitiveString` that `sensitiveInput()` never unwrapped |
| `PrismaFieldTypeError` | `PRISMA_FIELD_NOT_A_STRING` | A configured column is not a string |
| `PrismaUnsafeStatementError` | `PRISMA_SENSITIVE_STATEMENT` | A `SensitiveString` was passed as raw statement text |

## Limits worth knowing

Each of these is a path this package does not fully cover. They are listed rather than left to be
discovered, because partial coverage nobody knows about is worse than none.

- **Scalar lists** (`String[]`) are wrapped element by element, and that path is covered by unit tests
  over the real result builder rather than end to end. The suite runs on SQLite, which has no scalar
  list type; covering it against a database means a second provider and a second generated client.
- **TypedSQL** (`$queryRawTyped`) is handled: its argument carries `values` by reference like a
  tagged template, so parameters are unwrapped. It is matched by shape and is not exercised
  end to end, because generating typed SQL needs a live database at generate time.
- **MongoDB.** `$runCommandRaw` takes its arguments through the copy that flattens instances, so
  documents need `sensitiveInput()`. Composite (embedded) types are not models and cannot carry a
  computed field, so fields inside them are not wrapped on read.
- **Middleware.** `$use` was deprecated in Prisma 4.16 and removed in Prisma 7. Extensions only.
- **Memory.** Nothing here addresses heap dumps or V8 persistence; JavaScript has no secure memory
  primitives, and this is defence in depth.

## Exports

| Export | Purpose |
|---|---|
| `sensitiveExtension(config)` | The client extension. Pass to `$extends()` |
| `sensitiveInput(value, attribution?)` | Unwrap a write argument through an audited reveal |
| `wrapRows(rows, fields, model?)` | Wrap the configured columns of raw query rows |
| `normalizeConfig`, `normalizeModelFields`, `clientKey` | Configuration validation, exported for tooling |
| `buildResultComponent`, `revealArgs`, `revealRawArgs`, `buildRevealContext` | The pieces, for a custom extension |
| `isUnwrappedResidue`, `findUnwrapped`, `assertNoUnwrapped` | The guard, for use outside a query hook |
| `UnwrapSensitive`, `WrapRow`, `SensitiveResultComponent`, and the config types | Types |

## License

MIT
