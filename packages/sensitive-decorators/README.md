# @platform-sec/sensitive-string-decorators

Stage 3 decorators for
[`@platform-sec/sensitive-string-core`](../sensitive-core), with no framework
attached.

Two things a class-based codebase keeps writing by hand: wrapping a field's
value in a `SensitiveString` at every place that assigns it, and opening a
reveal context around every method that reveals one. Both are easy to forget in
exactly one spot, and a spot that forgets the first one holds a bare string that
`JSON.stringify` prints in full. `@Sensitive` and `@WithRevealContext` move both
to the declaration, where they are visible in review.

```typescript
import { Sensitive, WithRevealContext } from '@platform-sec/sensitive-string-decorators';
import { SensitiveString } from '@platform-sec/sensitive-string-core';

class User {
  @Sensitive('sensitive', 'email') accessor email!: SensitiveString<'sensitive'>;
  @Sensitive('credential') accessor passwordHash!: SensitiveString<'credential'>;
}

class PaymentProcessor {
  @WithRevealContext({ name: 'payment-processing', reason: 'charging card' })
  async processPayment(card: SensitiveString<'credential'>): Promise<Receipt> {
    return gateway.charge(card.reveal());
  }
}
```

## Installation

```bash
pnpm add @platform-sec/sensitive-string-decorators
```

`@platform-sec/sensitive-string-core` is a peer dependency. Nothing else is:
this package adds no runtime dependency of its own, and Stage 3 decorators need
no `reflect-metadata`.

## Requirements

- Node.js 22.12+
- TypeScript 5.0+ compiling with **`experimentalDecorators` off**, which is the
  default. Leave it unset.

Legacy decorators and Stage 3 decorators are two incompatible models, and a file
compiles under one or the other, never both. If your build sets
`experimentalDecorators: true`, these decorators will not work under it. NestJS
requires that setting, so a NestJS application gets the same two decorator names,
with the same semantics, from
[`@platform-sec/sensitive-string-nestjs`](../sensitive-nestjs) instead.

## `@Sensitive`

```typescript
class User {
  @Sensitive('sensitive', 'email') accessor email!: SensitiveString<'sensitive'>;
}
```

The `accessor` keyword is required, and it is the point. A plain field decorator
sees the initializer and nothing after it, so a later `user.email = raw` would
store a bare string and the field would be protected only until the first
assignment. An auto-accessor is the one field form whose assignments a decorator
can intercept, so both the initializer and every later assignment go through the
decorator.

### Declaring the field

Three declarations work, and they differ only in what TypeScript lets you
assign:

```typescript
class User {
  // Assignments must be a SensitiveString. Reads are one.
  @Sensitive('sensitive') accessor email!: SensitiveString<'sensitive'>;

  // Same, and the field may be absent.
  @Sensitive('sensitive') accessor nickname: SensitiveString<'sensitive'> | undefined;

  // Raw strings may also be assigned, at the cost of narrowing on every read.
  @Sensitive('credential') accessor token!: string | SensitiveString<'credential'>;
}
```

A bare `string` declaration is rejected at compile time, because a read of that
field returns a `SensitiveString` while TypeScript still believes it is a
string: `const raw: string = user.email` would compile and be wrong.

Wrapping happens at runtime whatever the declaration says, so a raw string that
arrives through an untyped path is wrapped too. That is where these leaks
actually come from:

```typescript
const user = Object.assign(new User(), await db.query(sql));
user.email; // SensitiveString, not the string the driver returned
```

### What each assignment stores

| Assigned                                  | Stored                                                     |
| ----------------------------------------- | ---------------------------------------------------------- |
| a string                                  | wrapped with this decorator's class, label, and options     |
| a `SensitiveString` of the same class     | that value, unchanged                                       |
| a `SensitiveString` of a stricter class   | that value, unchanged                                       |
| a `SensitiveString` of a looser class     | `TypeError`                                                 |
| `null` or `undefined`                     | unchanged                                                   |
| anything else                             | `TypeError`                                                 |

Refusing a looser value is rule R5: a field declared `credential` must not end
up holding a `sensitive` value, because the class is what decides whether
`equals()` runs in constant time and whether `mask()` and partial queries are
allowed at all. `reclassify()` is the one way to change a class, and it audits
the change.

An already-wrapped value keeps its own label and options. The decorator's
options apply to values it constructs, and it cannot tighten a value it did not
build: that would mean reading it, which only `reveal()` may do.

### Labels and options

The label defaults to the property name, so redacted output names the field the
value came from:

```typescript
class Account {
  @Sensitive('credential') accessor apiKey!: string | SensitiveString<'credential'>;
}

const account = new Account();
account.apiKey = 'sk_live_deadbeef';

console.log(account.apiKey);
// SensitiveString<credential:apiKey> { [REDACTED:credential] }
```

A third argument takes everything the `SensitiveString` constructor takes, so a
field whose values should expire says so once:

```typescript
class Session {
  @Sensitive('credential', 'otp', { ttl: 30_000 })
  accessor otp!: string | SensitiveString<'credential'>;
}
```

The options object is copied when the class is defined, so mutating it
afterwards does not change the field.

### An accessor field does not serialize

This is a consequence of the `accessor` keyword rather than of this package, and
it will change the shape of anything you already serialize. An auto-accessor is
a getter and setter pair on the prototype backed by a private field, so the
instance has no own enumerable property for it, and `JSON.stringify` and
`util.inspect` have nothing to print:

```typescript
JSON.stringify(new Plain());    // {"email":"[REDACTED:sensitive]"}
JSON.stringify(new Accessed()); // {}
```

Nothing leaks either way. But a response body that used to carry a redacted
placeholder now carries no key at all, and a snapshot test will notice. Declare
`toJSON()` where the shape matters:

```typescript
class User {
  @Sensitive('sensitive', 'email') accessor email!: SensitiveString<'sensitive'>;

  toJSON() {
    return { email: this.email };
  }
}

JSON.stringify(new User()); // {"email":"[REDACTED:sensitive]"}
```

`redactInStructure()` and `safeStringify()` honor `toJSON()`, so the same
declaration fixes them. `containsSensitive()` and `sensitiveClassesIn()` do not:
they walk own enumerable properties and report nothing for an object whose
sensitive fields are all accessors, with or without a `toJSON()`. Hand them the
field, or the result of `toJSON()`, rather than the instance.

## `@WithRevealContext`

```typescript
class PaymentProcessor {
  @WithRevealContext({ name: 'payment-processing', reason: 'charging card' })
  async processPayment(card: SensitiveString<'credential'>): Promise<Receipt> {
    return gateway.charge(card.reveal());
  }
}
```

Every `reveal()` the method reaches, however deep, runs under that context, on
the same `AsyncLocalStorage` propagation `withRevealContext()` uses. The
decorator names the operation; it grants nothing. A policy's
`checkRevealAllowed` still runs, and a context it rejects is still rejected.

A factory builds the context from the call instead. It receives the arguments
and the receiver:

```typescript
class OrderService {
  @WithRevealContext((args, self) => ({
    name: 'refund-processing',
    tags: { orderId: args[0], region: (self as OrderService).region },
  }))
  async refund(orderId: string): Promise<void> {}
}
```

`self` is typed `unknown` because a decorator factory is called before
TypeScript knows which class the decorator lands on. A factory that throws
propagates, and the method does not run.

### Nesting

The context is nested rather than substituted, on the terms `createChildContext`
sets. `name`, `reason`, and `auditReveal` given here replace the ambient ones,
`tags` merge with these winning on a conflict, and anything not given is
inherited:

```typescript
await withRevealContext({ name: 'http-request', auditReveal: log }, async () => {
  await processor.processPayment(card);
  // Audited by `log`, under the name 'payment-processing'.
});
```

Substitution would have dropped `log` and the reveal would have gone unaudited,
which is the one failure here that leaves no trace.

### Generators

Sync methods, async methods, generators, and async generators are all covered.
Generators need the extra handling: calling a generator function only builds the
iterator, and the body runs on `next()`, after the context would otherwise have
closed. The decorator wraps the iterator so every resumption, including the
`finally` block a `break` triggers, runs inside the context.

```typescript
class Exporter {
  @WithRevealContext({ name: 'account-export' })
  async *rows(accounts: Account[]): AsyncGenerator<string> {
    for (const account of accounts) {
      yield account.apiKey.reveal(); // audited, on every iteration
    }
  }
}
```

A method that is not itself a generator but returns an iterator built elsewhere
is not covered. The context ends when that method returns, so such a method
establishes its own context around the loop that produces values.

## Limitations

- **Stage 3 only.** There is no legacy decorator build and there will not be
  one. See the NestJS package for that model.
- **`accessor` only.** `@Sensitive` refuses fields, methods, getters, and
  setters, because it cannot intercept assignments to any of them.
- **Methods only.** `@WithRevealContext` refuses getters, setters, and classes.
  Call `withRevealContext()` in the body instead.
- **Accessor fields are invisible to structural walks.** `containsSensitive()`
  and `sensitiveClassesIn()` see own enumerable properties, and an
  auto-accessor is not one. See the section above.
- **No worker threads.** `AsyncLocalStorage` does not cross a worker boundary,
  so a context does not either. This is core's limitation, inherited.
- Everything in core's threat model applies. These decorators defend against
  accidents, not against code that already runs in the process.

## License

MIT
