# @platform-sec/sensitive-string-kdf

Password hashing for `SensitiveString` values: Argon2, bcrypt and scrypt behind one audited API,
with the stored hash wrapped as a `credential`.

## Why this is not in core

`SensitiveString.hash('sha256')` exists and is not this. It is fast, and speed is the one property a
stored password must not have: a wordlist runs through SHA-256 at billions of guesses a second on
hardware anybody can rent, and a salt does nothing about that for the attacker who has the row the
salt is stored in. What a stored password needs is a function that is deliberately slow and
memory-hard.

The functions that are need Argon2 or bcrypt, both native modules, and `core` has no runtime
dependencies. So they live here. Both are optional peer dependencies: an application that installs
neither can still hash with scrypt, which `node:crypto` computes.

## Installation

```bash
pnpm add @platform-sec/sensitive-string-kdf

# and one of these, unless scrypt is the algorithm
pnpm add argon2
pnpm add bcrypt
```

## Requirements

- Node.js 22.12+
- `@platform-sec/sensitive-string-core` as a peer dependency
- `argon2` or `bcrypt` only for those algorithms. Neither is needed for scrypt

## Quick Start

```typescript
import { SensitiveString } from '@platform-sec/sensitive-string-core';
import { hashForStorage, verifyHash } from '@platform-sec/sensitive-string-kdf';

// Registration
const password = new SensitiveString(body.password, 'credential', 'password');
const stored = await hashForStorage(password, { algorithm: 'argon2id' });

await db.users.create({ data: { email, password: stored.reveal() } });
```

```typescript
// Login
const stored = new SensitiveString(row.password, 'credential', 'password:stored');

if (!(await verifyHash(stored, body.password))) {
  throw new UnauthorizedError();
}
```

`hashForStorage` returns a `SensitiveString<'credential'>` holding the encoded hash, labelled
`${label}:stored`. It is classed `credential` because a stored hash is worth attacking offline, and
wrapping it is what keeps it out of a log line on the way to the database.

Both functions accept a plain string as well as a protected value, because a password arriving in a
request body is a string and a hash coming back from a database row is one too.

## Algorithms

| Algorithm | Needs | Use it for |
|---|---|---|
| `argon2id` | `argon2` | A new system. Memory-hard and side-channel resistant |
| `argon2i`, `argon2d` | `argon2` | Reproducing what an existing store already holds |
| `bcrypt` | `bcrypt` | A store that is already bcrypt. Still sound, not memory-hard |
| `scrypt` | nothing | An application that cannot install a native module |

Every parameter has a floor as well as a default, and a value below the floor is refused rather than
quietly raised: a caller who wrote `memoryCost: 1024` believed something about the cost of an
offline attack and needs to be told it was wrong.

```typescript
// Defaults, which are the OWASP recommendations
await hashForStorage(password, { algorithm: 'argon2id' });
// memoryCost 65536 KiB, timeCost 3, parallelism 4, hashLength 32
// floors:    19456 KiB,          2,              1,            16

await hashForStorage(password, { algorithm: 'bcrypt' });
// rounds 12, floor 10, ceiling 20

await hashForStorage(password, { algorithm: 'scrypt' });
// N 16384, r 8, p 1, keyLength 64
```

The bcrypt ceiling is there because rounds is an exponent. 20 is around thirty seconds per hash;
31, which bcrypt accepts, is measured in weeks. One digit too many should be an error rather than a
login handler that never returns.

## Verification reads the stored hash

The algorithm and its parameters come from the stored string, never from anything configured here.
A store hashed years ago under weaker parameters keeps verifying while new passwords are hashed
under stronger ones, which is what makes an incremental rehash-on-login migration possible.

A password that does not match answers `false`. A stored hash that cannot be read throws
`UnknownStoredHashError`: it is a fault in the data, and reporting it as a failed login turns a
corrupted column into an account nobody can sign in to and nobody can explain. The offending string
is never repeated in the message, because it is a credential.

scrypt hashes are written in the [PHC string format](https://github.com/P-H-C/phc-string-format),
which records `ln`, the base-two logarithm of the cost, rather than `N` itself. That is what the
format specifies and what makes a hash written here readable by something that is not this package.

## Rehashing a store that has outlived its parameters

Verification reads the parameters from the stored string, so a password hashed
years ago keeps verifying forever. `needsRehash` is how an application notices
that it should not, at the one moment it holds the plaintext and can do
something about it:

```typescript
const PASSWORD_HASHING = { algorithm: 'argon2id' } as const;

if (await verifyHash(stored, body.password)) {
  if (needsRehash(stored, PASSWORD_HASHING)) {
    const rehashed = await hashForStorage(body.password, PASSWORD_HASHING);
    await db.users.update({ where: { id }, data: { password: rehashed.reveal() } });
  }
}
```

Weaker, not different. A stored hash whose parameters are *above* what the
options ask for does not report: rolling a configuration back, or reading a
store some other service hashed more expensively, must not rehash a fleet of
passwords down to the lower setting. A different algorithm family always
reports, because moving a bcrypt store to Argon2id is the migration this exists
for.

It hashes nothing and loads no native module, which is what lets it answer for
an algorithm this process cannot compute: every format writes its cost into the
string ahead of the digest, so this reads it. Argon2's parallelism is
deliberately not compared, since lanes divide the same memory rather than
adding work.

## bcrypt and 72 bytes

bcrypt hashes the first 72 bytes of a password and silently ignores the rest, so two passwords
sharing a 72-byte prefix verify against each other's hash. The `bcrypt` package does this without a
word.

This package refuses a longer password instead, on the hashing side and on the verifying side both.
An error at registration is a bug report; a silent truncation is an authentication bypass nobody
finds. The check counts bytes, not characters: 36 emoji are 144 bytes. Argon2 and scrypt have no
such limit.

## What it inherits, and what it does not

Reading a protected password goes through `core`'s ordinary gate, so the class policy, the audit
hook, the deadline, the reveal budget and any revocation all apply. Hashing a password appears in an
audit log as the exposure it is, and a revoked password cannot be hashed.

The hash itself is a fresh `credential` and does not carry the password's deadline or reveal budget.
This is the one place in this library where a value derived from another does not inherit its
constraints, and it is deliberate: the hash has to outlive the password and be read on every login,
and a salted, memory-hard hash is not a reversible copy of the value the way a fast digest of a
guessable value is. `core`'s `hash()` inherits for exactly that reason, and the two functions differ
because their outputs differ.

The case where that reasoning is thin is a secret an attacker can enumerate outright, a four-digit
PIN, and no choice of KDF rescues that.

## API

- `hashForStorage(value, options, ctx?)` returns `Promise<SensitiveString<'credential'>>`
- `verifyHash(stored, input, ctx?)` returns `Promise<boolean>`
- `needsRehash(stored, options, ctx?)` returns `boolean`, synchronously and without a KDF
- `MissingKdfModuleError`, `UnknownStoredHashError`
- The floors, defaults and ceilings, as named constants, so a caller can cite them rather than copy
  them

## License

MIT
