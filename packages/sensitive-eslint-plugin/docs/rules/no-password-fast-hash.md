# no-password-fast-hash

Disallow hashing a password with `hash()` or `hmac()`, which are fast by design.

Severity in `recommended`: **warn**. In `strict`: **error**.

## Why

`hash()` exists for a lookup key, a deduplication key, a correlation token. It
is fast, which is the property those uses want and the one property a stored
password must not have: a wordlist runs through SHA-256 at billions of guesses a
second on hardware anybody can rent, and a salt does nothing about that for
whoever has the row the salt is stored in.

A password wants a function that is deliberately slow and memory-hard. That is
`hashForStorage()` from `@platform-sec/sensitive-string-kdf`, which is a
separate package because Argon2 and bcrypt are native modules and `core` has no
runtime dependencies.

`hmac()` is reported too. A key does not make a fast function slow. Peppering a
password with an HMAC is a real pattern and a defensible one *on top of* a KDF,
never instead of one.

## Examples

Incorrect:

```js
const stored = password.hash('sha256');
const stored = user.password.hash('sha256', { salt });
const stored = newPassword.hmac('sha256', pepper);
```

Correct:

```js
import { hashForStorage } from '@platform-sec/sensitive-string-kdf';

const stored = await hashForStorage(password, { algorithm: 'argon2id' });
```

```js
// hash() on the values it is for.
const lookupKey = token.hash('sha256', {}, { name: 'session-lookup' });
const pseudonym = email.hmac('sha256', correlationKey, {}, ctx);
```

## How a password is recognised

By the name of the value being hashed, matched case-insensitively as a
fragment: `password`, `passwd`, `passphrase`, `pwd`. So `newPassword`,
`user.passwd` and `plainPWD` all count.

The name that matters is the value's own, not whatever holds it.
`user.password.hash()` reports on `password`; `passwordService.token.hash()`
reports on `token`, which is to say not at all.

`secret`, `token` and `key` are deliberately not in the list. Those are the
values `hash()` is *for*, and a rule that reported them would be reporting the
feature.

## Why a name, when the plugin says elsewhere that names are worse than nothing

`type-info.ts` rejects name matching for a different question. There it has to
decide whether a value carries a sensitive one, and a name test answers
`JSON.stringify(token)` while staying quiet on `JSON.stringify(user)`, which is
the call that actually holds the secret. Types answer that question properly.

Here the question is whether this particular value is a *password*, and no type
answers it: a password and an API key are both `SensitiveString<'credential'>`.
The name is the only signal anybody has, which is why this rule is a warning
rather than an error in `recommended`. A false positive costs a one-line
suppression or an entry in `passwordNames`; a false negative is a password store
that a wordlist opens.

## Options

| Option | Default |
|---|---|
| `passwordNames` | `password`, `passwd`, `passphrase`, `pwd` |

A configured list replaces the default rather than extending it, which is the
convention across this plugin's name options.

## What it does not catch

`crypto.createHash('sha256').update(password)`, and the same written across two
statements. This plugin reads calls rather than following values, and by the
time an update is a statement of its own there is nothing at the call site
naming the algorithm that was chosen. A rule that tried would report the digest
of a file being read a chunk at a time.

It also says nothing about a password reaching `hashForStorage` with parameters
below the floor, because that call refuses at runtime and does not need a lint
rule to say so.
